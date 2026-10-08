# Shards — Two Formulas for the Same Conversion, Only One of Them Right

**Challenge:** Damn Vulnerable DeFi v4 — Shards
**Category:** Arithmetic Mismatch / Missing Scaling Factor
**Severity:** Critical (the marketplace's DVT balance is drained through fill/cancel alone, no NFT ever bought)

## What's going on

A marketplace lets a seller fractionalize an NFT into "shards" and sell them off in
pieces. Buyers call `fill()` to purchase some shards, paying DVT; if they cancel within
a short window, `cancel()` refunds them. The player starts with zero DVT and has to walk
away having drained a meaningful chunk of the marketplace's balance — without ever
staking, without touching the staking rewards pool, and in a single transaction.

## The bug

`fill()` and `cancel()` both convert "shards" into DVT, but they use two different
formulas, and only one of them is correct.

`fill()` charges the buyer proportionally to how much of the offer they're taking:

```solidity
paymentToken.transferFrom(
    msg.sender, address(this), want.mulDivDown(_toDVT(offer.price, _currentRate), offer.totalShards)
);
```

That's `want × (price × rate / 1e6) / totalShards` — correctly scaled down by the size
of the whole offer, so buying a small fraction of `totalShards` costs a small fraction
of the total price.

`cancel()` refunds using a completely different, unscaled formula:

```solidity
paymentToken.transfer(buyer, purchase.shards.mulDivUp(purchase.rate, 1e6));
```

That's `shards × rate / 1e6` — with **no division by `totalShards`** at all. It treats
the oracle's DVT-per-USDC `rate` as if it were "DVT owed per raw shard unit," which it
isn't. In this setup `totalShards = 1e25` and `price = 1e12`, so the refund formula
pays out roughly `1e13` times more generously than the payment formula ever charged,
for the exact same `want`.

Nothing closes this gap. A buyer can `fill()` a tiny `want`, immediately `cancel()`
within the allowed window, and the refund is unrelated to — and far larger than — what
they actually paid.

## The attack

**Bootstrap for free.** There's a `want` small enough that `fill()`'s payment rounds
down to exactly zero (the division by `totalShards` floors it away), while `cancel()`'s
refund — which never divides by `totalShards` — still pays out a real, nonzero amount.
That one call costs nothing and hands the attacker their first DVT.

**Scale it up, repeatedly.** With DVT in hand, loop: compute the largest `want` that
(a) the attacker can currently afford to pay for under `fill()`'s correct formula, and
(b) still leaves room under `cancel()`'s inflated refund formula without exceeding the
marketplace's remaining balance — then `fill()` and immediately `cancel()`. Each round
roughly multiplies the attacker's balance, converging toward the marketplace's spare
DVT rather than growing forever, since the loop stops once the marketplace's balance
drops below a useful threshold.

All of it happens inside the constructor of a single attacker contract, so the player's
nonce never moves past 1.

## PoC

```solidity
function test_shards() public checkSolvedByPlayer {
    new ShardsAttacker(marketplace, token, recovery);
}

contract ShardsAttacker {
    constructor(ShardsNFTMarketplace _marketplace, DamnValuableToken _token, address recovery) {
        // ... compute rate, totalShards, totalDVT, and zeroCostWant from the live offer ...
        _run();
        token.transfer(recovery, token.balanceOf(address(this)));
    }

    function _run() private {
        for (uint256 i = 0; i < 20; i++) {
            if (token.balanceOf(address(marketplace)) < minUsefulBal) break;
            uint256 want = _nextWant(); // sized to stay affordable under fill(), profitable under cancel()
            uint256 purchaseIndex = marketplace.fill(offerId, want);
            marketplace.cancel(offerId, purchaseIndex);
        }
    }
}
```

In the run that passed, the bootstrap call (`want = 133`) produced a refund of
`9.975e12` wei DVT for a payment that rounded to zero, and six further rounds of
fill/cancel grew the balance from there to roughly `7.5e20` wei (≈750,000 DVT) before
the marketplace's remaining balance fell below the loop's cutoff. Full test file:
`test/shards/Shards.t.sol`.

## Why I'm calling this Critical

- **No NFT is ever purchased and no stake is ever risked.** The exploit lives entirely
  inside `fill()`/`cancel()`, a feature meant only to let buyers back out of a purchase,
  not a profit center.
- **Self-funding.** The zero-cost bootstrap means the attacker needs no starting
  capital at all — the bug pays for its own escalation.
- **Large, direct loss.** The marketplace's DVT balance (collected as seller fees) is
  drained by a wide margin, not a rounding-dust amount.
- **The two formulas were never meant to diverge.** `fill()` getting the scaling right
  and `cancel()` getting it wrong means the vulnerability isn't a deliberate design
  trade-off anywhere — it's a straightforward implementation slip in one function that
  should mirror the other exactly, inverted.

## Fix

- Refund exactly what was charged. The simplest fix is to store the actual DVT amount
  paid in the `Purchase` struct at `fill()` time, and have `cancel()` refund that stored
  value directly — removing the need for a second, independently-derived formula that
  can drift out of sync.
- If a formula must be recomputed instead of stored, it must use the identical scaling
  as the charge formula (`× price / totalShards`), not a subset of it.
- Treat "the money that leaves must never exceed the money that came in for the same
  purchase" as an invariant worth asserting explicitly, the same way the contract
  already asserts `feesInBalance <= paymentToken.balanceOf(address(this))` elsewhere.

## Takeaway

Whenever a protocol computes the same conversion (price ↔ units, shares ↔ assets,
shards ↔ payment) in more than one place, check that every instance uses the exact same
formula — not just the same inputs. A payment function and its corresponding refund or
cancellation function are the single most common place for this kind of drift, because
they're written separately, often far apart in the file, and nothing forces them to stay
mirrored as the code evolves.
