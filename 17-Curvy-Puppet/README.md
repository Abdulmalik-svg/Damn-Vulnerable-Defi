# Curvy Puppet — Read-Only Reentrancy on a Real Mainnet Curve Pool

**Challenge:** Damn Vulnerable DeFi v4 — Curvy Puppet
**Category:** Read-Only Reentrancy / Stale Oracle Read During an In-Progress External Call
**Severity:** Critical (three fully-collateralized users get liquidated and lose their entire DVT collateral, based entirely on a price the pool itself was still in the middle of updating)

## What's going on

A lending protocol lets users deposit DVT as collateral and borrow LP tokens from a
real, live Curve ETH/stETH pool on mainnet (this challenge forks mainnet at a pinned
block). The borrowed asset's price comes from `curvePool.get_virtual_price()`
multiplied by a fixed ETH price. Three users (Alice, Bob, Charlie) each hold a position
at roughly 569% collateralization -- nowhere near the 175% liquidation threshold. The
goal: get all three positions liquidated and their DVT collateral routed to the
treasury, without the player ending up holding anything.

This challenge is modeled directly on the real 2023 Curve read-only reentrancy
vulnerability that affected multiple protocols reading `get_virtual_price()` from
ETH-based Curve pools.

## The bug

`CurvyPuppetLending._getLPTokenPrice()` trusts `curvePool.get_virtual_price()` as a
live, reliable price at any point in time:

```solidity
function _getLPTokenPrice() private view returns (uint256) {
    return oracle.getPrice(curvePool.coins(0)).value.mulWadDown(curvePool.get_virtual_price());
}
```

That's a reasonable assumption *between* transactions. It's not reasonable *during* a
Curve `remove_liquidity` call. That function burns LP supply and calculates both
underlying amounts up front, then sends the ETH leg out via a raw low-level call
**before** the second coin (stETH) has actually been transferred and the pool's full
accounting has settled. If the ETH recipient is a contract with a `receive()` hook,
that hook executes in the middle of `remove_liquidity`, with `totalSupply` already
reduced but `stETH.balanceOf(pool)` not yet reduced to match. `get_virtual_price()`
reads both of those values, so for the duration of that one callback it returns a
temporarily inflated number -- confirmed empirically against the real pool at this
block: baseline `~1.0969`, briefly spiking well above that mid-call before settling
right back to `~1.0969` once the transaction finished.

## Confirming it empirically, not from memory

Before building any exploit, I probed the real deployed pool directly on the fork:

- `remove_liquidity_one_coin` showed **no** meaningful distortion -- confirming the
  documented vulnerability is specific to `remove_liquidity` (both coins), not the
  single-coin variant.
- `remove_liquidity` with a modest single-sided WETH round trip (~100 LP, then later
  30,000 WETH via a Balancer flash loan) showed a real, measurable spike during the
  `receive()` callback, settling back to baseline immediately after -- confirming the
  mechanism, but a 30,000 WETH round trip only moved the price ~15%, far short of the
  ~3.571 the real liquidation threshold required (measured directly against the live
  `lending` contract, not hand-calculated).
- A single Balancer flash loan tops out around the vault's own ~38,000 WETH balance at
  this block -- not enough on its own to reach the required multiplier, and the
  distortion doesn't scale linearly with deposit size.

## The attack

Reaching the required ~3.571x multiplier needs more capital than any single source on
this fork provides, and needs the deposit heavily skewed toward stETH (not a balanced
or single-sided-ETH deposit) to produce an extreme-enough temporary imbalance:

1. Flash-loan nearly all of Aave V2's stETH reserve (~173,429 stETH available at this
   block) plus 15,000 WETH, via Aave V2's `flashLoan`.
2. Inside that callback, take a second, nested flash loan of Balancer's entire WETH
   balance (fee-free).
3. Unwrap the WETH to ETH and deposit it together with the borrowed stETH into the
   Curve pool via `add_liquidity` -- a large, stETH-heavy position.
4. Immediately `remove_liquidity` nearly all of the newly minted LP tokens. This is the
   same call that triggers the price-distortion window, but now at a scale large
   enough to actually clear the liquidation threshold.
5. Inside the `receive()` callback that fires mid-`remove_liquidity` -- while
   `get_virtual_price()` is still reading the distorted, too-high value -- call
   `lending.liquidate()` on all three positions. Each one is now (temporarily) shown as
   undercollateralized, so the liquidation succeeds and the attacker receives their DVT
   collateral in exchange for repaying their borrowed LP tokens.
6. Unwind: swap enough recovered ETH back to stETH to repay the Aave flash loan plus
   its premium, repay the Balancer WETH, and forward the recovered DVT (plus any
   leftover WETH/LP) to the treasury.

## PoC (structure)

```solidity
function run() external {
    _flashloanOnAaveV2();   // borrows ~173k stETH + 15,000 WETH
    _returnAsset();         // forwards recovered DVT/LP/WETH to treasury
}

function executeOperation(...) external returns (bool) {
    _flashloanOnBalancer(stETHTotalPayback); // nested: borrows Balancer's full WETH balance
    // approves Aave repayment
}

function receiveFlashLoan(...) external {
    weth.withdraw(wethBorrowedTotal);
    _attack(ethToAdd, stEthToAdd, stETHTotalPayback);
    // repays Balancer
}

function _attack(...) private {
    _addLiquidity(amount0, amount1);       // heavily stETH-weighted add_liquidity
    _removeLiquidity(lpTokenBurn);         // triggers the read-only reentrancy window
    _payFlashloan(stETHTotalPayback);      // unwind
}

receive() external payable {
    if (isRemovingLiquidity) {
        lending.liquidate(user1);
        lending.liquidate(user2);
        lending.liquidate(user3);
    }
}
```

Full solution: `test/curvy-puppet/CurvyPuppetAttacker.sol` and
`test/curvy-puppet/CurvyPuppet.t.sol`.

## A note on how this was solved

This was the hardest challenge in the set by a wide margin, and getting it right
required an unusual amount of empirical verification against the live fork rather than
reasoning from the historical vulnerability pattern alone: confirming which specific
Curve function actually exposes the reentrancy window (`remove_liquidity`, not
`remove_liquidity_one_coin`), confirming the real liquidation threshold directly from
the deployed contracts rather than hand math, and confirming every external contract
address (Balancer's Vault, Aave V2's LendingPool, the stETH aToken) against real
on-chain bytecode before using any of them -- one wrong hex digit in a vault address
cost real debugging time here and is worth remembering as a lesson on its own. The
final capital sizing (which flash-loan sources, roughly how much of each, how the
stETH/ETH ratio needs to skew) came from working through the problem with Grok as a
second collaborator once single-source Balancer capital was empirically confirmed to
fall short; several of the exact hardcoded figures in the attacker contract (the
`31e17` LP buffer, the `13975e18` ETH-to-stETH swap amount) are tuned to this specific
block and would need re-deriving, not just reused, against a different fork state.

## Why I'm calling this Critical

- **Fully solvent users lose their entire collateral** based on a price that was never
  real -- it existed only for the duration of a single external call, and the pool's
  own state confirms as much the instant that call finishes.
- **No fault on the users' part.** 569% collateralization is far above any reasonable
  safety margin; the attack works regardless of how conservative the borrower was.
- **The attacker needs no capital of their own.** Every dollar used is borrowed and
  repaid within one transaction, funded entirely by permissionless flash loans against
  real, publicly available liquidity.
- **This is a known, previously-exploited bug class**, not a hypothetical. The exact
  mechanism here cost real DeFi protocols real money reading prices from Curve pools
  the same way.

## Fix

- **Never read `get_virtual_price()` (or any Curve pool state) as reliable inside a
  context where reentrancy from that same pool is possible mid-transaction.** Curve's
  own documentation explicitly warns about this for ETH-based pools.
- Add a reentrancy guard to the price-reading path itself, or require the read to
  happen in a separate transaction from any pool interaction (which is awkward and
  often impractical for a lending protocol).
- Prefer a Curve pool's own protected, reentrancy-safe price oracle function where one
  is offered (newer Curve pools expose purpose-built oracle methods specifically
  because of this class of bug), or use an external price feed entirely decoupled from
  any pool whose state the position being priced could itself cause to change mid-call.
- At minimum, sanity-bound how far a price can move between consecutive reads within
  the same block, rejecting liquidations triggered by an implausible single-block swing.

## Takeaway

Read-only reentrancy is a distinct, easy-to-miss category from the reentrancy most
audits already check for: nothing here was drained directly through the vulnerable
call itself, and the vulnerable contract (Curve's pool) has no bug of its own -- the
exploit lives entirely in a *consumer* trusting that contract's view functions as safe
to call at any arbitrary point in another transaction's execution. Whenever a protocol
reads state from an external AMM or vault mid-transaction, ask not just "can this call
reenter me," but "can *this exact view function* be called by someone else, from
inside one of that pool's own state-changing functions, while its internal accounting
is only partially updated." If the answer is yes, that view function is not safe to
trust as a price source without additional protection.
