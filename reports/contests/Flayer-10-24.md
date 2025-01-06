# Flayer

> This report contains findings reported in the [Flayer](https://audits.sherlock.xyz/contests/468) competition on Sherlock by the me, [@flacko](https://x.com/flack00n), as a part of the Sentryx security team.

# Summary

|Severity|Issues|Unique|
|--|--|--|
|[High](#high)|3|0|
|[Medium](#medium)|1|1|

# Findings

# High

## [Locker actions affecting utilization rate are not checkpointed](https://github.com/sherlock-audit/2024-08-flayer-judging/issues/458)

### Summary
Utilization rate is not checkpointed at all times when necessary as depositing, redeeming and unbacked depositing to the Locker, for example, will affect the CT total supply while **not** affecting the collection's protected listings count and thus this will affect the utilization rate on which interest rates and liquidations rely on.
### Root Cause
Some functions of the **Locker** contract that alter the CollectionTokens' `totalSupply` do **not** checkpoint the collection's `compoundedFactor` which enables certain vulnerabilities outlined in the **Impact** section.

1. [**Locker**#`deposit()`](https://github.com/sherlock-audit/2024-08-flayer/blob/main/flayer/src/contracts/Locker.sol#L144-L166)
```solidity
    function deposit(address _collection, uint[] calldata _tokenIds, address _recipient) public
        nonReentrant
        whenNotPaused
        collectionExists(_collection)
    {
        uint tokenIdsLength = _tokenIds.length;
        if (tokenIdsLength == 0) revert NoTokenIds();

        // Define our collection token outside the loop
        IERC721 collection = IERC721(_collection);

        // Take the ERC721 tokens from the caller
        for (uint i; i < tokenIdsLength; ++i) {
            // Transfer the collection token from the caller to the locker
            collection.transferFrom(msg.sender, address(this), _tokenIds[i]);
        }

        // Mint the tokens to the recipient
        ICollectionToken token = _collectionToken[_collection];
→       token.mint(_recipient, tokenIdsLength * 1 ether * 10 ** token.denomination());

        emit TokenDeposit(_collection, _tokenIds, msg.sender, _recipient);
    }
```

2. [**Locker**#`unbackedDeposit()`](https://github.com/sherlock-audit/2024-08-flayer/blob/main/flayer/src/contracts/Locker.sol#L179-L188)
```solidity
    function unbackedDeposit(address _collection, uint _amount) public nonReentrant whenNotPaused collectionExists(_collection) {
        // Ensure that our caller is an approved manager
        if (!lockerManager.isManager(msg.sender)) revert UnapprovedCaller();

        // Ensure that the collection has not been initialized
        if (collectionInitialized[_collection]) revert CollectionAlreadyInitialized();

        // Mint the {CollectionToken} to the sender
→       _collectionToken[_collection].mint(msg.sender, _amount);
    }
```

3. [**Locker**#`redeem()`](https://github.com/sherlock-audit/2024-08-flayer/blob/main/flayer/src/contracts/Locker.sol#L209-L230)
```solidity
    function redeem(address _collection, uint[] calldata _tokenIds, address _recipient) public nonReentrant whenNotPaused collectionExists(_collection) {
        uint tokenIdsLength = _tokenIds.length;
        if (tokenIdsLength == 0) revert NoTokenIds();

        // Burn the ERC20 tokens from the caller
        ICollectionToken collectionToken_ = _collectionToken[_collection];
→       collectionToken_.burnFrom(msg.sender, tokenIdsLength * 1 ether * 10 ** collectionToken_.denomination());

        // Define our collection token outside the loop
        IERC721 collection = IERC721(_collection);

        // Loop through the tokenIds and redeem them
        for (uint i; i < tokenIdsLength; ++i) {
            // Ensure that the token requested is not a listing
            if (isListing(_collection, _tokenIds[i])) revert TokenIsListing(_tokenIds[i]);

            // Transfer the collection token to the caller
            collection.transferFrom(address(this), _recipient, _tokenIds[i]);
        }

        emit TokenRedeem(_collection, _tokenIds, msg.sender, _recipient);
    }
```

This becomes exploitable due to the way `unlockPrice()` and `getProtectedListingHealth()` measure the increase in compound factor. When a protected listing (a loan) is recorded, the current collection `compoundFactor` is checkpointed and its index is stored in the Listing struct as `checkpoint`.  Now when it comes to `getProtectedListingHealth()` lets see how it works:

https://github.com/sherlock-audit/2024-08-flayer/blob/main/flayer/src/contracts/ProtectedListings.sol#L497-L501
```solidity
    function getProtectedListingHealth(address _collection, uint _tokenId) public view listingExists(_collection, _tokenId) returns (int) {
        // ...
→       return int(MAX_PROTECTED_TOKEN_AMOUNT) - int(unlockPrice(_collection, _tokenId));
    }
```

The `MAX_PROTECTED_TOKEN_AMOUNT` constant is equal to $0.95e18$.

https://github.com/sherlock-audit/2024-08-flayer/blob/main/flayer/src/contracts/ProtectedListings.sol#L607-L617
```solidity
    function unlockPrice(address _collection, uint _tokenId) public view returns (uint unlockPrice_) {
        // ...
        unlockPrice_ = locker.taxCalculator().compound({
            _principle: listing.tokenTaken,
            _initialCheckpoint: collectionCheckpoints[_collection][listing.checkpoint],
→           _currentCheckpoint: _currentCheckpoint(_collection)
        });
    }
```

**TaxCalculator**#`compound()` simply takes the listing's `tokenTaken` and multiplies it by `_currentCheckpoint.compoundedFactor / __initialCheckpoint.compoundedFactor` in a typical rebase token fashion (for example).

https://github.com/sherlock-audit/2024-08-flayer/blob/main/flayer/src/contracts/ProtectedListings.sol#L580-L596
```solidity
    function _currentCheckpoint(address _collection) internal view returns (Checkpoint memory checkpoint_) {
        // Calculate the current interest rate based on utilization
→       (, uint _utilizationRate) = utilizationRate(_collection);

        // Update the compounded factor with the new interest rate and time period
        Checkpoint memory previousCheckpoint = collectionCheckpoints[_collection][collectionCheckpoints[_collection].length - 1];

        // Save the new checkpoint
        checkpoint_ = Checkpoint({
→           compoundedFactor: locker.taxCalculator().calculateCompoundedFactor({
                _previousCompoundedFactor: previousCheckpoint.compoundedFactor,
                _utilizationRate: _utilizationRate,
                _timePeriod: block.timestamp - previousCheckpoint.timestamp
            }),
            timestamp: block.timestamp
        });
    }
```

Now we've come to the essence of the problem. `_currentCheckpoint()` fetches the **current** `utilizationRate` to calculate the new `compoundedFactor` for the current `block.timestamp` checkpoint which fetches the current CollectionToken `totalSupply()` and the collection's protected listings count. And an attacker can manipulate the former (`totalSupply`) without making the latter change and thus influence the utilization rate of a collection in the direction they wish.

https://github.com/sherlock-audit/2024-08-flayer/blob/main/flayer/src/contracts/ProtectedListings.sol#L261-L276
```solidity
    function utilizationRate(address _collection) public view virtual returns (uint listingsOfType_, uint utilizationRate_) {
        // Get the count of active listings of the specified listing type
        listingsOfType_ = listingCount[_collection];

        // If we have listings of this type then we need to calculate the percentage, otherwise
        // we will just return a zero percent value.
        if (listingsOfType_ != 0) {
            ICollectionToken collectionToken = locker.collectionToken(_collection);

            // If we have no totalSupply, then we have a zero percent utilization
→           uint totalSupply = collectionToken.totalSupply();
            if (totalSupply != 0) {
→               utilizationRate_ = (listingsOfType_ * 1e36 * 10 ** collectionToken.denomination()) / totalSupply;
            }
        }
    }
```
### Internal pre-conditions
None
### External pre-conditions
None
### Attack Path
A few attack vectors stemming from this absence of checkpointing in the functions mentioned above include:

1. You can deposit/redeem from Locker to bring down the utilization rate to, for example, avoid being liquidated as your listing health is calculated as `0.95e18 - tokenTaken * compoundedFactor increase since loan is taken`. 
2. You can redeem NFTs to bump up the utilization rate, take loans at a high compounded factor and when you want to repay or unlock, deposit these NFTs back so you soften the increase in compound factor.
3. You can grief other users by bumping up the utilization rate when they are unlocking or adjusting their position so they pay more interest as the interest rate is a function of the utilization rate.
4. You can worsen loans' health and cause otherwise healthy loans to be subject to liquidation.
### Impact
As outlined in the **Attack Path** section, the impact is quite substantial. The highest of all is griefing other users by forcing them to unexpectedly pay higher interest on their loans and make otherwise healthy loans become liquidateable.

Given the way utilization rate is calculated, we can see how each function that affects either a collection's CollectionToken total supply or the number of protected listings will affect the utilization rate of the collection:

$utilizationRate = \dfrac{collection\ protected\ listings\ count\ *\ 1e36\ *\ 10^{denomination}}{CT\ total\ supply}$

### PoC
See **Attack Path** and **Impact**.
### Mitigation
Simply checkpoint a collection's `compoundFactor` by calling **ProtectedListings**#`createCheckpoint()` at the end of the vulnerable functions.

## [Tax is resolved on liquidation listings when they are relisted](https://github.com/sherlock-audit/2024-08-flayer-judging/issues/388)

### Summary
A liquidation listing is treated as a normal batch auction listing – can be filled or relisted. Filling a liquidation listing, however, does **not** refund tax to the owner of the listing. On the other hand, relisting a liquidation listing doesn't take this into account and would happily send fee to the **UniswapImplementation** contract and refund tax to the owner of the listing in a situation where the owner never has actually paid tax on the protected listing, breaking a main protocol invariant.
### Root Cause
There is no check in the **Listings**#`relist()` function if the listing being relisted is a liquidation one or not which makes the relisting functionality process the tax for the listing. Liquidation listings are created only for protected listings once their collateral goes underwater. A main protocol invariant, however, is that tax is not paid on protected listings as the code shows and the sponsor also confirmed that.

https://github.com/sherlock-audit/2024-08-flayer/blob/main/flayer/src/contracts/Listings.sol#L625-L672
```solidity
    function relist(CreateListing calldata _listing, bool _payTaxWithEscrow) public nonReentrant lockerNotPaused {
        // Load our tokenId
        address _collection = _listing.collection;
        uint _tokenId = _listing.tokenIds[0];

        // Read the existing listing in a single read
        Listing memory oldListing = _listings[_collection][_tokenId];

        // Ensure the caller is not the owner of the listing
        if (oldListing.owner == msg.sender) revert CallerIsAlreadyOwner();

        // Load our new Listing into memory
        Listing memory listing = _listing.listing;

        // Ensure that the existing listing is available
        (bool isAvailable, uint listingPrice) = getListingPrice(_collection, _tokenId);
        if (!isAvailable) revert ListingNotAvailable();

        // We can process a tax refund for the existing listing
→       (uint _fees,) = _resolveListingTax(oldListing, _collection, true);
        if (_fees != 0) {
            emit ListingFeeCaptured(_collection, _tokenId, _fees);
        }

        // Find the underlying {CollectionToken} attached to our collection
        ICollectionToken collectionToken = locker.collectionToken(_collection);

        // If the floor multiple of the original listings is different, then this needs
        // to be paid to the original owner of the listing.
        uint listingFloorPrice = 1 ether * 10 ** collectionToken.denomination();
        if (listingPrice > listingFloorPrice) {
            unchecked {
                collectionToken.transferFrom(msg.sender, oldListing.owner, listingPrice - listingFloorPrice);
            }
        }

        // Validate our new listing
        _validateCreateListing(_listing);

        // Store our listing into our Listing mappings
        _listings[_collection][_tokenId] = listing;

        // Pay our required taxes
        payTaxWithEscrow(address(collectionToken), getListingTaxRequired(listing, _collection), _payTaxWithEscrow);

        // Emit events
        emit ListingRelisted(_collection, _tokenId, listing);
    }
```

https://github.com/sherlock-audit/2024-08-flayer/blob/main/flayer/src/contracts/Listings.sol#L918-L956
```solidity
    function _resolveListingTax(Listing memory _listing, address _collection, bool _action) private returns (uint fees_, uint refund_) {
        // If we have been passed a Floor item as the listing, then no tax should be handled
        if (_listing.owner == address(0)) {
            return (fees_, refund_);
        }

        // Get the amount of tax in total that will have been paid for this listing
        uint taxPaid = getListingTaxRequired(_listing, _collection);
        if (taxPaid == 0) {
            return (fees_, refund_);
        }

        // Get the amount of tax to be refunded. If the listing has already ended
        // then no refund will be offered.
        if (block.timestamp < _listing.created + _listing.duration) {
→           refund_ = (_listing.duration - (block.timestamp - _listing.created)) * taxPaid / _listing.duration;
        }

        // Send paid tax fees to the {FeeCollector}
        unchecked {
            fees_ = (taxPaid > refund_) ? taxPaid - refund_ : 0;
        }

        if (_action) {
            ICollectionToken collectionToken = locker.collectionToken(_collection);

            if (fees_ != 0) {
                IBaseImplementation implementation = locker.implementation();

                collectionToken.approve(address(implementation), fees_);
                implementation.depositFees(_collection, 0, fees_);
            }

            // If there is tax to refund, then allocate it to the user via escrow
            if (refund_ != 0) {
→               _deposit(_listing.owner, address(collectionToken), refund_);
            }
        }
    }
```
### Internal pre-conditions
Have a protected listing that's liquidated and thus a liquidation batch auction listing is created for it.
### External pre-conditions
None
### Attack Path
Not needed.
### Impact
Whenever a user borrows against an NFT by creating a protected listing and that listing gets liquidated, that same user will get refunded tax they've never paid in the first place when that NFT gets relisted. The user will effectively extract value out of thin air in the form of CollectionTokens which they can later convert to WETH or use to obtain another NFT.

This will also result in more fees being sent to the **UniswapImplementation** contract or if there aren't enough CollectionTokens for that collection available in the **Listings** contract it'll make relisting the NFT revert.
### PoC
1. John has an NFT from a collection and creates a protected listing for it, borrowing up to 0.95e18 CollectionTokens.
2. As time goes on the loan accrues interest and goes underwater.
3. A liquidator comes in and liquidates the listing by calling **ProtectedListings**#`liquidateProtectedListing()`.
4. Now a batch auction listing with a `duration` of 4 days and a `floorMultiple` of `400` is created in the **Listings** contract and John is set as the `owner` of the liquidation listing.
5. Dillon sees the listing and decides to relist it for a higher price, so he calls **Listings**#`relist()`.
6. The function proceeds to resolve the listing tax and refunds the appropriate amount of tax to the owner of the listing – John and also sends fee to the **UniswapImplementation** contract.
7. John has never paid tax on the protected listing but now tax is being resolved for that same listing.
### Mitigation
Just as in `_fillListing()` and `reserve()`, check if the listing is a liquidation one and if it is do **not** resolve its tax.
```diff
diff --git a/flayer/src/contracts/Listings.sol b/flayer/src/contracts/Listings.sol
index eb39e7a..fb65c45 100644
--- a/flayer/src/contracts/Listings.sol
+++ b/flayer/src/contracts/Listings.sol
@@ -641,9 +641,11 @@ contract Listings is IListings, Ownable, ReentrancyGuard, TokenEscrow {
         if (!isAvailable) revert ListingNotAvailable();
 
         // We can process a tax refund for the existing listing
-        (uint _fees,) = _resolveListingTax(oldListing, _collection, true);
-        if (_fees != 0) {
-            emit ListingFeeCaptured(_collection, _tokenId, _fees);
+        if (!_isLiquidation[_collection][_tokenId]) {
+            (uint _fees,) = _resolveListingTax(oldListing, _collection, true);
+            if (_fees != 0) {
+                emit ListingFeeCaptured(_collection, _tokenId, _fees);
+            }
         }
 
         // Find the underlying {CollectionToken} attached to our collection

```

## [Wrong division when adjusting `perSecondRate` in compounded factor calculation](https://github.com/sherlock-audit/2024-08-flayer-judging/issues/324)

### Summary
Due to dividing by a `1000` instead of `10000`, the `perSecondRate` will end up being 10 times bigger than it should be which will result in a orders of magnitude higher compounded factor causing loans' collateral to depreciate times quicker and cause users protected listings get liquidated sooner than expected. 
### Root Cause
When the compounded factor is calculated (in **TaxCalculator**#`calculateCompoundedFactor()`) the `perSecondRate` variable is **not** scaled down properly which causes a way higher final compounded factor.

https://github.com/sherlock-audit/2024-08-flayer/blob/main/flayer/src/contracts/TaxCalculator.sol#L80-L91
```solidity
    function calculateCompoundedFactor(uint _previousCompoundedFactor, uint _utilizationRate, uint _timePeriod) public view returns (uint compoundedFactor_) {
        // Get our interest rate from our utilization rate
        uint interestRate = this.calculateProtectedInterest(_utilizationRate);

        // Ensure we calculate the compounded factor with correct precision. `interestRate` is
        // in basis points per annum with 1e2 precision and we convert the annual rate to per
        // second rate.
        uint perSecondRate = (interestRate * 1e18) / (365 * 24 * 60 * 60);

        // Calculate new compounded factor
→       compoundedFactor_ = _previousCompoundedFactor * (1e18 + (perSecondRate / 1000 * _timePeriod)) / 1e18;
    }
```

`perSecondRate` is an amount with 1e20 precision as `interestRate` is a number with a precision of $1e2$ (100), meaning 100% is `100_00` and **not** `10_00` and the comments above the function confirm that.

https://github.com/sherlock-audit/2024-08-flayer/blob/main/flayer/src/contracts/TaxCalculator.sol#L53-L71
```solidity
    /**
     * ...
     * 
→    * @dev The interest rate is returned to 2 decimal places (200 = 2%)
     *
     * ...
     */
    function calculateProtectedInterest(uint _utilizationRate) public pure returns (uint interestRate_) {
        // If we haven't reached our kink, then we can just return the base fee
        if (_utilizationRate <= UTILIZATION_KINK) {
            // Calculate percentage increase for input range 0 to 0.8 ether (2% to 8%)
            interestRate_ = 200 + (_utilizationRate * 600) / UTILIZATION_KINK;
        }
        // If we have passed our kink value, then we need to calculate our additional fee
        else {
            // Convert value in the range 0.8 to 1 to the respective percentage between 8% and
            // 100% and make it accurate to 2 decimal places.
            interestRate_ = (((_utilizationRate - UTILIZATION_KINK) * (100 - 8)) / (1 ether - UTILIZATION_KINK) + 8) * 100;
        }
    }
```

Now coming back to the `perSecondRate` calculation:

https://github.com/sherlock-audit/2024-08-flayer/blob/main/flayer/src/contracts/TaxCalculator.sol#L87
```solidity
        uint perSecondRate = (interestRate * 1e18) / (365 * 24 * 60 * 60);
```

We see that `interestRate` ($1e2$ precision), scaled by $1e18$ will result in a $1e20$ precision result. Meaning in `compoundedFactor_` calculation we have to scale it down by `100_00` (100%) to get the correct rate in 18 decimals precision before multiplying by `_timePeriod`.

https://github.com/sherlock-audit/2024-08-flayer/blob/main/flayer/src/contracts/TaxCalculator.sol#L90
```solidity
        compoundedFactor_ = _previousCompoundedFactor * (1e18 + (perSecondRate / 1000 * _timePeriod)) / 1e18;
```
### Internal pre-conditions
None
### External pre-conditions
None
### Attack Path
No additional action required, the protocol by itself will compound 10 times higher interest on protected listings.
### Impact
Compounded interest will be 10 times higher than intended, primarily affecting protected listings as they are subject to paying interest on loaned CollectionToken amounts.
### PoC
Let's express the formula that `calculateCompoundedFactor()` uses and evaluate it using some sample values:
https://github.com/sherlock-audit/2024-08-flayer/blob/main/flayer/src/contracts/TaxCalculator.sol#L80-L91

$compoundedFactor = \dfrac{previousCompoundFactor\ *\ (1e18 + (perSecondRate\ / 1000 * \_timePeriod))}{1e18}$

**Where our sample values will be:**\
$previousCompoundFactor = 1e18$\
$interestRate = 80e2\ (80\%)$\
$perSecondRate = \dfrac{interestRate * 1e18}{365 * 24 * 60 * 60} = \dfrac{80e2 * 1e18}{31 536 000} = 253678335870116$\
$timePeriod = 1209600\ (14\ days)$

**Final equation becomes:**
$compoundedFactor = \dfrac{1e18 * (1e18 + \dfrac{\dfrac{80e2 * 1e18}{31536000}}{\textcolor{red}{10e2}} * 1209600)}{1e18}$

$compoundedFactor = \dfrac{1e18 * (1e18 + 253678335870 * 1209600)}{1e18}$

$compoundedFactor = \dfrac{1e18 * (1e18 + 306849315068352000)}{1e18}$

$compoundedFactor = \dfrac{1e18 * 1306849315068352000}{1e18}$

$compoundedFactor = 1.306849315068352000e18$

**But it actually should be:**\
$compoundedFactor = \dfrac{1e18 * (1e18 + \dfrac{\dfrac{80e2 * 1e18}{31536000}}{\textcolor{green}{10e3}} * 1209600)}{1e18}$

$compoundedFactor = \dfrac{1e18 * (1e18 + 25367833587 * 1209600)}{1e18}$

$compoundedFactor = \dfrac{1e18 * 1030684931506835200}{1e18}$\
$compoundedFactor = 1.030684931506835200e18$

**Or ~3% should have compounded for 2 weeks at interest rate of 80% instead of compounding 30%.**

### Mitigation
```diff
diff --git a/flayer/src/contracts/TaxCalculator.sol b/flayer/src/contracts/TaxCalculator.sol
index 915c0ff..14f714f 100644
--- a/flayer/src/contracts/TaxCalculator.sol
+++ b/flayer/src/contracts/TaxCalculator.sol
@@ -87,7 +87,7 @@ contract TaxCalculator is ITaxCalculator {
         uint perSecondRate = (interestRate * 1e18) / (365 * 24 * 60 * 60);
 
         // Calculate new compounded factor
-        compoundedFactor_ = _previousCompoundedFactor * (1e18 + (perSecondRate / 1000 * _timePeriod)) / 1e18;
+        compoundedFactor_ = _previousCompoundedFactor * (1e18 + (perSecondRate / 10000 * _timePeriod)) / 1e18;
     }
 
     /**
```


# Medium

## [Reserving a listing checkpoints the collection's `compoundFactor` at an intermediary higher compound factor](https://github.com/sherlock-audit/2024-08-flayer-judging/issues/533)
### Summary
When a listing is reserved (**Listings**#`reserve()`) there are multiple CollectionToken operations that affect its `totalSupply` that take place in the following order: transfer → transfer → burn → mint → transfer → burn. After the function ends execution the `totalSupply` of the CollectionToken itself remains unchanged compared to before the call to the function, but in the middle of its execution a protected listing is created and its compound factor is checkpointed at an intermediary state of the CollectionToken's total supply (between the first burn and the mint) that will later affect the rate of interest accrual on the loan itself in harm to the borrower causing them to actually accrue more interest on the loan.
### Root Cause
To be able to understand the issue, we must inspect what CollectionToken operations are performed throughout the execution of the `reserve()` function and at which point exactly the protected listing's `compoundFactor` is checkpointed.

(Will comment out the irrelevant parts of the function for brevity)
https://github.com/sherlock-audit/2024-08-flayer/blob/main/flayer/src/contracts/Listings.sol#L690-L759
```solidity
    function reserve(address _collection, uint _tokenId, uint _collateral) public nonReentrant lockerNotPaused {
        // ...
        
        if (oldListing.owner != address(0)) {
            // We can process a tax refund for the existing listing if it isn't a liquidation
            if (!_isLiquidation[_collection][_tokenId]) {
                // 1st transfer
→               (uint _fees,) = _resolveListingTax(oldListing, _collection, true);
                if (_fees != 0) {
                    emit ListingFeeCaptured(_collection, _tokenId, _fees);
                }
            }
            
            // ...
            
            if (listingPrice > listingFloorPrice) {
                unchecked {
                    // 2nd transfer
→                   collectionToken.transferFrom(msg.sender, oldListing.owner, listingPrice - listingFloorPrice);
                }
            }
            
            // ...
        }

        // 1st burn
→       collectionToken.burnFrom(msg.sender, _collateral * 10 ** collectionToken.denomination());

        // ...

        // the protected listing is recorded in storage with the just-checkpointed compoundFactor
        // then: mint + transfer
→       protectedListings.createListings(createProtectedListing);

        // 2nd burn
→       collectionToken.burn((1 ether - _collateral) * 10 ** collectionToken.denomination());

        // ...
    }
```

Due to the loan's `compoundFactor` being checkpointed before the second burn of `1 ether - _collateral` CollectionTokens (and before `listingCount[listing.collection]` is incremented) , the `totalSupply` will be temporarily decreased which will make the collection's utilization ratio go up a notch due to the way it's derived and this will eventually be reflected in the checkpointed `compoundFactor` for the current block and respectively for the loan as well.

https://github.com/sherlock-audit/2024-08-flayer/blob/main/flayer/src/contracts/ProtectedListings.sol#L117-L156
```solidity
    function createListings(CreateListing[] calldata _createListings) public nonReentrant lockerNotPaused {
        // ...
        
        for (uint i; i < _createListings.length; ++i) {
            // ...
            
            if (checkpointIndex == 0) {
                // @audit Checkpoint the temporarily altered `compoundFactor` due to the temporary
                // change in the CollectionToken's `totalSupply`.
→               checkpointIndex = _createCheckpoint(listing.collection);
                assembly { tstore(checkpointKey, checkpointIndex) }
            }

            // ...
            
            // @audit Store the listing with a pointer to the index of the inacurate checkpoint above
→           tokensReceived = _mapListings(listing, tokensIdsLength, checkpointIndex) * 10 ** locker.collectionToken(listing.collection).denomination();

            // Register our listing type
            unchecked {
                listingCount[listing.collection] += tokensIdsLength;
            }

            // ...
        }
    }
```

https://github.com/sherlock-audit/2024-08-flayer/blob/main/flayer/src/contracts/ProtectedListings.sol#L530-L571
```solidity
    function _createCheckpoint(address _collection) internal returns (uint index_) {
→       Checkpoint memory checkpoint = _currentCheckpoint(_collection);

        // ...
        
        collectionCheckpoints[_collection].push(checkpoint);
    }
```

`_currentCheckpoint()` will fetch the current utilization ratio which is temporarily higher and will calculate the current checkpoint's `compoundedFactor` with it (which the newly created loan will reference thereafter).

https://github.com/sherlock-audit/2024-08-flayer/blob/main/flayer/src/contracts/ProtectedListings.sol#L580-L596
```solidity
    function _currentCheckpoint(address _collection) internal view returns (Checkpoint memory checkpoint_) {
        // ...
→       (, uint _utilizationRate) = utilizationRate(_collection);

        // ...
        
        checkpoint_ = Checkpoint({
→           compoundedFactor: locker.taxCalculator().calculateCompoundedFactor({
                _previousCompoundedFactor: previousCheckpoint.compoundedFactor,
                _utilizationRate: _utilizationRate,
                _timePeriod: block.timestamp - previousCheckpoint.timestamp
            }),
            timestamp: block.timestamp
        });
    }
```

https://github.com/sherlock-audit/2024-08-flayer/blob/main/flayer/src/contracts/ProtectedListings.sol#L261-L276
```solidity
    function utilizationRate(address _collection) public view virtual returns (uint listingsOfType_, uint utilizationRate_) {
        listingsOfType_ = listingCount[_collection];
        // ...
        if (listingsOfType_ != 0) {
            // ...
→           uint totalSupply = collectionToken.totalSupply();
            if (totalSupply != 0) {
→               utilizationRate_ = (listingsOfType_ * 1e36 * 10 ** collectionToken.denomination()) / totalSupply;
            }
        }
    }
```
### Internal pre-conditions
None
### External pre-conditions
None
### Attack Path
No attack required.
### Impact
Knowing how a collection's utilization rate is calculated we can clearly see the impact it'll have on the checkpointed compounded factor for a block:

$utilizationRate = \dfrac{collection\ protected\ listings\ count\ *\ 1e36\ *\ 10^{denomination}}{CT\ total\ supply}$

The less CollectionToken (CT) total supply, the higher the utilization rate for a constant collection's protected listings count. The higher the utilization rate, the higher the `compoundedFactor` will be for the current checkpoint and for the protected position created (the loan). 

$compoundedFactor = \dfrac{previousCompoundFactor\ *\ (1e18 + (perSecondRate\ / 1000 * \_timePeriod))}{1e18}$\
Where:\
$perSecondRate = \dfrac{interestRate * 1e18}{365 * 24 * 60 * 60}$

$interestRate = 200 + \dfrac{utilizationRate * 600}{0.8e18}$ – When `utilizationRate` ≤ 0.8e18 (`UTILIZATION_KINK`)\
OR\
$interestRate = \bigg(\dfrac{(utilizationRate - 200) * (100 - 8)}{1e18 - 200} + 8\bigg) * 100$ – When `utilizationRate` > 0.8e18 (`UTILIZATION_KINK`)

As a result (and with the help of another issue that has a different root cause and a fix which is submitted separately) the loan will end up checkpointing a temporarily higher `compoundedFactor`  and thus will compound more interest in the future than it's correct to. It's important to know that no matter how many times `createCheckpoint()` is called after the call to `reserve()`, the `compoundFactor` for the current block's checkpoint will remain as. But even without that, there is **no guarantee** that even if it worked correctly, there'd by any calls that'd record a new checkpoint for that collection.
### PoC
1. Bob lists an NFT for sale. The `duration` and the `floorMultiple` of the listing are irrelevant in this case.
2. John sees the NFT and wants to reserve it, putting up $0.9e18$ amount of CollectionTokens as `_collateral`.
3. The `_collateral` is burned.
4. The collection's `compoundFactor` for the current block is checkpointed.

Let's say there is only one protected listing prior to John's call to `reserve()` and its owner has put up $0.5e18$ CollectionTokens as collateral.

$old\ collection\ token\ total\ supply = 5e18$\
$collection\ protected\ listings\ count = 1$

We can now calculate the utilization rate the way it's calculated right now:

$`utilizationRate = \dfrac{collection\ protected\ listings\ count\ *\ 1e36\ *\ 10^{denomination}}{CT\ total\ supply}`$\
$`utilizationRate = \dfrac{1*1e36*10^0}{5e18 - 0.9e18}`$ (assuming $`denomination`$ is $`0`$)

$utilizationRate = \dfrac{1e36}{4.1e18} = 243902439024390243$

We can now proceed to calculate the wrong compounded factor:

$compoundedFactor = \dfrac{previousCompoundFactor\ *\ (1e18 + (perSecondRate\ / 1000 * \_timePeriod))}{1e18}$

**Where**:\
$previousCompoundFactor = 1e18$\
$interestRate = 200 + \dfrac{utilizationRate * 600}{0.8e18} = 200 + \dfrac{243902439024390243 * 600}{0.8e18} = 382$ (3.82 %)\
$perSecondRate = \dfrac{interestRate * 1e18}{365 * 24 * 60 * 60} = \dfrac{382 * 1e18}{31 536 000} = 12113140537798$\
$timePeriod = 432000\ (5\ days)$ (last checkpoint was made 5 days ago)

$compoundedFactor = \dfrac{1e18 * (1e18 + (12113140537798 / 1000 * 432000))}{1e18}$

$compoundedFactor = \dfrac{1e18 * 1005232876711984000}{1e18} = 1005232876711984000$ (This will be the final compound factor for the checkpoint for the current block)

The correct utilization rate however, should be calculated with a current collection token total supply of $5e18$ at the time when `reserve()` is called, which will result in:\
$utilizationRate = \dfrac{collection\ protected\ listings\ count\ *\ 1e36\ *\ 10^{denomination}}{CT\ total\ supply} = \dfrac{1 * 1e36}{5e18} = 200000000000000000$ (the difference with the wrong utilization rate with $43902439024390243$ or ~$0.439e18$ which is ~18% smaller than the wrongly computed utilization rate).

From then on the interest rate will be lower and thus the final and correct compounded factor comes out at $1004794520547808000$ (will not repeat the formulas for brevity) which is around 0.05% smaller than the wrongly recorded compounded factor. The % might not be big but remember that this error will be bigger with the longer time period between the two checkpoints and will be compounding with every call to `reserve()`.

5. A protected listing is created for the reserved NFT, referencing the current checkpoint.
6. When the collection's `compoundFactor` is checkpointed the next time, the final `compoundFactor` product will be times greater due to the now incremented collection's protected listings count and the increased (back to the value before the reserve was made) total supply of CollectionTokens.

Lets say after another 5 days the `createCheckpoint()` method is called for that collection without any changes in the CollectionToken total supply or the collection's protected listings count. The math will remain mostly the same with little updates and we will first run the math with the wrongly computed $previousCompoundedFactor$ and then will compare it to the correct one.

$collection\ token\ total\ supply = 5e18$ (because the burned `_collateral` amount of CollectionTokens has been essentially minted to the **ProtectedListings** contract hence as we said `reserve()` does **not** affect the total supply after the function is executed).\
$collection\ protected\ listings\ count = 2$ (now 1 more due to the created protected listing)\
$previousCompoundedFactor = 1005232876711984000$ (the wrong one, as we derived it a bit earlier)

$utilizationRate = \dfrac{collection\ protected\ listings\ count\ *\ 1e36\ *\ 10^{denomination}}{CT\ total\ supply}$\
$utilizationRate = \dfrac{2 * 1e36 * 10^0}{5e18} = \dfrac{2e36}{5e18} = 0.4e18$^0

$interestRate = 200 + \dfrac{utilizationRate * 600}{0.8e18} = 200 + \dfrac{0.4e18 * 600}{0.8e18} = 500$ (5 %)\
$perSecondRate = \dfrac{interestRate * 1e18}{365 * 24 * 60 * 60} = \dfrac{500 * 1e18}{31 536 000} = 15854895991882$\
$timePeriod = 432000\ (5\ days)$ (the previous checkpoint was made 5 days ago)

$compoundedFactor = \dfrac{1005232876711984000 * (1e18 + (15854895991882 / 1000 * 432000)}{1e18}$\
$compoundedFactor = \dfrac{1005232876711984000 * 1006849315068112000}{1e18} = 1012118033401408964$ or 0.68% accrued interest for that collection for the past 5 days.

Now let's run the math but compounding on top of the correct compound factor:

$compoundedFactor = \dfrac{1004794520547808000 * 1006849315068112000}{1e18} = 1011676674797752473$ or 0.21% of interest should've been accrued for that collection for the past 5 days, instead of 0.68% which in this case is 3 times bigger.
### Mitigation
Just burn the `_collateral` amount after the protected listing is created. This way the `compoundedFactor` will be calculated and checkpointed properly.

```diff
diff --git a/flayer/src/contracts/Listings.sol b/flayer/src/contracts/Listings.sol
index eb39e7a..c8eac4d 100644
--- a/flayer/src/contracts/Listings.sol
+++ b/flayer/src/contracts/Listings.sol
@@ -725,10 +725,6 @@ contract Listings is IListings, Ownable, ReentrancyGuard, TokenEscrow {
             unchecked { listingCount[_collection] -= 1; }
         }
 
-        // Burn the tokens that the user provided as collateral, as we will have it minted
-        // from {ProtectedListings}.
-        collectionToken.burnFrom(msg.sender, _collateral * 10 ** collectionToken.denomination());
-
         // We can now pull in the tokens from the Locker
         locker.withdrawToken(_collection, _tokenId, address(this));
         IERC721(_collection).approve(address(protectedListings), _tokenId);
@@ -750,6 +746,10 @@ contract Listings is IListings, Ownable, ReentrancyGuard, TokenEscrow {
         // Create our listing, receiving the ERC20 into this contract
         protectedListings.createListings(createProtectedListing);
 
+        // Burn the tokens that the user provided as collateral, as we will have it minted
+        // from {ProtectedListings}.
+        collectionToken.burnFrom(msg.sender, _collateral * 10 ** collectionToken.denomination());
+
         // We should now have received the non-collateral assets, which we will burn in
         // addition to the amount that the user sent us.
         collectionToken.burn((1 ether - _collateral) * 10 ** collectionToken.denomination());

```
