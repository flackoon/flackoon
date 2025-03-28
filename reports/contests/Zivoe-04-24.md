# Zivoe

> This report contains findings reported in the [Zivoe](https://audits.sherlock.xyz/contests/280) competition on Sherlock by the me, [@flacko](https://x.com/flack00n), as a part of the Sentryx security team.

# Summary

|Severity|Issues|Unique|
|--|--|--|
|[High](#high)|1|0|
|[Medium](#medium)|1|0|

# Findings

# High

## [Tokens will be stuck in ZivoeRewards contracts because of precision loss when calculating reward rate](https://github.com/sherlock-audit/2024-03-zivoe-judging/issues/386)

### Summary
Due to precision loss when calculating the `rewardRate` in the rewards and vesting contracts, reward tokens will accumulate and be left stuck.

### Vulnerability Detail
When rewards are deposited to an instance of **ZivoeRewards** or **ZivoeRewardsVesting** via `depositRewards()`, the `rewardRate` for the deposited `_rewardsToken` will be either calculated for the first time or recalculated if there have already been deposited rewards for that token and their `periodFinish` hasn't elapsed yet. In any case though, there'll be a precision loss when dividing the rewards by the duration:

```solidity
        if (block.timestamp >= rewardData[_rewardsToken].periodFinish) {
→           rewardData[_rewardsToken].rewardRate = reward.div(rewardData[_rewardsToken].rewardsDuration);
        } else {
            uint256 remaining = rewardData[_rewardsToken].periodFinish.sub(block.timestamp);
            uint256 leftover = remaining.mul(rewardData[_rewardsToken].rewardRate);
→           rewardData[_rewardsToken].rewardRate = reward.add(leftover).div(rewardData[_rewardsToken].rewardsDuration);
        }
```

The two contracts in question have no means of handling that dust amount accumulated over time and it will essentially remain stuck.
### Impact
Let's consider the following two examples:
1. The current period for a `_rewardsToken` has finished
    `reward` = 1000e18
    `rewardsDuration` = 30 days = 2952000 seconds
    `rewardRate` = 385802469135802
    Running back the check: `rewardRate` * `rewardsDuration` = 999999999999998784000. We get 1216000 difference because of the precision loss.
2. The current period for a `rewardsToken` has not finished yet
    `reward` = 1000e18
    `rewardsDuration` = 30 days = 2952000 seconds
    `rewardRate` = 385802469135802 (using the former `rewardRate`)
    
    `remaining` = 15 days (half of `rewardsDuration` have passed) 
    `leftover` = `remaining` * `rewardRate` = 499999999999999392000
    `rewardRate` = (`reward` + `lefover`) / `rewardsDuration` = (1000e18 + 499999999999999392000) / 29520000 = 1499999999999999392000 / 2952000 = 578703703703703
    Running back the check: `rewardRate` * `rewardsDuration` = 1499999999999998176000.
    `leftover` + `reward` = 499999999999999392000 + 1000e18 = 1499999999999999392000
    The difference of 1216000 is still there.

In the above calculations, `reward` is still quite the round number. If it was just 1 ether worth of reward token less - 999e18 - the difference lost because of precision loss would grow to 1728000. Now this might not seem like much, but considering there will be 3 instances of **ZivoeRewards** and one instance of **ZivoeRewardsVesting** that makes 4 contracts accumulating stuck assets + every different `_rewardsToken` will suffer precision loss when calculating the reward rate for it. Another factor that will make matters worse is the less decimals of precision a reward token has, the bigger the precision loss hence the larger the amount of stuck tokens that'll accumulate.

### Code Snippet
https://github.com/sherlock-audit/2024-03-zivoe/blob/main/zivoe-core-foundry/src/ZivoeRewards.sol#L232-L238\
https://github.com/sherlock-audit/2024-03-zivoe/blob/main/zivoe-core-foundry/src/ZivoeRewardsVesting.sol#L356-L362

### Tool used
Manual Review

### Recommendation
Implement a `skim`-like function that allows for the dust accumulated in these contracts instances to be transferred to the DAO for example, or deposit the dust amount 'virtually' to the contract itself so it can be distributed when enough of it accumulates.

# Medium

## [Pushing assets to OCL ZVE locker would revert unnecessarily](https://github.com/sherlock-audit/2024-03-zivoe-judging/issues/320)

### Summary
When **OCL ZVE**'s `pushToLockerMulti()` is called, either of the `assert`s after the `addLiquidity()` call to Uni V2's router would revert when not entire allowance of either of the tokens is used by the Uniswap pool even though the call went through.
### Vulnerability Detail
After the call that adds liquidity to the Uni V2 pool in `pushToLockerMulti()`, the **OCL_ZVE** contract asserts that the Uni router consumed the entire allowance given to it for both tokens ZVE and pairAsset. However, it's not guaranteed that the entirety of these allowances would be consumed resulting in the inability to deposit the tokens even though the `addLiquidity()` call to the Uni router succeeded. It's enough 1 wei of either ZVE or pairAsset to remain in the allowance to the router and the call is guaranteed to revert.

```solidity
    function pushToLockerMulti(
        address[] calldata assets, uint256[] calldata amounts, bytes[] calldata data
    ) external override onlyOwner nonReentrant {
        // ... 
        
        // Router addLiquidity() endpoint.
        uint balPairAsset = IERC20(pairAsset).balanceOf(address(this));
        uint balZVE = IERC20(ZVE).balanceOf(address(this));
        IERC20(pairAsset).safeIncreaseAllowance(router, balPairAsset);
        IERC20(ZVE).safeIncreaseAllowance(router, balZVE);

        // Prevent volatility of greater than 10% in pool relative to amounts present.
        (uint256 depositedPairAsset, uint256 depositedZVE, uint256 minted) = IRouter_OCL_ZVE(router).addLiquidity(
            pairAsset, 
            ZVE, 
            balPairAsset,
            balZVE, 
            (balPairAsset * 9) / 10,
            (balZVE * 9) / 10, 
            address(this), block.timestamp + 14 days
        );
        emit LiquidityTokensMinted(minted, depositedZVE, depositedPairAsset);
        
→       assert(IERC20(pairAsset).allowance(address(this), router) == 0);
→       assert(IERC20(ZVE).allowance(address(this), router) == 0);

        // ...
    }
```
### Impact
Locker will essentially be unable to add liquidity to the _ZVE/pairAsset_ Uniswap pool even though the liquidity addition to the pool itself succeeded resulting in the contract DOSing itself.

### Code Snippet
https://github.com/sherlock-audit/2024-03-zivoe/blob/main/zivoe-core-foundry/src/lockers/OCL/OCL_ZVE.sol#L208-L209

### Tool used
Manual Review

### Recommendation
We suspect the protocol intends to guard itself from leaving unnecessary allowances to the Uni router but the approach seems a bit odd. If that's the case we suggest decreasing allowances to the router to 0 after the call to `addLiquidity()`, otherwise the asserts can simply be removed.

