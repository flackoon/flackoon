# Nibiru

> This report contains findings reported in the [Symbiotic](https://cantina.xyz/competitions/8bab566e-a6d4-4c1b-9f28-71a94bfd1da2) competition on Cantina by the me, [@flacko](https://x.com/flack00n).

# Summary

|Severity|Issues|Unique|
|--|--|--|
|[Medium](#medium)|1|0|
|[Low](#low)|1|0|

# Findings

# Medium

## Operator will end up withdrawing funds if veto slash requests are not executed in the order they were requested

### Summary
If two or more slashing requests are submitted consecutively and the second one (in the case of 2 requests) is executed before the first one, the operator of a vault will end up not being slashed for the first request (and the earlier requests in general), allowing them to commit dishonest attributions as operators and withdraw their stake after that.
### Description
There is a check in `executeslash()` that ensures that requests with `capturetimestamp` < `latestSlashedCaptureTimestamp[subnetwork]` cannot be executed and makes the function revert.

```solidity
    function executeSlash(
        uint256 slashIndex,
        bytes calldata hints
    ) external initialized nonReentrant returns (uint256 slashedAmount) {
        // ...

        address vault_ = vault;
        if (Time.Timestamp() - request.captureTimestamp > IVault(vault_).epochDuration()) {
            revert SlashPeriodEnded();
        }

→       _checkLatestSlashedCaptureTimestamp(request.subnetwork, request.captureTimestamp);

        // ...

→       _updateLatestSlashedCaptureTimestamp(request.subnetwork, request.captureTimestamp);


        // ...
    }
```

And upon successful execution of the slash sets the `latestSlashedCaptureTimestamp[subnetwork]` value to the just-processed `request.captureTimestmap`. If the network middleware happens to execute the second request before executing the first one, the first request becomes 'blocked' due to having the earlier `captureTimestamp` of the two.
### Impact
As a result the operator and the vault will end up **NOT** being slashed for the first offence they committed and if they've scheduled a withdrawal within the same epoch they've committed the slashable offence, they might be able to claim their withdrawals. 

![](https://imagedelivery.net/wtv4_V7VzVsxpAFaxzmpbw/4a523e8c-4dc8-4243-88be-9f8e22f68400/public)

### Proof of Concept
Let's look at the following scenario, depicted in the illustration above:
1. Operator commits slashable offence at some point in epoch 0 (this will be our $captureTimestamp$)
2. `requestSlash()` is called for the first time for that operator at $requestTimestamp_1$ for 
2. `requestSlash()` is called for the third time for that operator at $requestTimestamp_2$ due to how the network slashing mechanism works.
3. After the $vetoDuration$ on the request from $requestTimestamp_2$ passes, the network middleware proceeds to execute that request first.
4. `latestSlashedCaptureTimestamp[subnetwork]` is set to $captureTimestamp$
5. The slash request for $captureTimestamp_1$ is now impossible to be executed due to the `_checkLatestSlashedCaptureTimestamp(request.subnetwork, request.captureTimestamp)` check.
6. At some point in epoch 1 the middleware notices that and decides to request a 3rd slash request to slash the stake that was supposed to be slashed with the first request.
7. The veto phase of the 3rd request rolls into the second epoch where the scheduled withdrawals from epoch 0 are now claimable.
8. Operator and stakers claim their withdrawals escaping a bigger penalty (slash) than what they were supposed to get slashed by.
### Recommendation
Require that there is no pending slashing requests before the one being currently executed in `executeSlash()` in **VetoSlasher**.

# Low
## Veto slash requests are only executable by the network middleware and not by 'any participant'

### Summary
The documentation states that anyone can execute veto slash requests after they pass the veto phase without being veto-ed. The code, however, enforces a stricter access control allowing only the network middleware to execute the slash.
### Description
[The documentation on Veto slashing states](https://docs.symbiotic.fi/core-modules/vaults/#veto-slashing):
> After submitting a slashing request, there is a period of VV time to issue a veto on the slashing. The veto can be made by designated participants in the vault, known as resolvers. Each network can either have a resolver or not, and a resolver can cancel all of the slashing or pass the slashing to the next phase. If the slashing is not resolved after this phase, there is a period of $E=EPOCH−V−(request\_timestamp − capture\_timestamp)$ time to execute the slashing. Any participant can execute it.

If we look at `executeSlash()` however we can see that there's a call to: `_checkNetworkMiddleware(request.subnetwork)` that ensures that `msg.sender` is the designated middleware of the subnetwork in question, and if it is **NOT** – reverts.

```solidity
    function executeSlash(
        uint256 slashIndex,
        bytes calldata hints
    ) external initialized nonReentrant returns (uint256 slashedAmount) {
        ExecuteSlashHints memory executeSlashHints;
        if (hints.length > 0) {
            executeSlashHints = abi.decode(hints, (ExecuteSlashHints));
        }

        if (slashIndex >= slashRequests.length) {
            revert SlashRequestNotExist();
        }

        SlashRequest storage request = slashRequests[slashIndex];

→       _checkNetworkMiddleware(request.subnetwork);

        // ...
    }
```
### Impact
There is a clear discrepancy between the documentation and the code and the code breaks an invariant about the execution of Veto slash requests.
### Recommendation
Remove the `_checkNetworkMiddleware()` check or update the docs (after the contest concludes).

