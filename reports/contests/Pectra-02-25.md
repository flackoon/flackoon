# Ethereum Pectra Upgrade

> This report contains findings reported in the [Pectra](https://cantina.xyz/competitions/pectra) competition on Cantina by the me, [@flacko](https://x.com/flack00n).

# Summary

|Severity|Issues|Unique|
|--|--|--|
|[Informational](#informational)|1|0|

# Findings

# Informational

## (Nethermind) Authorization tuple nonce check is repeated
### Summary
The check that the nonce of an authorization tuple in a EIP-7702 SetCode transaction is repeated.
The check that the authorization tuple's `Nonce` is < `ulong.MaxValue` must be performed only once as it'd be sufficient.

### Recommendation
Remove the second if clause on line 290.
