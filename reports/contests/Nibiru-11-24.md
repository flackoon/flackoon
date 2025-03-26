
# Nibiru

> This report contains findings reported in the [Nibiru](https://code4rena.com/audits/2024-11-nibiru) competition on code4rena by the me, [@flacko](https://x.com/flack00n).

# Summary

|Severity|Issues|Unique|
|--|--|--|
|[Medium](#medium)|3|1|

# Findings

# Medium

## [EVM transactions bundled in a single SDK transaction will not receive gas refunds](https://github.com/code-423n4/2024-11-nibiru-findings/issues/66)

### Links to affected code
https://github.com/code-423n4/2024-11-nibiru/blob/8ed91a036f664b421182e183f19f6cef1a4e28ea/x/evm/keeper/msg_server.go#L86-L88
### Finding description and impact
When executing an **EVM** transaction message in `EthereumTx()` the sender is only refunded gas if their current **EVM** transaction's `GasLimit` is greater than all the gas used by **EVM** messages executed until now within the currently processed **SDK** transaction. This, however, is wrong because when a user bundles multiple **EVM** transactions in a single **SDK** transaction, `blockGasUsed` will be incremented by the actual gas consumed by every single transaction and the last **EVM** transactions in the bundle are at an increasing risk of **not** receiving a gas refund.

The gas in Nibiru is handled in the following manner (overly simplified):
1. User submits **EVM** transaction messages via a **SDK** transaction.
2. The ante handler deducts in advance the gas fees in `unibi` coins from the sender's bank coin balance.
3. **EVM** transactions are processed via `EthereumTx()`.
4. User is refunded the leftover gas that wasn't used at the same price they were charged by the ante handler.

The conditions under which the user is refunded their unused gas are wrong and will result in users **NOT** receiving gas refunds a lot of the times when they submit multiple **EVM** transactions in a single **SDK** transaction.

https://github.com/code-423n4/2024-11-nibiru/blob/8ed91a036f664b421182e183f19f6cef1a4e28ea/x/evm/keeper/msg_server.go#L31-L92
```go
func (k *Keeper) EthereumTx(
	goCtx context.Context, txMsg *evm.MsgEthereumTx,
) (evmResp *evm.MsgEthereumTxResponse, err error) {
  // ...

	evmResp, _, err = k.ApplyEvmMsg(tmpCtx, evmMsg, nil, true, evmConfig, txConfig, false)

  // ...

	blockGasUsed, err := k.AddToBlockGasUsed(ctx, evmResp.GasUsed)

	// refund gas in order to match the Ethereum gas consumption instead of the
	// default SDK one.
	refundGas := uint64(0)
	if evmMsg.Gas() > blockGasUsed {
		refundGas = evmMsg.Gas() - blockGasUsed
	}
	weiPerGas := txMsg.EffectiveGasPriceWeiPerGas(evmConfig.BaseFeeWei)
	if err = k.RefundGas(ctx, evmMsg.From(), refundGas, weiPerGas); err != nil {
		return nil, errors.Wrapf(err, "EthereumTx: error refunding leftover gas to sender %s", evmMsg.From())
	}
```

Here we see that the **EVM** transaction's `GasLimit` is checked if greater than `blockGasUsed`. `blockGasUsed` is set to 0 by the ante handler each time a new **SDK** transaction is executed. We can see in this code snippet that every `MsgEthereumTx` message will increment it by the gas that the currently processed **EVM** transaction actually consumed, so with each processed **EVM** transaction `blockGasUsed` will grow. By the time the second, or third **EVM** transaction message in a single **SDK** transaction is executed, this value will already be big enough so that it makes the if-clause evaluate to `false` every time.

On the other side, `evmResp.GasUsed` is the `GasLimit` of the processed **EVM** transaction minus the actually used gas and is capped at a maximum of the actual gas refunds accumulated while executing the transaction by the VM interpreter.

https://github.com/code-423n4/2024-11-nibiru/blob/8ed91a036f664b421182e183f19f6cef1a4e28ea/x/evm/keeper/msg_server.go#L369-L397
```go
	refundQuotient := params.RefundQuotientEIP3529
	if fullRefundLeftoverGas {
		refundQuotient = 1 // 100% refund
	}
	temporaryGasUsed := msg.Gas() - leftoverGas
	refund := GasToRefund(stateDB.GetRefund(), temporaryGasUsed, refundQuotient)

	// update leftoverGas and temporaryGasUsed with refund amount
	leftoverGas += refund
	temporaryGasUsed -= refund
	if msg.Gas() < leftoverGas {
		return nil, evmObj, errors.Wrapf(core.ErrGasUintOverflow, "ApplyEvmMsg: message gas limit (%d) < leftover gas (%d)", msg.Gas(), leftoverGas)
	}

	// Min gas used is a % of gasLimit
	gasUsed := math.LegacyNewDec(int64(temporaryGasUsed)).TruncateInt().Uint64()

	// This resulting "leftoverGas" is used by the tracer. This happens as a
	// result of the defer statement near the beginning of the function with
	// "vm.Tracer".
	leftoverGas = msg.Gas() - gasUsed

	return &evm.MsgEthereumTxResponse{
		GasUsed: gasUsed,
		VmError: vmError,
		Ret:     ret,
		Logs:    evm.NewLogsFromEth(stateDB.Logs()),
		Hash:    txConfig.TxHash.Hex(),
	}, evmObj, nil
```

And the problem boils down to comparing apples to oranges. We are comparing a single **EVM** transaction's `GasLimit` to all the gas used by all **EVM** transactions executed in the current **SDK** transaction, effectively making the user overpay for gas (by not receiving their refunds and the gas that hasn't been used). 
### Proof of Concept
1. User submits 3 **EVM** transactions (messages) in a single **SDK** transaction. Each of the **EVM** transactions has a `GasLimit` of 200 000.
2. The ante handler charges the user for $3 \times 200\ 000 = 600\ 000$ gas at a minimum price of 1 `unibi` per gas unit. 
2. The first **EVM** transaction is processed and it consumes 150 000 gas and has 30 000 of refunds (150 000 / 5).
3. `blockGasUsed` = 120 000 (0 + 150 000 - 30 000), `evmMsg.Gas()` = 200 000, so the user receives 80 000 gas units refunded back at the same price they paid initially.
4. The second **EVM** transaction is processed but it consumes only 100 000 gas. It has 20 000 gas units in refunds.
5. `blockGasUsed` = 200 000 (120 000 + 100 000 - 20 000), `evmMsg.Gas()` = 200 000. The user does does not receive any gas refund as `evmMsg.Gas() < blockGasUsed`, but they should've received 120 000 gas refunded back.
6. The third **EVM** transaction is processed. It consumes 80 000 gas. It's refund is 16 000 gas.
7. `blockGasUsed` = 264 000 (200 000 + 80 000 - 16 000), `evmMsg.Gas()`  = 200 000. Again, the user is not refunded any gas.

So the three transactions the user submitted consumed in total 264 000 gas units. They should've been reimbursed 336 000 gas but are only refunded 80 000 gas back.
### Recommended mitigation steps
Compare `evmMsg.Gas()` with `evmResp.GasUsed` instead, as it already has the refund deducted and shows the gas that was actually used by the EVM to process the message.
```go
if evmMsg.Gas() > evmResp.GasUsed {
	refundGas = evmMsg.Gas() - evmResp.GasUsed
}
```
## [Nonce can be manipulated by inserting a contract creation `EthereumTx` message first in an SDK TX with multiple `EthereumTX` messages](https://github.com/code-423n4/2024-11-nibiru-findings/issues/29)
### Links to affected code
https://github.com/code-423n4/2024-11-nibiru/blob/main/x/evm/keeper/msg_server.go#L330
### Finding description and impact
The Ante handler for `MsgEthereumTx` transactions is responsible for ensuring messages are coming with correct nonces. After doing so, it'll increment the account's sequences for each message that the account has signed and broadcasted.

The problem is that when the `EthereumTx()` message server method calls `ApplyEvmMsg()` it'll override the account nonce when the currently processed EVM transaction message is a contract creation and will set it to the nonce of the message. When a non-contract creation EVM transaction message is processed, however, the `ApplyEvmMsg()` method does **not** touch the account's nonce.

This opens up an exploit window where a malicious user can replay a TX multiple times and reuse their nonces. Users can manipulate their Sequence (nonce) by submitting a contract creation EVM transaction message and multiple call/transfer EVM transaction messages in a single SDK transaction.

The code relies on `evmObj.Call()` and later `stateDB.commitCtx()` to persist a correct nonce in state but the `Call()` method on `evmObj` does **not** handle account nonces, it just executes the transaction. As we can see the method in `geth` that's normally used to transition the state increments the sender's nonce by 1 in either case:

https://github.com/NibiruChain/go-ethereum/blob/nibiru/geth/core/state_transition.go#L331-L337
```go
	if contractCreation {
		ret, _, st.gas, vmerr = st.evm.Create(sender, st.data, st.gas, st.value)
	} else {
		// Increment the nonce for the next transaction
		st.state.SetNonce(msg.From(), st.state.GetNonce(sender.Address())+1)
		ret, st.gas, vmerr = st.evm.Call(sender, st.to(), st.data, st.gas, st.value)
	}
```
https://github.com/NibiruChain/go-ethereum/blob/nibiru/geth/core/vm/evm.go#L498-L501
```go
func (evm *EVM) Create(caller ContractRef, code []byte, gas uint64, value *big.Int) (ret []byte, contractAddr common.Address, leftOverGas uint64, err error) {
	contractAddr = crypto.CreateAddress(caller.Address(), evm.StateDB.GetNonce(caller.Address()))
	return evm.create(caller, &codeAndHash{code: code}, gas, value, contractAddr, CREATE)
}
```
https://github.com/NibiruChain/go-ethereum/blob/7fb652f186b09b81cce9977408e1aff744f4e3ef/core/vm/evm.go#L405-L418
```go
func (evm *EVM) create(caller ContractRef, codeAndHash *codeAndHash, gas uint64, value *big.Int, address common.Address, typ OpCode) ([]byte, common.Address, uint64, error) {
	// Depth check execution. Fail if we're trying to execute above the
	// limit.
	if evm.depth > int(params.CallCreateDepth) {
		return nil, common.Address{}, gas, ErrDepth
	}
	if !evm.Context.CanTransfer(evm.StateDB, caller.Address(), value) {
		return nil, common.Address{}, gas, ErrInsufficientBalance
	}
	nonce := evm.StateDB.GetNonce(caller.Address())
	if nonce+1 < nonce {
		return nil, common.Address{}, gas, ErrNonceUintOverflow
	}
	evm.StateDB.SetNonce(caller.Address(), nonce+1)
```

But `ApplyEvmMsg()` calls `evmObj.Call()` (`st.evm.Call()` in the above code snippet) directly and does not increment sender's nonce:
```go
	if contractCreation {
		// take over the nonce management from evm:
		// - reset sender's nonce to msg.Nonce() before calling evm.
		// - increase sender's nonce by one no matter the result.
		stateDB.SetNonce(sender.Address(), msg.Nonce())
		ret, _, leftoverGas, vmErr = evmObj.Create(
			sender,
			msg.Data(),
			leftoverGas,
			msgWei,
		)
		stateDB.SetNonce(sender.Address(), msg.Nonce()+1)
	} else {
		ret, leftoverGas, vmErr = evmObj.Call(
			sender,
			*msg.To(),
			msg.Data(),
			leftoverGas,
			msgWei,
		)
	}
```
### Proof of Concept
1. User constructs an **SDK** transaction with 4 `MsgEthereumTx` messages in it.
2. The first message is an **EVM** transaction that creates a new contract and has a nonce 1.
3. The next three messages are also **EVM** transactions that transfer ether (unibi as its the native unit of account in Nibiru's EVM) or just call some contracts.
4. The three messages have nonces of 2, 3 and 4.
5. The user broadcasts the **SDK** transaction. It passes validation through the Ante handler and is included in the mempool.
6. The TX is picked up to be processed by `DeliverTx()` method and the Ante handler is called again.
7. The Ante handler increments the `MsgEthereumTx` message sender's sequence (nonce) for each **EVM** transaction message.
8. User's sequence (nonce) in their SDK `x/auth` account is currently 5 (the next consecutive ready-for-use nonce).
9. `ApplyEvmMsg()` is called to process the first **EVM** transaction message and since it's a contract creation transaction it sets the sender's sequence (nonce) to `msg.Nonce() + 1`. After running the transaction through the geth interpreter, the account `stateObject` properties (like nonce, code hash and account state) are persisted to the `x/evm` module keeper's storage by calling `stateDB.Commit()`. The user account's `Sequence` is now reset to `msg.Nonce() + 1` (equal to 2).
10. The remaining three messages with nonces (2, 3, and 4) are then executed but the user's sequence (nonce) is still at `2`.
11. User can now replay their last three messages.


| SDK TX Message # | Contract creation | Message nonce | Account sequence set by ante handler | Account sequence after execution                |
| ---------------- | ----------------- | ------------- | ------------------------------------ | ----------------------------------------------- |
| 1                | true              | 1             | 1                                    | 1 (set by `ApplyEvmMsg()`)                      |
| 2                | false             | 2             | 2                                    | 1 (not updated as `contractCreation == false` ) |
| 3                | false             | 3             | 3                                    | 1                                               |
| 4                | false             | 4             | 4                                    | 1                                               |
### Recommended mitigation steps
Set the sender's nonce to `msg.Nonce() + 1` when `contractCreation` is `false`. 

## [Nibiru is incompatible with rebasing ERC20 tokens](https://github.com/code-423n4/2024-11-nibiru-findings/issues/65)

### Links to affected code
https://github.com/code-423n4/2024-11-nibiru/blob/8ed91a036f664b421182e183f19f6cef1a4e28ea/x/evm/precompile/funtoken.go#L109
### Finding description and impact
The Nibiru chain is designed to handle FOT tokens properly but is incompatible with ERC20 tokens where balances can change outside of transfers (also known as rebasing tokens). The problem arises from the fact that Nibiru doesn't keep any internal accounting for the ERC20 tokens for which FunTokens are created.

This allows for a situation where users deposit a rebasing ERC20 token in exchange for `x/bank` coins (through a FunToken mapping) and later only being able to withdraw their initial deposit in case the underlying ERC20 token rebases up or incur losses for other depositors in case the token rebases down.
### Proof of Concept
Suppose user A and B convert each $1\ 000$ `token`s to a bank coin via `sendToBank()` on the `FunToken` precompile contract.
1. Each one of them transfer $1\ 000$ `token` to the `x/evm` ETH account.
2. `x/evm` ETH account now holds $2\ 000$ `token` ERC20 tokens.
2. Each user gets minted $1\ 000$ `erc20/token` bank coins. Summed up, they have $2\ 000$ `erc20/token` bank tokens.
3. Some time passes and the `token` ERC20 token shrinks by 10%.
4. The `x/evm` module ETH account now owns only $1\ 900$ `token` ERC20 tokens.
5. User A calls `ConvertCoinToEvm()` to convert back their $1\ 000$ `erc20/token` bank tokens into the `token` ERC20 token.
6. User B calls `ConvertCoinToEvm()` to also convert back their $1\ 000$ `erc20/token` bank tokens into the `token` ERC20 token, but their request fails, as the `x/evm` module ETH account only has a balance of $900$ `token` ERC20 tokens.
7. User B carries the entire $100$ `token`s loss instead of it being split 50/50 between the 2 users.
### Recommended mitigation steps
Implementing an internal accounting to support rebasing tokens properly.
