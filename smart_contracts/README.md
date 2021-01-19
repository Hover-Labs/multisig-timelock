# Multisig Timelock Contract

This smart contract creates a multisig contract with a timelock. 

The contract maintains a operationId to prevent replay attacks. Additionally, the chain ID is also checked to prevent replay attacks. 

When an operation is submitted, it is placed in a timelock and can be executed after the timelock length has passed. Multiple operations can be timelocked at the same time. Anyone can execute operations in a timelock after the time has passed.

A CLI is provided as well, which helps create and formulate bytes to sign and submit to the contract.

## Building and Testing

You will need the [SmartPy CLI](https://smartpy.io).

To build and test the contract, run:
```
$ ./compile.sh
```

## Contract Parameters

The contract can be configured with the following parameters:
- `threshold` (`nat`): The number of signers required to submit an operation
- `signers` (`list(key)`): A list of public keys which can sign an operation
- `timelockSeconds` (`nat`): The number of seconds operations must remain in a timelock before they can be executed. 

## Contract Specification

The contract defined the following entrypoints:

### submit

Submits an operation to the timelock. The operation will be assigned an `operationId`, which is the value of the operationId it was submitted with. After the operation has been in the timelock for long enough, anyone can call the `execute` entrypoint with the `operationId` to submit the transaction.

Parameter: `sp.TPair(sp.TMap(sp.TKeyHash, sp.TSignature), sp.TPair(sp.TChainId, sp.TPair(sp.TNat,  sp.TLambda(sp.TUnit, sp.TList(sp.TOperation)))))`

In order, the nested params in the pair represent:
- `signatureMap`: A map of public keys to signatures. The signature is produced by signing the serialized bytes of the remainder of the parameter (`sp.TPair(sp.TChainId, sp.TPair(sp.TNat,  sp.TLambda(sp.TUnit, sp.TList(sp.TOperation))))`)
- `chainId`: The ID of the chain the contract is on.
- `operationId`: The operationId of the contract. This is produced by reading the `operationId` field from contract storage and incrementing by 1.
- `operation`: A lambda that will produce a list of operations to execute.

### execute

Executes an operation in the timelock. This call will fail if the operation has not been in the timelock for long enough.

Parameter: `nat`. The `operationId` of the operation to executed. The `operationID` is the operationId the operation was submitted with, and the key of the operation in the `timelock` map in the contract's storage.

### cancel

Cancels an operation in the timelock.

Parameter: `sp.TPair(sp.TMap(sp.TKeyHash, sp.TSignature), sp.TPair(sp.TChainId, sp.TPair(sp.TNat, sp.TNat)))`

In order, the nested params in the pair represent:
- `signatureMap`: A map of public keys to signatures. The signature is produced by signing the serialized bytes of the remainder of the parameter (`sp.TPair(sp.TChainId, sp.TPair(sp.TNat, sp.TNat))`)
- `chainId`: The ID of the chain the contract is on.
- `operationId`: The operationId of the contract. This is produced by reading the `operationId` field from contract storage and incrementing by 1.
- `operationId`: The operation to cancel. The `operationID` is the operationId the operation was submitted with, and the key of the operation in the `timelock` map in the contract's storage.

### rotate

Rotate keys for the timelock. This operation is applied instantly and is not subject to a waiting period.

Parameter: `sp.TPair(sp.TMap(sp.TKeyHash, sp.TSignature), sp.TPair(sp.TChainId, sp.TPair(sp.TNat, sp.TPair(sp.TNat, sp.TList(sp.TKey)))))`

In order, the nested params in the pair represent:
- `signatureMap`: A map of public keys to signatures. The signature is produced by signing the serialized bytes of the remainder of the parameter (`sp.TPair(sp.TChainId, sp.TPair(sp.TNat, sp.TPair(sp.TNat, sp.TList(sp.TKey))))`)
- `chainId`: The ID of the chain the contract is on.
- `operationId`: The operationId of the contract. This is produced by reading the `operationId` field from contract storage and incrementing by 1.
- `newThreshold`: The new threshold to use fo signers.
- `newSignerList`: The new list of signers for the multisig.
