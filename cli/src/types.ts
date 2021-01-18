/** Types */
export type address = string
export type chainId = string
export type ophash = string
export type publicKey = string
export type url = string

// An operation for the multisig to trigger.
export type OperationData = {
  address: address
  amountMutez: number
  entrypoint: string
  argSmartPy: string
}

// Result of originating a contract.
// TODO(keefertaylor): Copied from Kolibri deploy scripts. Dedupe.
export type ContractOriginationResult = {
  operationHash: ophash
  contractAddress: address
}
