import Utils from './utils'
import { OperationData, url, address, publicKey } from './types'
import {
  getChainId,
  getNonce,
  compileOperation,
  loadContract,
  deployContract,
} from './helpers'
import {
  TezosParameterFormat,
  TezosNodeReader,
  TezosNodeWriter,
  TezosMessageUtils,
} from 'conseiljs'
import OperationFeeEstimator from './operation-fee-estimator'
import Constants from './constants'

/** Constants */
const CONTRACT_SOURCE = `${__dirname}/msig-timelock.tz`

/** Command functions */

/**
 * Retrieve bytes to sign to submit an operation.
 *
 * @param operation The operation to encode.
 * @param nodeUrl The URL of the tezos node.
 * @param nonce The nonce to use. If undefined, a nonce will be fetched from the multisig contract.
 * @param multiSigContractAddress The address of the multisig contract.
 * @param attemptAutomatic Attempt to automatically produce bytes.
 */
export const bytesToSubmit = async (
  operation: OperationData,
  nodeUrl: url,
  nonce: number | undefined,
  multiSigContractAddress: address,
  attemptAutomatic: boolean,
): Promise<void> => {
  const chainId = await getChainId(nodeUrl)
  const actualNonce = nonce
    ? nonce
    : (await getNonce(multiSigContractAddress, nodeUrl)) + 1

  const lambda = compileOperation(operation)
  const michelson = `Pair "${chainId}" (Pair ${actualNonce} ${lambda})`

  Utils.print('Data to encode')
  Utils.print(`Pair "${chainId}" (Pair ${actualNonce} ${lambda})'`)
  Utils.print(``)

  Utils.print('Encode bytes with: ')
  Utils.print(
    `tezos-client -E ${nodeUrl} hash data 'Pair "${chainId}" (Pair ${actualNonce} ${lambda})' of type 'pair chain_id (pair nat (lambda unit (list operation)))'`,
  )
  Utils.print('')

  Utils.print(`Verify these bytes with: `)
  Utils.print(`tezos-client -E ${nodeUrl} unpack michelson data  0x<BYTES>`)
  Utils.print('')

  Utils.print(`Sign these bytes with: `)
  Utils.print(`tezos-client -E ${nodeUrl} sign bytes  0x<BYTES> for <KEY>`)
  Utils.print('')

  if (attemptAutomatic) {
    const hex = TezosMessageUtils.writePackedData(
      michelson,
      'pair (chain_id) (pair (nat) (lambda unit (list operation)))',
      TezosParameterFormat.Michelson,
    )
    Utils.print(
      `[Experimental] I tried to encode the bytes myself. Here is what I came up with: `,
    )
    Utils.print(hex)
    Utils.print('')
  }
}

/**
 * Retrieve bytes to sign for a key rotation.
 *
 * @param threshold The new signing threshhold.
 * @param keyList The new list of keys.
 * @param nodeUrl The URL of the tezos node.
 * @param nonce The nonce to use. If undefined, a nonce will be fetched from the multisig contract.
 * @param multiSigContractAddress The address of the multisig contract.
 * @param attemptAutomatic Attempt to automatically produce bytes.
 */
export const keyRotationbytesToSubmit = async (
  threshold: number,
  keyList: Array<publicKey>,
  nodeUrl: url,
  nonce: number | undefined,
  multiSigContractAddress: address,
  attemptAutomatic: boolean,
): Promise<void> => {
  const chainId = await getChainId(nodeUrl)
  const actualNonce =
    nonce ? nonce : (await getNonce(multiSigContractAddress, nodeUrl)) + 1

  const keyListMichelson = keyList.reduce((previous, current) => {
    return `${previous} "${current}";`
  }, '')

  const michelson = `Pair "${chainId}" (Pair ${actualNonce} (Pair ${threshold} {${keyListMichelson}}))`

  Utils.print('Data to encode')
  Utils.print(`${michelson}`)
  Utils.print(``)

  Utils.print('Encode bytes with: ')
  Utils.print(
    `tezos-client -E ${nodeUrl} hash data '${michelson}' of type 'pair chain_id (pair nat (pair nat (list key)))'`,
  )
  Utils.print('')

  Utils.print(`Verify these bytes with: `)
  Utils.print(`tezos-client -E ${nodeUrl} unpack michelson data  0x<BYTES>`)
  Utils.print('')

  Utils.print(`Sign these bytes with: `)
  Utils.print(`tezos-client -E ${nodeUrl} sign bytes  0x<BYTES> for <KEY>`)
  Utils.print('')

  if (attemptAutomatic) {
    const hex = TezosMessageUtils.writePackedData(
      michelson,
      'pair chain_id (pair nat (pair nat (list key)))',
      TezosParameterFormat.Michelson,
    )
    Utils.print(
      `[Experimental] I tried to encode the bytes myself. Here is what I came up with: `,
    )
    Utils.print(hex)
    Utils.print('')
  }
}

/**
 * Retrieve bytes to sign for a cancel operation.
 *
 * @param operationId The operation id to cancel.
 * @param nodeUrl The URL of the tezos node.
 * @param nonce The nonce to use. If undefined, a nonce will be fetched from the multisig contract.
 * @param multiSigContractAddress The address of the multisig contract.
 * @param attemptAutomatic Attempt to automatically produce bytes.
 */
export const cancelbytesToSubmit = async (
  operationId: number,
  nodeUrl: url,
  nonce: number | undefined,
  multiSigContractAddress: address,
  attemptAutomatic: boolean,
): Promise<void> => {
  const chainId = await getChainId(nodeUrl)
  const actualNonce =
    nonce ? nonce : (await getNonce(multiSigContractAddress, nodeUrl)) + 1

  const michelson = `Pair "${chainId}" (Pair ${actualNonce} ${operationId})`

  Utils.print('Data to encode')
  Utils.print(`${michelson}`)
  Utils.print(``)

  Utils.print('Encode bytes with: ')
  Utils.print(
    `tezos-client -E ${nodeUrl} hash data '${michelson}' of type 'pair chain_id (pair nat nat)'`,
  )
  Utils.print('')

  Utils.print(`Verify these bytes with: `)
  Utils.print(`tezos-client -E ${nodeUrl} unpack michelson data  0x<BYTES>`)
  Utils.print('')

  Utils.print(`Sign these bytes with: `)
  Utils.print(`tezos-client -E ${nodeUrl} sign bytes  0x<BYTES> for <KEY>`)
  Utils.print('')

  if (attemptAutomatic) {
    const hex = TezosMessageUtils.writePackedData(
      michelson,
      'pair chain_id (pair nat nat)',
      TezosParameterFormat.Michelson,
    )
    Utils.print(
      `[Experimental] I tried to encode the bytes myself. Here is what I came up with: `,
    )
    Utils.print(hex)
    Utils.print('')
  }
}

/**
 * Deploys a multisig contract.
 *
 * @param timelockSeconds The number of seconds the timelock will last for.
 * @param threshold The number of signatures required for the multisig.
 * @param publicKeys An array of public keys.
 * @param nodeUrl The url of the Tezos node.
 * @param privateKey The private key to sign the transaction with. Only keys starting with edsk are supported.
 */
export const deployMultisig = async (
  timelockSeconds: number,
  threshold: number,
  publicKeys: Array<publicKey>,
  nodeUrl: url,
  privateKey: string,
): Promise<void> => {
  const source = loadContract(CONTRACT_SOURCE)

  // Sort public keys alphabetically (required by Tezos) and create a michelson list.
  const sortedPublicKeys = publicKeys.sort()
  const michelsonPublicKeyList = sortedPublicKeys.reduce(
    (previous: string, current: publicKey) => {
      return `${previous} "${current}"`
    },
    '',
  )

  // Formulate initial storage.
  // Note: 0 literal is a nonce.
  const storage = `(Pair(Pair 0 { ${michelsonPublicKeyList}}) (Pair ${threshold} (Pair { } ${timelockSeconds})))`

  const keyStore = await Utils.keyStoreFromPrivateKey(privateKey)
  const signer = await Utils.signerFromKeyStore(keyStore)

  Utils.print(`Deploying from: ${keyStore.publicKeyHash} `)
  Utils.print(`Storage: ${storage} `)

  await Utils.revealAccountIfNeeded(nodeUrl, keyStore, signer)

  let counter = await TezosNodeReader.getCounterForAccount(
    nodeUrl,
    keyStore.publicKeyHash,
  )

  counter++
  const deployResult = await deployContract(
    nodeUrl,
    source,
    storage,
    keyStore,
    counter,
  )

  Utils.print(`Deployed!`)
  Utils.print(`Address: ${deployResult.contractAddress} `)
  Utils.print(`Operation Hash: ${deployResult.operationHash} `)
}

/**
 * Cancels an operation.
 *
 * @param operationId The operation to cancel.
 * @param addresses Parallel sorted arrays of addresses.
 * @param signatures Parrell sorted array of signatures.
 * @param nonce The nonce.
 * @param multiSigContractAddress The address of the multisig
 * @param nodeUrl The url of the Tezos node.
 * @param privateKey The private key to sign the transaction with. Only keys starting with edsk are supported.
 * @param attemptAutomatic Attempt to automatically produce bytes.
 */
export const cancel = async (
  operationId: number,
  addresses: Array<address>,
  signatures: Array<string>,
  nonce: number,
  multiSigContractAddress: address,
  nodeUrl: url,
  privateKey: string,
  attemptAutomatic: boolean,
): Promise<void> => {
  const keyStore = await Utils.keyStoreFromPrivateKey(privateKey)
  const signer = await Utils.signerFromKeyStore(keyStore)

  Utils.print(`Submitting cancel operation from: ${keyStore.publicKeyHash} `)
  Utils.print(`Using nonce: ${nonce} `)

  await Utils.revealAccountIfNeeded(nodeUrl, keyStore, signer)

  const counter = await TezosNodeReader.getCounterForAccount(
    nodeUrl,
    keyStore.publicKeyHash,
  )

  const chainId = await getChainId(nodeUrl)

  let signaturesMap = ''
  for (let i = 0; i < addresses.length; i++) {
    const address = addresses[i]
    const signature = signatures[i]

    signaturesMap += `Elt "${address}" "${signature}"; `
  }

  const param = `Pair { ${signaturesMap} } (Pair "${chainId}" (Pair ${nonce} ${operationId}))`
  Utils.print(`Invoking with param: ${param}`)
  Utils.print('')

  Utils.print(`Use tezos-client to submit the operation manually.`)
  Utils.print(
    `tezos-client -E ${nodeUrl} transfer 0 from ${keyStore.publicKeyHash} to ${multiSigContractAddress} --arg '${param}' --entrypoint 'cancel'`,
  )
  Utils.print('')

  if (attemptAutomatic) {
    Utils.print(`Attempting to inject automatically:`)
    const operation = TezosNodeWriter.constructContractInvocationOperation(
      keyStore.publicKeyHash,
      counter + 1,
      multiSigContractAddress,
      0,
      0,
      Constants.storageLimit,
      Constants.gasLimit,
      'cancel',
      `${param} `,
      TezosParameterFormat.Michelson,
    )

    const operationFeeEstimator = new OperationFeeEstimator(nodeUrl)
    const operationsWithFees = await operationFeeEstimator.estimateAndApplyFees(
      [operation],
    )

    const nodeResult = await TezosNodeWriter.sendOperation(
      nodeUrl,
      operationsWithFees,
      signer,
    )

    const hash = nodeResult.operationGroupID.replace(/"/g, '')
    Utils.print(`Executed with hash: ${hash} `)
  }
}

/**
 * Rotates keys.
 *
 * @param threshold The new threshold
 * @param keyList The new list of keys.
 * @param addresses Parallel sorted arrays of addresses.
 * @param signatures Parrell sorted array of signatures.
 * @param nonce The nonce.
 * @param multiSigContractAddress The address of the multisig
 * @param nodeUrl The url of the Tezos node.
 * @param privateKey The private key to sign the transaction with. Only keys starting with edsk are supported.
 * @param attemptAutomatic Attempt to automatically produce bytes.
 */
export const rotateKey = async (
  threshold: number,
  keyList: Array<publicKey>,
  addresses: Array<address>,
  signatures: Array<string>,
  nonce: number,
  multiSigContractAddress: address,
  nodeUrl: url,
  privateKey: string,
  attemptAutomatic: boolean,
): Promise<void> => {
  const keyStore = await Utils.keyStoreFromPrivateKey(privateKey)
  const signer = await Utils.signerFromKeyStore(keyStore)

  Utils.print(`Submitting rotate from: ${keyStore.publicKeyHash} `)
  Utils.print(`Using nonce: ${nonce} `)

  await Utils.revealAccountIfNeeded(nodeUrl, keyStore, signer)

  const counter = await TezosNodeReader.getCounterForAccount(
    nodeUrl,
    keyStore.publicKeyHash,
  )

  const chainId = await getChainId(nodeUrl)
  const keyListMichelson = keyList.reduce((previous, current) => {
    return `${previous} "${current}";`
  }, '')

  let signaturesMap = ''
  for (let i = 0; i < addresses.length; i++) {
    const address = addresses[i]
    const signature = signatures[i]

    signaturesMap += `Elt "${address}" "${signature}"; `
  }

  const param = `Pair { ${signaturesMap} } (Pair "${chainId}" (Pair ${nonce} (Pair ${threshold} {${keyListMichelson}})))`
  Utils.print(`Invoking with param: ${param}`)
  Utils.print('')

  Utils.print(`Use tezos-client to submit the operation manually.`)
  Utils.print(
    `tezos-client -E ${nodeUrl} transfer 0 from ${keyStore.publicKeyHash} to ${multiSigContractAddress} --arg '${param}' --entrypoint 'rotate'`,
  )
  Utils.print('')

  if (attemptAutomatic) {
    Utils.print(`Attempting to inject automatically:`)
    const operation = TezosNodeWriter.constructContractInvocationOperation(
      keyStore.publicKeyHash,
      counter + 1,
      multiSigContractAddress,
      0,
      0,
      Constants.storageLimit,
      Constants.gasLimit,
      'rotate',
      `${param} `,
      TezosParameterFormat.Michelson,
    )

    const operationFeeEstimator = new OperationFeeEstimator(nodeUrl)
    const operationsWithFees = await operationFeeEstimator.estimateAndApplyFees(
      [operation],
    )

    const nodeResult = await TezosNodeWriter.sendOperation(
      nodeUrl,
      operationsWithFees,
      signer,
    )

    const hash = nodeResult.operationGroupID.replace(/"/g, '')
    Utils.print(`Executed with hash: ${hash} `)
  }
}

/**
 * Adds a given operation to the timelock.
 *
 * @param operation The operation
 * @param addresses Parallel sorted arrays of addresses.
 * @param signatures Parrell sorted array of signatures.
 * @param nonce The nonce.
 * @param multiSigContractAddress The address of the multisig
 * @param nodeUrl The url of the Tezos node.
 * @param privateKey The private key to sign the transaction with. Only keys starting with edsk are supported.
 * @param attemptAutomatic Attempt to automatically produce bytes.
 */
export const submit = async (
  operation: OperationData,
  addresses: Array<address>,
  signatures: Array<string>,
  nonce: number | undefined,
  multiSigContractAddress: address,
  nodeUrl: url,
  privateKey: string,
  attemptAutomatic: boolean,
): Promise<void> => {
  const keyStore = await Utils.keyStoreFromPrivateKey(privateKey)
  const signer = await Utils.signerFromKeyStore(keyStore)

  Utils.print(`Submitting operation from: ${keyStore.publicKeyHash} `)
  Utils.print(`Using nonce: ${nonce} `)

  await Utils.revealAccountIfNeeded(nodeUrl, keyStore, signer)

  const actualNonce =
    nonce ? nonce : (await getNonce(multiSigContractAddress, nodeUrl)) + 1
  Utils.print(`Using nonce: ${actualNonce} `)

  const counter = await TezosNodeReader.getCounterForAccount(
    nodeUrl,
    keyStore.publicKeyHash,
  )

  const chainId = await getChainId(nodeUrl)
  const lambda = compileOperation(operation)

  let signaturesMap = ''
  for (let i = 0; i < addresses.length; i++) {
    const address = addresses[i]
    const signature = signatures[i]

    signaturesMap += `Elt "${address}" "${signature}"; `
  }

  const param = `Pair { ${signaturesMap} } (Pair "${chainId}" (Pair ${actualNonce} ${lambda}))`
  Utils.print(`Invoking with param: ${param}`)
  Utils.print('')

  Utils.print(`Use tezos-client to submit the operation manually.`)
  Utils.print(
    `tezos-client -E ${nodeUrl} transfer 0 from ${keyStore.publicKeyHash} to ${multiSigContractAddress} --arg '${param}' --entrypoint 'submit'`,
  )
  Utils.print('')

  if (attemptAutomatic) {
    Utils.print(`Attempting to inject automatically:`)
    const operation = TezosNodeWriter.constructContractInvocationOperation(
      keyStore.publicKeyHash,
      counter + 1,
      multiSigContractAddress,
      0,
      0,
      Constants.storageLimit,
      Constants.gasLimit,
      'submit',
      `${param} `,
      TezosParameterFormat.Michelson,
    )

    const operationFeeEstimator = new OperationFeeEstimator(nodeUrl)
    const operationsWithFees = await operationFeeEstimator.estimateAndApplyFees(
      [operation],
    )

    const nodeResult = await TezosNodeWriter.sendOperation(
      nodeUrl,
      operationsWithFees,
      signer,
    )

    const hash = nodeResult.operationGroupID.replace(/"/g, '')
    Utils.print(`Executed with hash: ${hash} `)
  }
}

/**
 * Executes a given operation that is in the timelock.
 *
 * @param operationId The nonce of the operation to execute.
 * @param multiSigContractAddress The address of the multisig
 * @param nodeUrl The url of the Tezos node.
 * @param privateKey The private key to sign the transaction with. Only keys starting with edsk are supported.
 */
export const execute = async (
  operationId: number,
  multiSigContractAddress: address,
  nodeUrl: url,
  privateKey: string,
): Promise<void> => {
  const keyStore = await Utils.keyStoreFromPrivateKey(privateKey)
  const signer = await Utils.signerFromKeyStore(keyStore)

  Utils.print(`Sending execute from: ${keyStore.publicKeyHash} `)
  Utils.print(`Using nonce: ${operationId} `)

  await Utils.revealAccountIfNeeded(nodeUrl, keyStore, signer)

  const counter = await TezosNodeReader.getCounterForAccount(
    nodeUrl,
    keyStore.publicKeyHash,
  )

  const operation = TezosNodeWriter.constructContractInvocationOperation(
    keyStore.publicKeyHash,
    counter + 1,
    multiSigContractAddress,
    0,
    0,
    Constants.storageLimit,
    Constants.gasLimit,
    'execute',
    `${operationId} `,
    TezosParameterFormat.Michelson,
  )

  const operationFeeEstimator = new OperationFeeEstimator(nodeUrl)
  const operationsWithFees = await operationFeeEstimator.estimateAndApplyFees([
    operation,
  ])

  const nodeResult = await TezosNodeWriter.sendOperation(
    nodeUrl,
    operationsWithFees,
    signer,
  )

  const hash = nodeResult.operationGroupID.replace(/"/g, '')
  Utils.print(`Executed with hash: ${hash} `)
}
