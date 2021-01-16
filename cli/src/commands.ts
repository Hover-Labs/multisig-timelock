import Utils from './utils'
import { OperationData, url, address, publicKey } from './types'
import { getChainId, getNonce, compileCommand, loadContract, deployContract } from './helpers'
import { TezosParameterFormat, TezosNodeReader, TezosNodeWriter } from 'conseiljs'
import OperationFeeEstimator from './operation-fee-estimator'
import Constants from './constants'

/** Constants */
const CONTRACT_SOURCE = __dirname + "/../../smart_contracts/msig-timelock.tz"

/** Command functions */

/**
 * Retrieve bytes to sign.
 * 
 * @param operation The operation to encode.
 * @param nodeUrl The URL of the tezos node.
 * @param nonce The nonce to use. If undefined, a nonce will be fetched from the multisig contract.
 * @param multiSigContractAddress The address of the multisig contract.
 */
export const bytesToSign = async (operation: OperationData, nodeUrl: url, nonce: number | undefined, multiSigContractAddress: address) => {
  const chainId = await getChainId(nodeUrl)
  const actualNonce = nonce ?? await getNonce(multiSigContractAddress, nodeUrl)

  const lambda = await compileCommand(operation)
  const michelson = `Pair "${chainId}" (Pair ${actualNonce} ${lambda})`
  Utils.print(`Encoding Michelson: ${michelson}`)


  const cli = `tezos-client hash data 'Pair "${chainId}" (Pair ${nonce} ${lambda})' of type 'pair (chain_id) (pair (nat) (lambda unit (list operation)))'`
  Utils.print("Get bytes with: ")
  Utils.print(cli)

  // TODO(keefertaylor): Enable, someday.
  // const hex = TezosMessageUtils.writePackedData(michelson, "pair (chain_id) (pair (nat) (lambda unit (list operation)))", TezosParameterFormat.Michelson)
  // Utils.print(`Bytes to sign: ${hex}`)
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
export const deployMultisig = async (timelockSeconds: number, threshold: number, publicKeys: Array<publicKey>, nodeUrl: url, privateKey: string) => {
  const source = loadContract(CONTRACT_SOURCE)

  // Sort public keys alphabetically (required by Tezos) and create a michelson list.
  const sortedPublicKeys = publicKeys.sort()
  const michelsonPublicKeyList = sortedPublicKeys.reduce((previous: string, current: publicKey) => {
    return `${previous} "${current}"`
  }, "")

  // Formulate initial storage. 
  // Note: 0 literal is a nonce.
  const storage = `(Pair (Pair 0 {"edpkuX2icxnt5krjTJAmNv8uNJNiQtFmDy9Hzj6SF1f6e3NjT4LXKB"}) (Pair 1 (Pair {} 3600)))` //`(Pair (Pair 0 {${michelsonPublicKeyList}}) (Pair ${threshold} (Pair {} ${timelockSeconds})))`

  const keyStore = await Utils.keyStoreFromPrivateKey(privateKey)
  const signer = await Utils.signerFromKeyStore(keyStore)

  Utils.print(`Deploying from: ${keyStore.publicKeyHash}`)
  Utils.print(`Storage: ${storage}`)

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
  Utils.print(`Address: ${deployResult.contractAddress}`)
  Utils.print(`Operation Hash: ${deployResult.operationHash}`)
}


/**
 * Adds a given command to the timelock.
 * 
 * @param operation The operation
 * @param addresses Parallel sorted arrays of addresses.
 * @param signatures Parrell sorted array of signatures.
 * @param nonce The nonce. 
 * @param multiSigContractAddress The address of the multisig
 * @param nodeUrl The url of the Tezos node. 
 * @param privateKey The private key to sign the transaction with. Only keys starting with edsk are supported.
 */
// TODO(keefertaylor): Standardize operation and command.
export const submit = async (
  command: OperationData,
  addresses: Array<address>,
  signatures: Array<string>,
  nonce: number,
  multiSigContractAddress: address,
  nodeUrl: url,
  privateKey: string
) => {
  const keyStore = await Utils.keyStoreFromPrivateKey(privateKey)
  const signer = await Utils.signerFromKeyStore(keyStore)

  Utils.print(`Submitting command from command from: ${keyStore.publicKeyHash}`)
  Utils.print(`Using nonce: ${nonce}`)

  await Utils.revealAccountIfNeeded(nodeUrl, keyStore, signer)

  const counter = await TezosNodeReader.getCounterForAccount(
    nodeUrl,
    keyStore.publicKeyHash,
  )

  const chainId = await getChainId(nodeUrl)
  const lambda = await compileCommand(command)

  let signaturesMap = ""
  for (let i = 0; i < addresses.length; i++) {
    const address = addresses[i]
    const signature = signatures[i]

    signaturesMap += `Elt "${address}" "${signature}"; `
  }

  const param = `Pair ${signaturesMap} (Pair "${chainId}" (Pair ${nonce} ${lambda}))`


  const operation = TezosNodeWriter.constructContractInvocationOperation(
    keyStore.publicKeyHash,
    counter + 1,
    multiSigContractAddress,
    0,
    0,
    Constants.storageLimit,
    Constants.gasLimit,
    'execute',
    `${nonce}`,
    TezosParameterFormat.Michelson,
  )

  const operationFeeEstimator = new OperationFeeEstimator(
    nodeUrl
  )
  const operationsWithFees = await operationFeeEstimator.estimateAndApplyFees(
    [operation],
  )

  const nodeResult = await TezosNodeWriter.sendOperation(
    nodeUrl,
    operationsWithFees,
    signer,
  )

  const hash = nodeResult.operationGroupID.replace(/"/g, '')
  Utils.print(`Executed with hash: ${hash}`)
}

/**
 * Executes a given command that is in the timelock.
 * 
 * @param nonce The nonce of the command to execute. 
 * @param multiSigContractAddress The address of the multisig
 * @param nodeUrl The url of the Tezos node. 
 * @param privateKey The private key to sign the transaction with. Only keys starting with edsk are supported.
 */
export const executeCommand = async (nonce: number, multiSigContractAddress: address, nodeUrl: url, privateKey: string) => {
  const keyStore = await Utils.keyStoreFromPrivateKey(privateKey)
  const signer = await Utils.signerFromKeyStore(keyStore)

  Utils.print(`Sending execute command from: ${keyStore.publicKeyHash}`)
  Utils.print(`Using nonce: ${nonce}`)

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
    `${nonce}`,
    TezosParameterFormat.Michelson,
  )

  const operationFeeEstimator = new OperationFeeEstimator(
    nodeUrl
  )
  const operationsWithFees = await operationFeeEstimator.estimateAndApplyFees(
    [operation],
  )

  const nodeResult = await TezosNodeWriter.sendOperation(
    nodeUrl,
    operationsWithFees,
    signer,
  )

  const hash = nodeResult.operationGroupID.replace(/"/g, '')
  Utils.print(`Executed with hash: ${hash}`)
}