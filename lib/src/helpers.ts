import {
  ContractOriginationResult,
  OperationData,
  chainId,
  url,
  address,
} from './types'
import { TezosToolkit } from '@taquito/taquito'
import BigNumber from 'bignumber.js'
import fs = require('fs')
import childProcess = require('child_process')
import { KeyStore, TezosParameterFormat, TezosNodeWriter } from 'conseiljs'
import Utils from './utils'
import OperationFeeEstimator from './operation-fee-estimator'
import Constants from './constants'

/** Common Functions */

/**
 * Retrieve the current operation ID for a multisig contract.
 *
 * @param multiSigContractAddress The address of the multisig contract.
 * @param nodeUrl The URL of the Tezos node to use.
 * @returns The current operation ID
 */
export const getOperationId = async (
  multiSigContractAddress: address,
  nodeUrl: url,
): Promise<number> => {
  const tezos = new TezosToolkit(nodeUrl)

  const multiSigContract = await tezos.contract.at(multiSigContractAddress)
  const multiSigStorage: any = await multiSigContract.storage()
  const operationId: BigNumber = await multiSigStorage.operationId

  return operationId.toNumber()
}

/**
 * Retrieve the chain ID the given node is running on.
 *
 * @param nodeUrl The URL of the Tezos node to use.
 * @returns The chain ID.
 */
export const getChainId = async (nodeUrl: url): Promise<chainId> => {
  const tezos = new TezosToolkit(nodeUrl)

  return tezos.rpc.getChainId()
}

/**
 * Compile an operation to a michelson lambda.
 *
 * This relies on having SmartPy installed and likely only works on OSX. Sorry!
 *
 * @param operation The operation.
 * @param smartpyPath The location to find the SmartPy compiler.
 * @returns The compiled michelson.
 */
export const compileOperation = (
  operation: OperationData,
  smartpyPath: string,
): string => {
  // If a type was given, inline it into the program. Otherwise no-op
  const argType =
    operation.argTypeSmartPy === undefined ? 'None' : operation.argTypeSmartPy

  // A simple program that executes the lambda.
  const program = `
import smartpy as sp

def operation(self):
  arg = ${operation.argSmartPy}

  transfer_operation = sp.transfer_operation(
    arg,
    sp.mutez(${operation.amountMutez}), 
    sp.contract(${argType}, sp.address("${operation.address}"), "${operation.entrypoint}"
  ).open_some())
  
  operation_list = [ transfer_operation ]
  
  sp.result(operation_list)

sp.add_expression_compilation_target("operation", operation)
`

  // Make a directory and write the program to it.
  const dirName = `./.msig-cli-tmp`
  const fileName = `${dirName}/operation.py`
  fs.rmdirSync(dirName, { recursive: true })
  fs.mkdirSync(dirName)
  fs.writeFileSync(fileName, program)

  // Compile the operation.
  childProcess.execSync(`${smartpyPath} compile ${fileName} ${dirName}`)

  // Read the operation back into memory.
  const outputFile = `${dirName}/operation/step_000_expression.tz`
  const compiled = fs.readFileSync(outputFile).toString()

  // Cleanup files
  fs.rmdirSync(dirName, { recursive: true })

  return compiled
}

/**
 * Read a smart contract from a file.
 *
 * @param filename The file to read.
 * @returns The smart contract source.
 */
// TODO(keefertaylor): Copied from Kolibri's deploy scripts. Dedupe.
export function loadContract(filename: string): string {
  const contractFile = filename
  const contract = fs.readFileSync(contractFile).toString()
  return contract
}

/**
 * Deploy a contract.
 *
 * @param nodeUrl The URL of the Tezos node.
 * @param contractSource Source code of the contract.
 * @param storage Initial storage for the contract.
 * @param keystore Keystore to deploy with.
 * @param counter The counter for the deploy.
 * @returns The result of deploying the contract.
 */
// TODO(keefertaylor): Copied from Kolibri's deploy scripts. Dedupe.
export async function deployContract(
  nodeUrl: url,
  contractSource: string,
  storage: string,
  keystore: KeyStore,
  counter: number,
): Promise<ContractOriginationResult> {
  try {
    await Utils.revealAccountIfNeeded(
      nodeUrl,
      keystore,
      await Utils.signerFromKeyStore(keystore),
    )

    const signer = await Utils.signerFromKeyStore(keystore)

    const operation = TezosNodeWriter.constructContractOriginationOperation(
      keystore,
      0,
      undefined,
      0,
      Constants.storageLimit,
      Constants.gasLimit,
      contractSource,
      storage,
      TezosParameterFormat.Michelson,
      counter,
    )

    const operationFeeEstimator = new OperationFeeEstimator(nodeUrl)
    const operationnWithFees = await operationFeeEstimator.estimateAndApplyFees(
      [operation],
    )

    const nodeResult = await TezosNodeWriter.sendOperation(
      nodeUrl,
      operationnWithFees,
      signer,
    )

    const operationHash = nodeResult.operationGroupID
      .replace(/"/g, '')
      .replace(/\n/, '')
    const contractAddress = Utils.calculateContractAddress(operationHash, 0)

    // Seems like sometimes Node's mempools run a little slow.
    await Utils.sleep(30)

    return {
      operationHash,
      contractAddress,
    }
  } catch (e: any) {
    Utils.print('Caught exception, retrying...')
    Utils.print(e.message)
    await Utils.sleep(30)

    return deployContract(nodeUrl, contractSource, storage, keystore, counter)
  }
}
