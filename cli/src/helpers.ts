import { ContractOriginationResult, OperationData, chainId, url, address, publicKey } from './types'
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
 * Retrieve the nonce for a multisig contract.
 * 
 * @param multiSigContractAddress The address of the multisig contract.
 * @param nodeUrl The URL of the Tezos node to use.
 * @returns The current nonce
 */
export const getNonce = async (multiSigContractAddress: address, nodeUrl: url): Promise<number> => {
  const tezos = new TezosToolkit(nodeUrl)

  const multiSigContract = await tezos.contract.at(multiSigContractAddress)
  const multiSigStorage: any = await multiSigContract.storage()

  const nonce: BigNumber = await multiSigStorage.interestIndex
  return nonce.toNumber()
}

/**
 * Retrieve the chain ID the given node is running on.
 * @param nodeUrl The URL of the Tezos node to use.
 * @returns The current nonce
 */
export const getChainId = async (nodeUrl: url): Promise<chainId> => {
  const tezos = new TezosToolkit(nodeUrl)

  return tezos.rpc.getChainId()
}

/**
 * Compile a command to a michelson lambda.
 *
 * This relies on having SmartPy installed and likely only works on OSX. Sorry!
 *
 * @param command The command.
 * @returns The compiled michelson.
 */
export const compileCommand = async (command: OperationData): Promise<string> => {
  // A simple program that executes the lambda.
  const program = `
import smartpy as sp

def command(self):
  transfer_operation = sp.transfer_operation(
    ${command.argSmartPy},
    sp.mutez(${command.amountMutez}), 
    sp.contract(None, sp.address("${command.address}")
  ).open_some())
  
  operation_list = [ transfer_operation ]
  
  sp.result(operation_list)
`

  // Make a directory and write the program to it.
  const dirName = `./.msig-cli-tmp`
  const fileName = `${dirName}/command.py`
  fs.mkdirSync(dirName)
  fs.writeFileSync(fileName, program);

  // Compile the command.
  childProcess.execSync(`~/smartpy-cli/SmartPy.sh compile-expression "${fileName}" "command" ${dirName}`)

  // Read the command back into memory.
  const outputFile = `${dirName}/command_michelson.tz`
  const compiled = fs.readFileSync(outputFile).toString()

  // Cleanup files
  // TODO(keefertaylor): enable cleanup
  // fs.rmdirSync(dirName, { recursive: true })

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
    console.log(`Using storage: ${storage} `)
    console.log(`Using counter: ${counter} `)

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
  } catch (e) {
    console.log('Caught exception, retrying...')
    console.log(e.message)
    await Utils.sleep(30)

    return deployContract(
      nodeUrl,
      contractSource,
      storage,
      keystore,
      counter,
    )
  }
}

