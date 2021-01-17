#!/usr/bin/env node

/** Commander uses `any` objects to type commands. Disable some linting rules for this. */
/* eslint-disable @typescript-eslint/no-unsafe-assignment */
/* eslint-disable @typescript-eslint/no-unsafe-call */
/* eslint-disable @typescript-eslint/no-unsafe-member-access */

import fetch from 'node-fetch'
import { getLogger, LogLevelDesc } from 'loglevel'
import { registerFetch, registerLogger } from 'conseiljs'
import { bytesToSign, deployMultisig, submit } from './commands'
import * as commander from 'commander'
import { OperationData } from './types'
import { command } from 'commander'

const version = '0.0.1'

const program = new commander.Command()
program.version(version)

// Global options
program.option('--debug', 'Print verbose output.')

// Deploy multisig command.
program
  .command('deploy')
  .description('Deploys a multisig contract')
  .requiredOption('--threshold <number>', "Number of singatures required to execute the multisig")
  .requiredOption('--public-keys <string>', "Comma seperated list of public keys. Ex. edpk123,edpk456,edpk789")
  .requiredOption('--timelock-seconds <number>', "Number of seconds the timelock lasts for")
  .requiredOption('--deployer-private-key <string>', "Private key of the deployer, prefixed with edsk.")
  .requiredOption('--node-url <string>', "The URL of the node to use")
  .action(function (commandObject) {
    const conseilLogLevel = program.debug ? 'debug' : 'error'
    initConseil(conseilLogLevel)

    // TODO(keefertaylor): Delete and trawl for other console.logs
    console.log("VAL: " + commandObject)
    console.log("VAL: " + commandObject.publicKeys)

    const publicKeys = commandObject.publicKeys.split(',').sort()

    deployMultisig(
      commandObject.timelockSeconds,
      commandObject.threshold,
      publicKeys,
      commandObject.nodeUrl,
      commandObject.deployerPrivateKey
    )
  })

// Obtain bytes to sign.
program
  .command('bytes')
  .description('Get bytes to sign for an operation')
  .requiredOption('--target-contract <string>', 'The contract to invoke')
  .requiredOption('--target-entrypoint <string>', 'The entrypoing in the target contract to invoke')
  .requiredOption('--target-arg <string>', 'The argument, in SmartPy notation (sorry!). Ex: (sp.nat(1), (sp.address("kt1..."), sp.string("arg")))')
  .requiredOption('--node-url <string>', "The URL of the node to use")
  .requiredOption('--multisig-address <string>', "The address of the multisig contract.")
  .option('--nonce <number>', 'The nonce to use, or undefined.')
  .action(function (commandObject) {
    const conseilLogLevel = program.debug ? 'debug' : 'error'
    initConseil(conseilLogLevel)

    const operation: OperationData = {
      address: commandObject.targetContract,
      argSmartPy: commandObject.targetArg,
      entrypoint: commandObject.targetEntrypoint,
      amountMutez: 0
    }

    bytesToSign(operation, commandObject.nodeUrl, commandObject.nonce, commandObject.multisigAddress)
  })

// Submit bytes
program
  .command('submit')
  .description('Submit an operation')
  .requiredOption('--target-contract <string>', 'The contract to invoke')
  .requiredOption('--target-entrypoint <string>', 'The entrypoing in the target contract to invoke')
  .requiredOption('--target-arg <string>', 'The argument, in SmartPy notation (sorry!). Ex: (sp.nat(1), (sp.address("kt1..."), sp.string("arg")))')
  .requiredOption('--node-url <string>', "The URL of the node to use")
  .requiredOption('--multisig-address <string>', "The address of the multisig contract.")
  .requiredOption('--nonce <number>', 'The nonce to use, or undefined.')
  .requiredOption('--private-key <string>', "Private key of the submitter, prefixed with edsk.")
  .requiredOption('--signatures <string>', "Pairs of public key hashes and signatures, separated by colors. Ex: 'tz1abc:edsig123,tz2def:edsig456'")
  .action(function (commandObject) {
    const conseilLogLevel = program.debug ? 'debug' : 'error'
    initConseil(conseilLogLevel)

    const operation: OperationData = {
      address: commandObject.targetContract,
      argSmartPy: commandObject.targetArg,
      entrypoint: commandObject.targetEntrypoint,
      amountMutez: 0
    }

    // Create parallel sorted arrays of addresses and signatures, in alphabetical order.
    const adddressesAndSignatures: Array<string> = commandObject.signatures.split(',').sort()
    const addresses = adddressesAndSignatures.map((value) => value.split(':')[0])
    const signatures = adddressesAndSignatures.map((value) => value.split(':')[1])

    submit(operation, addresses, signatures, commandObject.nonce, commandObject.multisigAddress, commandObject.nodeUrl, commandObject.privateKey)
  })

/**
 * Initialize Conseil.
 *
 * @param conseilLogLevel The log level to use for Conseil.
 */
export function initConseil(conseilLogLevel: LogLevelDesc = 'error'): void {
  const logger = getLogger('conseiljs')
  logger.setLevel(conseilLogLevel, false)

  registerLogger(logger)
  registerFetch(fetch)
}

// Parse input arguments.
program.parse()