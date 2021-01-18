#!/usr/bin/env node

/** Commander uses `any` objects to type commands. Disable some linting rules for this. */
/* eslint-disable @typescript-eslint/no-unsafe-assignment */
/* eslint-disable @typescript-eslint/no-unsafe-call */
/* eslint-disable @typescript-eslint/no-unsafe-member-access */

// TODO(keefertaylor): Support and test executing a command.

import fetch from 'node-fetch'
import { getLogger, LogLevelDesc } from 'loglevel'
import { registerFetch, registerLogger } from 'conseiljs'
import { bytesToSign, deployMultisig, submit, keyRotationBytesToSign, rotateKey, cancel, cancelBytesToSign, executeCommand } from './commands'
import * as commander from 'commander'
import { OperationData } from './types'
import { command } from 'commander'

const version = '0.0.2'

const program = new commander.Command()
program.version(version)

// Global options
program.option('--debug', 'Print verbose output.')

// Deploy multisig command.
// TODO(keefertaylor): s/deployer-private-key/private-key
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
// TODO(keefertaylor): Update for key rotation bytes
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


// Obtain bytes to sign for a key rotation.
program
  .command('key-rotation-bytes')
  .description('Get bytes to sign for a key rotation')
  .requiredOption('--threshold <number>', 'The new threshold')
  .requiredOption('--signers <string>', 'A comma separated list of signer\'s public keys. Ex: "edpk123,edpk456,edpk789"')
  .requiredOption('--node-url <string>', "The URL of the node to use")
  .requiredOption('--multisig-address <string>', "The address of the multisig contract.")
  .option('--nonce <number>', 'The nonce to use, or undefined.')
  .action(function (commandObject) {
    const conseilLogLevel = program.debug ? 'debug' : 'error'
    initConseil(conseilLogLevel)

    const keys = commandObject.signers.split(',').sort()

    keyRotationBytesToSign(commandObject.threshold, keys, commandObject.nodeUrl, commandObject.nonce, commandObject.multisigAddress)
  })

// Obtain bytes to sign for a cancellation.
program
  .command('cancel-bytes')
  .description('Get bytes to sign for a key rotation')
  .requiredOption('--operation-id <number>', 'The operation id to cancel')
  .requiredOption('--node-url <string>', "The URL of the node to use")
  .requiredOption('--multisig-address <string>', "The address of the multisig contract.")
  .option('--nonce <number>', 'The nonce to use, or undefined.')
  .action(function (commandObject) {
    const conseilLogLevel = program.debug ? 'debug' : 'error'
    initConseil(conseilLogLevel)

    cancelBytesToSign(commandObject.operationId, commandObject.nodeUrl, commandObject.nonce, commandObject.multisigAddress)
  })

// Cancel
program
  .command('cancel')
  .description('Rotate keys')
  .requiredOption('--operation-id <number>', 'The operation id to cancel')
  .requiredOption('--node-url <string>', "The URL of the node to use")
  .requiredOption('--multisig-address <string>', "The address of the multisig contract.")
  .requiredOption('--nonce <number>', 'The nonce to use, or undefined.')
  .requiredOption('--private-key <string>', "Private key of the submitter, prefixed with edsk.")
  .requiredOption('--signatures <string>', "Pairs of public key hashes and signatures, separated by colors. Ex: 'tz1abc:edsig123,tz2def:edsig456'")
  .action(function (commandObject) {
    const conseilLogLevel = program.debug ? 'debug' : 'error'
    initConseil(conseilLogLevel)

    // Create parallel sorted arrays of addresses and signatures, in alphabetical order.
    const adddressesAndSignatures: Array<string> = commandObject.signatures.split(',').sort()
    const addresses = adddressesAndSignatures.map((value) => value.split(':')[0])
    const signatures = adddressesAndSignatures.map((value) => value.split(':')[1])

    cancel(commandObject.operationId, addresses, signatures, commandObject.nonce, commandObject.multisigAddress, commandObject.nodeUrl, commandObject.privateKey)
  })

// Rotate keys
program
  .command('rotate-keys')
  .description('Rotate keys')
  .requiredOption('--threshold <number>', 'The new threshold')
  .requiredOption('--signers <string>', 'A comma separated list of signer\'s public keys. Ex: "edpk123,edpk456,edpk789"')
  .requiredOption('--node-url <string>', "The URL of the node to use")
  .requiredOption('--multisig-address <string>', "The address of the multisig contract.")
  .requiredOption('--nonce <number>', 'The nonce to use, or undefined.')
  .requiredOption('--private-key <string>', "Private key of the submitter, prefixed with edsk.")
  .requiredOption('--signatures <string>', "Pairs of public key hashes and signatures, separated by colors. Ex: 'tz1abc:edsig123,tz2def:edsig456'")
  .action(function (commandObject) {
    const conseilLogLevel = program.debug ? 'debug' : 'error'
    initConseil(conseilLogLevel)

    // Sort new keys.
    const keys = commandObject.signers.split(',').sort()

    // Create parallel sorted arrays of addresses and signatures, in alphabetical order.
    const adddressesAndSignatures: Array<string> = commandObject.signatures.split(',').sort()
    const addresses = adddressesAndSignatures.map((value) => value.split(':')[0])
    const signatures = adddressesAndSignatures.map((value) => value.split(':')[1])

    rotateKey(commandObject.threshold, keys, addresses, signatures, commandObject.nonce, commandObject.multisigAddress, commandObject.nodeUrl, commandObject.privateKey)
  })

// Submit bytes
// TODO(Keefertaylor): make nonce optional.
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


// Execute a command in the timelock
program
  .command('execute')
  .description('Executes an operation in the timelock')
  .requiredOption('--operation-id <number>', 'The operation ID to execute')
  .requiredOption('--node-url <string>', "The URL of the node to use")
  .requiredOption('--multisig-address <string>', "The address of the multisig contract.")
  .requiredOption('--private-key <string>', "Private key of the submitter, prefixed with edsk.")
  .action(function (commandObject) {
    const conseilLogLevel = program.debug ? 'debug' : 'error'
    initConseil(conseilLogLevel)

    executeCommand(commandObject.operationId, commandObject.multisigAddress, commandObject.nodeUrl, commandObject.privateKey)
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