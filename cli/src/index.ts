#!/usr/bin/env node

/** Commander uses `any` objects to type commands. Disable some linting rules for this. */
/* eslint-disable @typescript-eslint/no-unsafe-assignment */
/* eslint-disable @typescript-eslint/no-unsafe-call */
/* eslint-disable @typescript-eslint/no-unsafe-member-access */

import fetch from 'node-fetch'
import { getLogger, LogLevelDesc } from 'loglevel'
import { registerFetch, registerLogger } from 'conseiljs'
import {
  bytesToSubmit,
  deployMultisig,
  submit,
  keyRotationbytesToSubmit,
  rotateKey,
  cancel,
  cancelbytesToSubmit,
  execute,
} from './commands'
import * as commander from 'commander'
import { OperationData } from './types'

const version = '0.0.8'

const program = new commander.Command()
program.version(version)

// Global options
program.option('--debug', 'Print verbose output.')

// Deploy multisig command.
program
  .command('deploy')
  .description('Deploys a multisig contract')
  .requiredOption(
    '--threshold <number>',
    'Number of singatures required to execute the multisig',
  )
  .requiredOption(
    '--public-keys <string>',
    'Comma seperated list of public keys. Ex. edpk123,edpk456,edpk789',
  )
  .requiredOption(
    '--timelock-seconds <number>',
    'Number of seconds the timelock lasts for',
  )
  .requiredOption(
    '--private-key <string>',
    'Private key of the deployer, prefixed with edsk.',
  )
  .requiredOption('--node-url <string>', 'The URL of the node to use')
  .action(async function (commandObject) {
    const conseilLogLevel = program.debug ? 'debug' : 'error'
    initConseil(conseilLogLevel)

    const publicKeys = commandObject.publicKeys.split(',').sort()

    await deployMultisig(
      commandObject.timelockSeconds,
      commandObject.threshold,
      publicKeys,
      commandObject.nodeUrl,
      commandObject.privateKey,
    )
  })

// Obtain bytes to sign.
program
  .command('bytes-submit')
  .description('Get bytes to sign to submit an operation')
  .requiredOption('--target-contract <string>', 'The contract to invoke')
  .requiredOption(
    '--target-entrypoint <string>',
    'The entrypoing in the target contract to invoke',
  )
  .requiredOption(
    '--target-arg <string>',
    'The argument, in SmartPy notation (sorry!). Ex: (sp.nat(1), (sp.address("kt1..."), sp.string("arg")))',
  )
  .requiredOption('--node-url <string>', 'The URL of the node to use')
  .requiredOption(
    '--multisig-address <string>',
    'The address of the multisig contract.',
  )
  .option(
    '--operation-id <number>',
    'The operation ID to use, or undefined. If undefined, the operation ID will be fetched automatically.',
  )
  .option(
    '--auto',
    '[Experimental: Likely to fail] Attempt to automatically formulate bytes.',
  )
  .action(async function (commandObject) {
    const conseilLogLevel = program.debug ? 'debug' : 'error'
    initConseil(conseilLogLevel)

    const operation: OperationData = {
      address: commandObject.targetContract,
      argSmartPy: commandObject.targetArg,
      entrypoint: commandObject.targetEntrypoint,
      amountMutez: 0,
    }

    await bytesToSubmit(
      operation,
      commandObject.nodeUrl,
      commandObject.operationId,
      commandObject.multisigAddress,
      commandObject.auto,
    )
  })

// Obtain bytes to sign for a key rotation.
program
  .command('bytes-rotate')
  .description('Get bytes to sign for a key rotation')
  .requiredOption('--threshold <number>', 'The new threshold')
  .requiredOption(
    '--signers <string>',
    'A comma separated list of signer\'s public keys. Ex: "edpk123,edpk456,edpk789"',
  )
  .requiredOption('--node-url <string>', 'The URL of the node to use')
  .requiredOption(
    '--multisig-address <string>',
    'The address of the multisig contract.',
  )
  .option(
    '--operation-id <number>',
    'The operation ID to use, or undefined. If undefined, the operation ID will be fetched automatically.',
  )
  .option(
    '--auto',
    '[Experimental: Likely to fail] Attempt to automatically formulate bytes.',
  )
  .action(async function (commandObject) {
    const conseilLogLevel = program.debug ? 'debug' : 'error'
    initConseil(conseilLogLevel)

    const keys = commandObject.signers.split(',').sort()

    await keyRotationbytesToSubmit(
      commandObject.threshold,
      keys,
      commandObject.nodeUrl,
      commandObject.operationId,
      commandObject.multisigAddress,
      commandObject.auto,
    )
  })

// Obtain bytes to sign for a cancellation.
program
  .command('bytes-cancel')
  .description('Get bytes to sign for a cancel')
  .requiredOption('--operation-id <number>', 'The operation id to cancel')
  .requiredOption('--node-url <string>', 'The URL of the node to use')
  .requiredOption(
    '--multisig-address <string>',
    'The address of the multisig contract.',
  )
  .option(
    '--operation-id <number>',
    'The operation ID to use, or undefined. If undefined, the operation ID will be fetched automatically.',
  )
  .option(
    '--auto',
    '[Experimental: Likely to fail] Attempt to automatically formulate bytes.',
  )
  .action(async function (commandObject) {
    const conseilLogLevel = program.debug ? 'debug' : 'error'
    initConseil(conseilLogLevel)

    await cancelbytesToSubmit(
      commandObject.operationId,
      commandObject.nodeUrl,
      commandObject.operationId,
      commandObject.multisigAddress,
      commandObject.auto,
    )
  })

// Cancel
program
  .command('cancel')
  .description('Rotate keys')
  .requiredOption('--operation-id <number>', 'The operation id to cancel')
  .requiredOption('--node-url <string>', 'The URL of the node to use')
  .requiredOption(
    '--multisig-address <string>',
    'The address of the multisig contract.',
  )
  .requiredOption(
    '--private-key <string>',
    'Private key of the submitter, prefixed with edsk.',
  )
  .requiredOption(
    '--signatures <string>',
    "Pairs of public key hashes and signatures, separated by colors. Ex: 'tz1abc:edsig123,tz2def:edsig456'",
  )
  .option(
    '--operation-id <number>',
    'The operation ID to use, or undefined. If undefined, the operation ID will be fetched automatically.',
  )
  .option(
    '--auto',
    '[Experimental: Likely to fail] Attempt to automatically inject the operation',
  )
  .action(async function (commandObject) {
    const conseilLogLevel = program.debug ? 'debug' : 'error'
    initConseil(conseilLogLevel)

    // Create parallel sorted arrays of addresses and signatures, in alphabetical order.
    const adddressesAndSignatures: Array<string> = commandObject.signatures
      .split(',')
      .sort()
    const addresses = adddressesAndSignatures.map(
      (value) => value.split(':')[0],
    )
    const signatures = adddressesAndSignatures.map(
      (value) => value.split(':')[1],
    )

    await cancel(
      commandObject.operationId,
      addresses,
      signatures,
      commandObject.operationId,
      commandObject.multisigAddress,
      commandObject.nodeUrl,
      commandObject.privateKey,
      commandObject.auto,
    )
  })

// Rotate keys
program
  .command('rotate')
  .description('Rotate keys')
  .requiredOption('--threshold <number>', 'The new threshold')
  .requiredOption(
    '--signers <string>',
    'A comma separated list of signer\'s public keys. Ex: "edpk123,edpk456,edpk789"',
  )
  .requiredOption('--node-url <string>', 'The URL of the node to use')
  .requiredOption(
    '--multisig-address <string>',
    'The address of the multisig contract.',
  )
  .requiredOption(
    '--private-key <string>',
    'Private key of the submitter, prefixed with edsk.',
  )
  .requiredOption(
    '--signatures <string>',
    "Pairs of public key hashes and signatures, separated by colors. Ex: 'tz1abc:edsig123,tz2def:edsig456'",
  )
  .option(
    '--operation-id <number>',
    'The operation ID to use, or undefined. If undefined, the operation ID will be fetched automatically.',
  )
  .option(
    '--auto',
    '[Experimental: Likely to fail] Attempt to automatically inject the operation',
  )
  .action(async function (commandObject) {
    const conseilLogLevel = program.debug ? 'debug' : 'error'
    initConseil(conseilLogLevel)

    // Sort new keys.
    const keys = commandObject.signers.split(',').sort()

    // Create parallel sorted arrays of addresses and signatures, in alphabetical order.
    const adddressesAndSignatures: Array<string> = commandObject.signatures
      .split(',')
      .sort()
    const addresses = adddressesAndSignatures.map(
      (value) => value.split(':')[0],
    )
    const signatures = adddressesAndSignatures.map(
      (value) => value.split(':')[1],
    )

    await rotateKey(
      commandObject.threshold,
      keys,
      addresses,
      signatures,
      commandObject.operationId,
      commandObject.multisigAddress,
      commandObject.nodeUrl,
      commandObject.privateKey,
      commandObject.auto,
    )
  })

// Submit bytes
program
  .command('submit')
  .description('Submit an operation')
  .requiredOption('--target-contract <string>', 'The contract to invoke')
  .requiredOption(
    '--target-entrypoint <string>',
    'The entrypoing in the target contract to invoke',
  )
  .requiredOption(
    '--target-arg <string>',
    'The argument, in SmartPy notation (sorry!). Ex: (sp.nat(1), (sp.address("kt1..."), sp.string("arg")))',
  )
  .requiredOption('--node-url <string>', 'The URL of the node to use')
  .requiredOption(
    '--multisig-address <string>',
    'The address of the multisig contract.',
  )
  .requiredOption(
    '--private-key <string>',
    'Private key of the submitter, prefixed with edsk.',
  )
  .requiredOption(
    '--signatures <string>',
    "Pairs of public key hashes and signatures, separated by colors. Ex: 'tz1abc:edsig123,tz2def:edsig456'",
  )
  .option('--operation-id <number>', 'The operation ID to use, or undefined.')
  .option(
    '--auto',
    '[Experimental: Likely to fail] Attempt to automatically inject the operation',
  )
  .action(async function (commandObject) {
    const conseilLogLevel = program.debug ? 'debug' : 'error'
    initConseil(conseilLogLevel)

    const operation: OperationData = {
      address: commandObject.targetContract,
      argSmartPy: commandObject.targetArg,
      entrypoint: commandObject.targetEntrypoint,
      amountMutez: 0,
    }

    // Create parallel sorted arrays of addresses and signatures, in alphabetical order.
    const adddressesAndSignatures: Array<string> = commandObject.signatures
      .split(',')
      .sort()
    const addresses = adddressesAndSignatures.map(
      (value) => value.split(':')[0],
    )
    const signatures = adddressesAndSignatures.map(
      (value) => value.split(':')[1],
    )

    await submit(
      operation,
      addresses,
      signatures,
      commandObject.operationId,
      commandObject.multisigAddress,
      commandObject.nodeUrl,
      commandObject.privateKey,
      commandObject.auto,
    )
  })

// Execute an operation in the timelock
program
  .command('execute')
  .description('Executes an operation in the timelock')
  .requiredOption('--operation-id <number>', 'The operation ID to execute')
  .requiredOption('--node-url <string>', 'The URL of the node to use')
  .requiredOption(
    '--multisig-address <string>',
    'The address of the multisig contract.',
  )
  .requiredOption(
    '--private-key <string>',
    'Private key of the submitter, prefixed with edsk.',
  )
  .action(async function (commandObject) {
    const conseilLogLevel = program.debug ? 'debug' : 'error'
    initConseil(conseilLogLevel)

    await execute(
      commandObject.operationId,
      commandObject.multisigAddress,
      commandObject.nodeUrl,
      commandObject.privateKey,
    )
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
