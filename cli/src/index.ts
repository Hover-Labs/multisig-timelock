#!/usr/bin/env node

/** Commander uses `any` objects to type commands. Disable some linting rules for this. */
/* eslint-disable @typescript-eslint/no-unsafe-assignment */
/* eslint-disable @typescript-eslint/no-unsafe-call */
/* eslint-disable @typescript-eslint/no-unsafe-member-access */

import fetch from 'node-fetch'
import { getLogger, LogLevelDesc } from 'loglevel'
import { registerFetch, registerLogger } from 'conseiljs'
import { deployMultisig } from './commands'
import * as commander from 'commander'

const version = '0.0.1'

const program = new commander.Command()
program.version(version)

// Global options
program.option('--debug', 'Print verbose output.')
program.option('--debug-conseil', 'Prints ConseilJS debug data.')

// Deploy multisig command.
program
  .command('deploy')
  .description('Deploys a multisig contract')
  .requiredOption('--threshold <number>', "Number of singatures required to execute the multisig")
  // TODO(keefertaylor): Use variadic param
  .requiredOption('--public-keys <string>', "Comma seperated list of public keys. Ex. edpk123,edpk456,edpk789")
  .requiredOption('--timelock-seconds <number>', "Number of seconds the timelock lasts for")
  .requiredOption('--deployer-private-key <string>', "Private key of the deployer, prefixed with edsk.")
  .requiredOption('--node-url <string>', "The URL of the node to use")
  .action(function (commandObject) {
    const logLevel = program.debug ? "debug" : "info"
    const conseilLogLevel = program.debugConseil ? 'debug' : 'error'
    initConseil(conseilLogLevel)

    console.log("VAL: " + commandObject)
    console.log("VAL: " + commandObject.threshold)

    const publicKeys = commandObject.publicKeys.split(',')

    deployMultisig(
      commandObject.timelockSeconds,
      commandObject.threshold,
      publicKeys,
      commandObject.nodeUrl,
      commandObject.deployerPrivateKey
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