import {
  KeyStore,
} from 'conseiljs'
import { KeyStoreUtils } from 'conseiljs-softsigner'
import { Utils } from '@hover-labs/tezos-multisig-lib'

// Following libraries do not include .d.ts files.
/* eslint-disable @typescript-eslint/no-var-requires */
const base58Check = require('bs58check')
const sodium = require('libsodium-wrappers')
/* eslint-enable @typescript-eslint/no-var-requires */

/**
* Create a Conseil `Keystore` from the given private key.
*
* @param privateKey A base58check encoded private key, beginning with 'edsk'.
* @returns A `Keystore` representing the private key.
*/
export const keyStoreFromPrivateKey = async (privateKey: string): Promise<KeyStore> => {
  if (!privateKey.startsWith('edsk')) {
    throw new Error('Only edsk keys are supported')
  }

  // Make sure use did not unwittingly provide a seed.
  if (privateKey.length === 54) {
    // Decode and slice the `edsk` prefix.
    await sodium.ready
    const decodedBytes = base58Check.decode(privateKey).slice(4)
    const keyPair = sodium.crypto_sign_seed_keypair(decodedBytes)
    const derivedPrivateKeyBytes = Utils.mergeBytes(
      new Uint8Array([43, 246, 78, 7]),
      keyPair.privateKey,
    )
    const derivedPrivateKey = base58Check.encode(derivedPrivateKeyBytes)

    return await KeyStoreUtils.restoreIdentityFromSecretKey(derivedPrivateKey)
  } else {
    return await KeyStoreUtils.restoreIdentityFromSecretKey(privateKey)
  }
}

