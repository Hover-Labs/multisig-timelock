import smartpy as sp

# The type of a lambda that will be executed.
LAMBDA_TYPE = sp.TLambda(sp.TUnit, sp.TList(sp.TOperation))

# The type for a set of signatures
# Param:
# - signaturesMap (map(keyHash, signature)) A map of keys to signatures.
SIGNATURES_TYPE = sp.TMap(sp.TKeyHash, sp.TSignature)

# Type for a set of keys in the multisig.
# Params:
# - threshold (nat): The number of keys required.
# - keys (list(keys)): The list of public keys which can be used in the multisig.
KEY_DATA_TYPE = sp.TPair(sp.TNat, sp.TList(sp.TKey))

# Type for a request for execution.
# Params:
# - chainId (chainID) The chain id to execute on.
# - nonce (nat) The nonce of the contract
# - payload (LAMBDA_TYPE) The lambda to execute.
EXECUTION_REQUEST_TYPE = sp.TPair(sp.TChainId, sp.TPair(sp.TNat, LAMBDA_TYPE))

# Type for a signed execution request.
# Params:
# - signatures (SIGNATURES_TYPE) A map of public keys to signatures
# - executionRequest (EXECUTION_REQUEST_TYPE) The request to execute
SIGNED_EXECUTION_REQUEST_TYPE = sp.TPair(SIGNATURES_TYPE, EXECUTION_REQUEST_TYPE)

# Type for values in the timelock map. 
# Params:
# - timelockStart (timestamp) The time that the timelock began
# - lambda (LAMBDA_TYPE) The lambda to execute
TIMELOCK_TYPE = sp.TPair(sp.TTimestamp, LAMBDA_TYPE)

# Type for a request to roate keys.
# - chainId (chainID) The chain id to execute on.
# - nonce (nat) The nonce of the contract
# - payload (KEY_DATA_TYPE) The lambda to execute.
KEY_ROTATION_REQUEST_TYPE = sp.TPair(sp.TChainId, sp.TPair(sp.TNat, KEY_DATA_TYPE))

# Type for a signed request to rotate keys.
# - signatures (SIGNATURES_TYPE) A map of public keys to signatures
# - keyRotationRequest (KEY_ROTATION_REQUEST_TYPE) The request to execute
SIGNED_KEY_ROTATION_REQUEST_TYPE = sp.TPair(SIGNATURES_TYPE, KEY_ROTATION_REQUEST_TYPE)

class MultiSigTimelock(sp.Contract):
   # TODO(keefertaylor): Consistent indentation and casing.
    def __init__(self, 
      signers_threshold = sp.nat(1),
      timelock_seconds = sp.nat(0),
      operator_public_keys = [sp.key("edpkuX2icxnt5krjTJAmNv8uNJNiQtFmDy9Hzj6SF1f6e3NjT4LXKB")]
    ):
        self.init(
            nonce=sp.nat(0), 
            signers_threshold=signers_threshold,
            operator_public_keys=operator_public_keys,

            # Seconds to timelock for.
            timelock_seconds = sp.nat(60 * 60), # 1 hour

            # Map of <nonce>:<execution request>
            timelock = sp.big_map(
                l = {},
                tkey = sp.TNat,
                tvalue = TIMELOCK_TYPE
            )
        )

    # Rotate keys.
    # Param:
    # - signedKeyRotationRequest (SIGNED_KEY_ROTATION_REQUEST_TYPE) The request to submit.
    @sp.entry_point
    def addExecutionRequest(self, signedKeyRotationRequest):
      # Destructure input params
      sp.set_type(signedExecutionRequest, SIGNED_KEY_ROTATION_REQUEST_TYPE)
      signatures, keyRotationRequest = sp.match_pair(signedExecutionRequest)

      # Destructure execution request
      chainId, innerPair = sp.match_pair(keyRotationRequest)
      nonce, lambdaToExecute = sp.match_pair(innerPair)

      # Verify ChainID
      sp.verify(chainId == sp.chain_id, "BAD_CHAIN_ID")
      
      # Verify Nonce
      sp.verify(nonce == self.data.nonce + 1, "BAD_NONCE")

      # Count valid signatures
      validSignaturesCounter = sp.local('valid_signatures_counter', sp.nat(0))
      sp.for operator_public_key in self.data.operator_public_keys:
        # Check if the given public key is in the signatures list.
        keyHash = sp.hash_key(operator_public_key)
        sp.if signatures.contains(keyHash):
          sp.if sp.check_signature(operator_public_key, signatures[keyHash], sp.pack(keyRotationRequest)):
            validSignaturesCounter.value += 1

      # Verify that enough signatures were provided.
      sp.verify(validSignaturesCounter.value >= self.data.signers_threshold, "TOO_FEW_SIGS")
      
      # Change out data. 
      newThreshold, newKeys = sp.match_pair(key_rotation_request)

      # Increment nonce.
      self.data.nonce += 1

    # Add a request to the timelock, assuming it has been properly signed.
    # Param:
    # - signedExecutionRequest (SIGNED_EXECUTION_REQUEST_TYPE) The request to submit.
    @sp.entry_point
    def addExecutionRequest(self, signedExecutionRequest):
      # Destructure input params
      sp.set_type(signedExecutionRequest, SIGNED_EXECUTION_REQUEST_TYPE)
      signatures, executionRequest = sp.match_pair(signedExecutionRequest)

      # Destructure execution request
      chainId, innerPair = sp.match_pair(executionRequest)
      nonce, lambdaToExecute = sp.match_pair(innerPair)

      # Verify ChainID
      sp.verify(chainId == sp.chain_id, "BAD_CHAIN_ID")
      
      # Verify Nonce
      sp.verify(nonce == self.data.nonce + 1, "BAD_NONCE")

      # Count valid signatures
      validSignaturesCounter = sp.local('valid_signatures_counter', sp.nat(0))
      sp.for operator_public_key in self.data.operator_public_keys:
        # Check if the given public key is in the signatures list.
        keyHash = sp.hash_key(operator_public_key)
        sp.if signatures.contains(keyHash):
          sp.if sp.check_signature(operator_public_key, signatures[keyHash], sp.pack(executionRequest)):
            validSignaturesCounter.value += 1

      # Verify that enough signatures were provided.
      sp.verify(validSignaturesCounter.value >= self.data.signers_threshold, "TOO_FEW_SIGS")

      # Increment nonce.
      self.data.nonce += 1

      # Add to timelock.
      self.data.timelock[self.data.nonce] = (sp.now, lambdaToExecute)

    # Execute a request in the timelock.
    # Pamrams:
    # - nonce (nat) The identifier of the nonce to execute.
    @sp.entry_point
    def execute(self, nonce):
        # Get timelock. Will fail if there's no request for nonce.
        timelockItem = self.data.timelock[nonce]
        timelockToStart, lambdaToExecute = sp.match_pair(timelockItem)

        # Verify time has been exceeded.
        execution_time = timelockToStart.add_seconds(sp.to_int(self.data.timelock_seconds))
        sp.verify(execution_time < sp.now, "TOO_EARLY")

        # Execute request.
        sp.add_operations(lambdaToExecute(sp.unit).rev())

    # TODO(keefertaylor): Write a cancel function.

# A contract which stores a value that may only be set by the admin.
# TODO(keefertaylor): Refactor?
class StoreValueContract(sp.Contract):
  def __init__(self, value, admin):
    self.init(storedValue = value, admin=admin)

  @sp.entry_point
  def default(self, params):
    pass

  @sp.entry_point
  def replace(self, params):
    sp.verify(sp.sender == self.data.admin, "NOT_ADMIN")       
    self.data.storedValue = params.value

@sp.add_test(name = "addExecutionRequest - succeeds with all signatures")
def test():
  scenario = sp.test_scenario()

  # GIVEN a set of an accounts
  alice = sp.test_account("alice")
  bob = sp.test_account("bob")
  charlie = sp.test_account("charlie")
  dan = sp.test_account("dan")
  eve = sp.test_account("eve")

  # AND a timelock multisig contract with a threshold of 3/5
  threshhold = 3
  multiSigContract = MultiSigTimelock(
    signers_threshold = threshhold,
    operator_public_keys = [ alice.public_key, bob.public_key, charlie.public_key, dan.public_key, eve.public_key ]
  )
  scenario += multiSigContract

  # AND a chain id.
  chainId = sp.chain_id_cst("0x9caecab9")

  # AND a store value contract with the multisig as the admin.
  storeContract = StoreValueContract(value = 0, admin = multiSigContract.address)
  scenario += storeContract

  # AND a lambda is to update the value
  newValue = 1
  def updateLambda(unitParam):
    sp.set_type(unitParam, sp.TUnit)
    storeContractHandle = sp.contract(sp.TNat, storeContract.address, 'replace').open_some()
    sp.result([sp.transfer_operation(newValue, sp.mutez(0), storeContractHandle)])

  # AND a payload is correctly signed by all parties.
  nonce = 1
  executionRequest = (chainId, (nonce, updateLambda))
  executionRequestBytes = sp.pack(executionRequest)

  aliceSignature = sp.make_signature(alice.secret_key, executionRequestBytes)
  bobSignature = sp.make_signature(bob.secret_key, executionRequestBytes)
  charlieSignature = sp.make_signature(charlie.secret_key, executionRequestBytes)
  danSignature = sp.make_signature(dan.secret_key, executionRequestBytes)
  eveSignature = sp.make_signature(eve.secret_key, executionRequestBytes)

  #  WHEN the request is sent to the multisignature contract.
  signatures = {
   alice.public_key_hash:   aliceSignature,
   bob.public_key_hash:     bobSignature, 
   charlie.public_key_hash: charlieSignature,
   dan.public_key_hash:     danSignature,
   eve.public_key_hash:     eveSignature 
  }
  signedExecutionRequest = (signatures, executionRequest)
  now = sp.timestamp(123)
  scenario += multiSigContract.addExecutionRequest(signedExecutionRequest).run(
    chain_id = chainId,
    now = now
  )

  # THEN there is one request in the timelock
  scenario.verify(multiSigContract.data.timelock.contains(nonce))

  # AND the request has the execution time.
  timelockItem = multiSigContract.data.timelock[nonce]
  scenario.verify(sp.fst(timelockItem) == now)

@sp.add_test(name = "addExecutionRequest - succeeds with threshold signatures")
def test():
  scenario = sp.test_scenario()

  # GIVEN a set of an accounts
  alice = sp.test_account("alice")
  bob = sp.test_account("bob")
  charlie = sp.test_account("charlie")
  dan = sp.test_account("dan")
  eve = sp.test_account("eve")

  # AND a timelock multisig contract with a threshold of 3/5
  threshhold = 3
  multiSigContract = MultiSigTimelock(
    signers_threshold = threshhold,
    operator_public_keys = [ alice.public_key, bob.public_key, charlie.public_key, dan.public_key, eve.public_key ]
  )
  scenario += multiSigContract

  # AND a chain id.
  chainId = sp.chain_id_cst("0x9caecab9")

  # AND a store value contract with the multisig as the admin.
  storeContract = StoreValueContract(value = 0, admin = multiSigContract.address)
  scenario += storeContract

  # AND a lambda is to update the value
  newValue = 1
  def updateLambda(unitParam):
    sp.set_type(unitParam, sp.TUnit)
    storeContractHandle = sp.contract(sp.TNat, storeContract.address, 'replace').open_some()
    sp.result([sp.transfer_operation(newValue, sp.mutez(0), storeContractHandle)])

  # AND a payload is correctly signed by 3 parties.
  nonce = 1
  executionRequest = (chainId, (nonce, updateLambda))
  executionRequestBytes = sp.pack(executionRequest)

  bobSignature = sp.make_signature(bob.secret_key, executionRequestBytes)
  charlieSignature = sp.make_signature(charlie.secret_key, executionRequestBytes)
  danSignature = sp.make_signature(dan.secret_key, executionRequestBytes)

  #  WHEN the request is sent to the multisignature contract.
  signatures = {
   bob.public_key_hash:     bobSignature, 
   charlie.public_key_hash: charlieSignature,
   dan.public_key_hash:     danSignature,
  }
  signedExecutionRequest = (signatures, executionRequest)
  now = sp.timestamp(123)
  scenario += multiSigContract.addExecutionRequest(signedExecutionRequest).run(
    chain_id = chainId,
    now = now
  )

  # THEN there is one request in the timelock
  scenario.verify(multiSigContract.data.timelock.contains(nonce))

  # AND the request has the execution time.
  timelockItem = multiSigContract.data.timelock[nonce]
  scenario.verify(sp.fst(timelockItem) == now)

@sp.add_test(name = "addExecutionRequest - fails with less than threshold signatures")
def test():
  scenario = sp.test_scenario()

  # GIVEN a set of an accounts
  alice = sp.test_account("alice")
  bob = sp.test_account("bob")
  charlie = sp.test_account("charlie")
  dan = sp.test_account("dan")
  eve = sp.test_account("eve")

  # AND a timelock multisig contract with a threshold of 3/5
  threshhold = 3
  multiSigContract = MultiSigTimelock(
    signers_threshold = threshhold,
    operator_public_keys = [ alice.public_key, bob.public_key, charlie.public_key, dan.public_key, eve.public_key ]
  )
  scenario += multiSigContract

  # AND a chain id.
  chainId = sp.chain_id_cst("0x9caecab9")

  # AND a store value contract with the multisig as the admin.
  storeContract = StoreValueContract(value = 0, admin = multiSigContract.address)
  scenario += storeContract

  # AND a lambda is to update the value
  newValue = 1
  def updateLambda(unitParam):
    sp.set_type(unitParam, sp.TUnit)
    storeContractHandle = sp.contract(sp.TNat, storeContract.address, 'replace').open_some()
    sp.result([sp.transfer_operation(newValue, sp.mutez(0), storeContractHandle)])

  # AND a payload is correctly signed by less than the threshold.
  nonce = 1
  executionRequest = (chainId, (nonce, updateLambda))
  executionRequestBytes = sp.pack(executionRequest)

  bobSignature = sp.make_signature(bob.secret_key, executionRequestBytes)
  charlieSignature = sp.make_signature(charlie.secret_key, executionRequestBytes)

  #  WHEN the request is sent to the multisignature contract.
  signatures = {
   bob.public_key_hash:     bobSignature, 
   charlie.public_key_hash: charlieSignature,
  }
  signedExecutionRequest = (signatures, executionRequest)
  now = sp.timestamp(123)

  # THEN it fails.
  scenario += multiSigContract.addExecutionRequest(signedExecutionRequest).run(
    chain_id = chainId,
    now = now,
    valid = False
  )

  @sp.add_test(name = "addExecutionRequest - does not count invalid signatures")
  def test():
    scenario = sp.test_scenario()

    # GIVEN a set of an accounts
    alice = sp.test_account("alice")
    bob = sp.test_account("bob")
    charlie = sp.test_account("charlie")
    dan = sp.test_account("dan")
    eve = sp.test_account("eve")

    # AND a timelock multisig contract with a threshold of 3/3
    threshhold = 3
    multiSigContract = MultiSigTimelock(
      signers_threshold = threshhold,
      operator_public_keys = [ alice.public_key, bob.public_key, charlie.public_key]
    )
    scenario += multiSigContract

    # AND a chain id.
    chainId = sp.chain_id_cst("0x9caecab9")

    # AND a store value contract with the multisig as the admin.
    storeContract = StoreValueContract(value = 0, admin = multiSigContract.address)
    scenario += storeContract

    # AND a lambda is to update the value
    newValue = 1
    def updateLambda(unitParam):
      sp.set_type(unitParam, sp.TUnit)
      storeContractHandle = sp.contract(sp.TNat, storeContract.address, 'replace').open_some()
      sp.result([sp.transfer_operation(newValue, sp.mutez(0), storeContractHandle)])

    # AND a payload is signed by 3 signatures but 2 are invalid.
    nonce = 1
    executionRequest = (chainId, (nonce, updateLambda))
    executionRequestBytes = sp.pack(executionRequest)

    charlieSignature = sp.make_signature(charlie.secret_key, executionRequestBytes)
    danSignature = sp.make_signature(dan.secret_key, executionRequestBytes)
    eveSignature = sp.make_signature(eve.secret_key, executionRequestBytes)

    #  WHEN the request is sent to the multisignature contract.
    signatures = {
      charlie.public_key_hash: charlieSignature,
      dan.public_key_hash: danSignature,
      eve.public_key_hash: eveSignature,
    }
    signedExecutionRequest = (signatures, executionRequest)
    now = sp.timestamp(123)

    # THEN it fails.
    scenario += multiSigContract.addExecutionRequest(signedExecutionRequest).run(
      chain_id = chainId,
      now = now,
      valid = False
    )
