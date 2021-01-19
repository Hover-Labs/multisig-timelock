import smartpy as sp

################################################################
################################################################
# Constants
################################################################
################################################################

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
# - operationId (nat) The operation id of the contract
# - payload (LAMBDA_TYPE) The lambda to execute.
EXECUTION_REQUEST_TYPE = sp.TPair(sp.TChainId, sp.TPair(sp.TNat, LAMBDA_TYPE))

# Type for a request to cancel.
# - chainId (chainID) The chain id to execute on.
# - operationId (nat) The operation id of the contract
# - timelockId (nat) The id in the timelock to cancel.
CANCELLATION_REQUEST_TYPE = sp.TPair(sp.TChainId, sp.TPair(sp.TNat, sp.TNat))

# Type cor a signed request to cancel.
# Params:
# - signatures (SIGNATURES_TYPE) A map of public keys to signatures
# - cancellationRequest (CANCELLATION_REQUEST_TYPE) The cancellation request.
SIGNED_CANCELLATION_REQUEST_TYPE = sp.TPair(SIGNATURES_TYPE, CANCELLATION_REQUEST_TYPE)

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
# - operationId (nat) The operation Id of the contract
# - payload (KEY_DATA_TYPE) The lambda to execute.
KEY_ROTATION_REQUEST_TYPE = sp.TPair(sp.TChainId, sp.TPair(sp.TNat, KEY_DATA_TYPE))

# Type for a signed request to rotate keys.
# - signatures (SIGNATURES_TYPE) A map of public keys to signatures
# - keyRotationRequest (KEY_ROTATION_REQUEST_TYPE) The request to execute
SIGNED_KEY_ROTATION_REQUEST_TYPE = sp.TPair(SIGNATURES_TYPE, KEY_ROTATION_REQUEST_TYPE)

################################################################
################################################################
# Contract
################################################################
################################################################

class MultiSigTimelock(sp.Contract):
  # Params:
  # - threshold (nat) The number of signatures required.
  # - timelockSeconds (nat) The number of seconds a timelock lasts for.
  # - signers (list(key)) The keys which can sign.
  def __init__(self, 
    threshold = sp.nat(1),
    timelockSeconds = sp.nat(60 * 60), # 1 hour
    signers = [sp.key("edpkuX2icxnt5krjTJAmNv8uNJNiQtFmDy9Hzj6SF1f6e3NjT4LXKB")]
  ):
    self.init(
      operationId=sp.nat(0), 
      threshold=threshold,
      signers=signers,
      timelockSeconds = timelockSeconds,

      # Map of <operationId>:<execution request>
      timelock = sp.big_map(
        l = {},
        tkey = sp.TNat,
        tvalue = TIMELOCK_TYPE
      )
    )

  # Add a request to the timelock, assuming it has been properly signed.
  # Param:
  # - signedExecutionRequest (SIGNED_EXECUTION_REQUEST_TYPE) The request to submit.
  @sp.entry_point
  def submit(self, signedExecutionRequest):
    # Destructure input params
    sp.set_type(signedExecutionRequest, SIGNED_EXECUTION_REQUEST_TYPE)
    signatures, executionRequest = sp.match_pair(signedExecutionRequest)

    # Destructure execution request
    chainId, innerPair = sp.match_pair(executionRequest)
    operationId, lambdaToExecute = sp.match_pair(innerPair)

    # Verify ChainID
    sp.verify_equal(chainId, sp.chain_id, "BAD_CHAIN_ID")
    
    # Verify Operation ID
    sp.verify(operationId == self.data.operationId + 1, "BAD_OP_ID")

    # Count valid signatures
    validSignaturesCounter = sp.local('valid_signatures_counter', sp.nat(0))
    sp.for signer in self.data.signers:
      # Check if the given public key is in the signatures list.
      keyHash = sp.hash_key(signer)
      sp.if signatures.contains(keyHash):
        sp.verify(sp.check_signature(signer, signatures[keyHash], sp.pack(executionRequest)), "BAD_SIGNATURE")
        validSignaturesCounter.value += 1
      
    # Verify that enough signatures were provided.
    sp.verify(validSignaturesCounter.value >= self.data.threshold, "TOO_FEW_SIGS")

    # Increment operation ID.
    self.data.operationId += 1

    # Add to timelock.
    self.data.timelock[self.data.operationId] = (sp.now, lambdaToExecute)

  # Rotate keys, assuming the request has been properly signed.
  # Param:
  # - signedKeyRotationRequest (SIGNED_KEY_ROTATION_REQUEST_TYPE) The request to submit.
  @sp.entry_point
  def rotate(self, signedKeyRotationRequest):
    # Destructure input params
    sp.set_type(signedKeyRotationRequest, SIGNED_KEY_ROTATION_REQUEST_TYPE)
    signatures, keyRotationRequest = sp.match_pair(signedKeyRotationRequest)

    # Destructure key request
    chainId, innerPair = sp.match_pair(keyRotationRequest)
    operationId, keyData = sp.match_pair(innerPair)

    # Verify ChainID
    sp.verify_equal(chainId, sp.chain_id, "BAD_CHAIN_ID")
    
    # Verify Operation ID
    sp.verify(operationId == self.data.operationId + 1, "BAD_OP_ID")

    # Count valid signatures
    validSignaturesCounter = sp.local('valid_signatures_counter', sp.nat(0))
    sp.for signer in self.data.signers:
      # Check if the given public key is in the signatures list.
      keyHash = sp.hash_key(signer)
      sp.if signatures.contains(keyHash):
        sp.verify(sp.check_signature(signer, signatures[keyHash], sp.pack(keyRotationRequest)), "BAD_SIGNATURE")
        validSignaturesCounter.value += 1
      
    # Verify that enough signatures were provided.
    sp.verify(validSignaturesCounter.value >= self.data.threshold, "TOO_FEW_SIGS")

    # Increment operation ID.
    self.data.operationId += 1

    # Update key data
    threshold, keyList = sp.match_pair(keyData)
    self.data.threshold  = threshold
    self.data.signers = keyList

  # Cancel a request in the timelock.
  # Param:
  # - signedCancellationRequest (SIGNED_CANCELLATION_REQUEST_TYPE) The request to submit.
  @sp.entry_point
  def cancel(self, signedCancellationRequest):
    # Destructure input params
    sp.set_type(signedCancellationRequest, SIGNED_CANCELLATION_REQUEST_TYPE)
    signatures, cancellationRequest = sp.match_pair(signedCancellationRequest)

    # Destructure cancellation request
    chainId, innerPair = sp.match_pair(cancellationRequest)
    operationId, cancellationTarget = sp.match_pair(innerPair)

    # Verify ChainID
    sp.verify_equal(chainId, sp.chain_id, "BAD_CHAIN_ID")
    
    # Verify Operation ID
    sp.verify(operationId == self.data.operationId + 1, "BAD_OP_ID")

    # Count valid signatures
    validSignaturesCounter = sp.local('valid_signatures_counter', sp.nat(0))
    sp.for signer in self.data.signers:
      # Check if the given public key is in the signatures list.
      keyHash = sp.hash_key(signer)
      sp.if signatures.contains(keyHash):
        sp.verify(sp.check_signature(signer, signatures[keyHash], sp.pack(cancellationRequest)), "BAD_SIGNATURE")
        validSignaturesCounter.value += 1
      
    # Verify that enough signatures were provided.
    sp.verify(validSignaturesCounter.value >= self.data.threshold, "TOO_FEW_SIGS")

    # Increment operation ID.
    self.data.operationId += 1

    # Update key data
    del self.data.timelock[cancellationTarget]

  # Execute a request in the timelock.
  # Pamrams:
  # - operationId (nat) The identifier of the operation ID to execute.
  @sp.entry_point
  def execute(self, operationId):
      # Get timelock. Will fail if there's no request for the operation ID.
      timelockItem = self.data.timelock[operationId]
      timelockToStart, lambdaToExecute = sp.match_pair(timelockItem)

      # Verify time has been exceeded.
      execution_time = timelockToStart.add_seconds(sp.to_int(self.data.timelockSeconds))
      sp.verify(execution_time < sp.now, "TOO_EARLY")

      # Remove item from timelock.
      del self.data.timelock[operationId]

      # Execute request.
      operations = lambdaToExecute(sp.unit)
      sp.set_type(operations, sp.TList(sp.TOperation))
      sp.add_operations(operations)

################################################################
################################################################
# Tests
################################################################
################################################################

Store = sp.import_script_from_url("file:test-helpers/store.py")

################################################################
# submit
################################################################

@sp.add_test(name = "submit - succeeds with all signatures")
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
    threshold = threshhold,
    signers = [ alice.public_key, bob.public_key, charlie.public_key, dan.public_key, eve.public_key ]
  )
  scenario += multiSigContract

  # AND a chain id.
  chainId = sp.chain_id_cst("0x9caecab9")

  # AND a store value contract with the multisig as the admin.
  storeContract = Store.StoreValueContract(value = 0, admin = multiSigContract.address)
  scenario += storeContract

  # AND a lambda is to update the value
  newValue = 1
  def updateLambda(unitParam):
    sp.set_type(unitParam, sp.TUnit)
    storeContractHandle = sp.contract(sp.TNat, storeContract.address, 'replace').open_some()
    sp.result([sp.transfer_operation(newValue, sp.mutez(0), storeContractHandle)])

  # AND a payload is correctly signed by all parties.
  operationId = 1
  executionRequest = (chainId, (operationId, updateLambda))
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
  scenario += multiSigContract.submit(signedExecutionRequest).run(
    chain_id = chainId,
    now = now
  )

  # THEN there is one request in the timelock
  scenario.verify(multiSigContract.data.timelock.contains(operationId))

  # THEN the operationId has been updated
  scenario.verify(multiSigContract.data.operationId == operationId)

  # AND the request has the execution time.
  timelockItem = multiSigContract.data.timelock[operationId]
  scenario.verify(sp.fst(timelockItem) == now)

@sp.add_test(name = "submit - succeeds with threshold signatures")
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
    threshold = threshhold,
    signers = [ alice.public_key, bob.public_key, charlie.public_key, dan.public_key, eve.public_key ]
  )
  scenario += multiSigContract

  # AND a chain id.
  chainId = sp.chain_id_cst("0x9caecab9")

  # AND a store value contract with the multisig as the admin.
  storeContract = Store.StoreValueContract(value = 0, admin = multiSigContract.address)
  scenario += storeContract

  # AND a lambda is to update the value
  newValue = 1
  def updateLambda(unitParam):
    sp.set_type(unitParam, sp.TUnit)
    storeContractHandle = sp.contract(sp.TNat, storeContract.address, 'replace').open_some()
    sp.result([sp.transfer_operation(newValue, sp.mutez(0), storeContractHandle)])

  # AND a payload is correctly signed by 3 parties.
  operationId = 1
  executionRequest = (chainId, (operationId, updateLambda))
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
  scenario += multiSigContract.submit(signedExecutionRequest).run(
    chain_id = chainId,
    now = now
  )

  # THEN there is one request in the timelock
  scenario.verify(multiSigContract.data.timelock.contains(operationId))

  # THEN the operationId has been updated
  scenario.verify(multiSigContract.data.operationId == operationId)

  # AND the request has the execution time.
  timelockItem = multiSigContract.data.timelock[operationId]
  scenario.verify(sp.fst(timelockItem) == now)

@sp.add_test(name = "submit - fails with bad operationId")
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
    threshold = threshhold,
    signers = [ alice.public_key, bob.public_key, charlie.public_key, dan.public_key, eve.public_key ]
  )
  scenario += multiSigContract

  # AND a chain id.
  chainId = sp.chain_id_cst("0x9caecab9")

  # AND a store value contract with the multisig as the admin.
  storeContract = Store.StoreValueContract(value = 0, admin = multiSigContract.address)
  scenario += storeContract

  # AND a lambda is to update the value
  newValue = 1
  def updateLambda(unitParam):
    sp.set_type(unitParam, sp.TUnit)
    storeContractHandle = sp.contract(sp.TNat, storeContract.address, 'replace').open_some()
    sp.result([sp.transfer_operation(newValue, sp.mutez(0), storeContractHandle)])

  # AND a payload is correctly with a bad operationId
  operationId = 4 # Obviously wrong.
  executionRequest = (chainId, (operationId, updateLambda))
  executionRequestBytes = sp.pack(executionRequest)

  bobSignature = sp.make_signature(bob.secret_key, executionRequestBytes)
  charlieSignature = sp.make_signature(charlie.secret_key, executionRequestBytes)
  danSignature = sp.make_signature(dan.secret_key, executionRequestBytes)

  # WHEN the request is sent to the multisignature contract
  signatures = {
   bob.public_key_hash:     bobSignature, 
   charlie.public_key_hash: charlieSignature,
   dan.public_key_hash:     danSignature,
  }
  signedExecutionRequest = (signatures, executionRequest)
  now = sp.timestamp(123)

  # THEN the call fails.
  scenario += multiSigContract.submit(signedExecutionRequest).run(
    chain_id = chainId,
    now = now,
    valid = False
  )

@sp.add_test(name = "submit - fails with bad chain id")
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
    threshold = threshhold,
    signers = [ alice.public_key, bob.public_key, charlie.public_key, dan.public_key, eve.public_key ]
  )
  scenario += multiSigContract

  # AND a chain id.
  chainId = sp.chain_id_cst("0x9caecab9")

  # AND a store value contract with the multisig as the admin.
  storeContract = Store.StoreValueContract(value = 0, admin = multiSigContract.address)
  scenario += storeContract

  # AND a lambda is to update the value
  newValue = 1
  def updateLambda(unitParam):
    sp.set_type(unitParam, sp.TUnit)
    storeContractHandle = sp.contract(sp.TNat, storeContract.address, 'replace').open_some()
    sp.result([sp.transfer_operation(newValue, sp.mutez(0), storeContractHandle)])

  # AND a payload is correctly signed by 3 parties.
  operationId = 1
  executionRequest = (chainId, (operationId, updateLambda))
  executionRequestBytes = sp.pack(executionRequest)

  bobSignature = sp.make_signature(bob.secret_key, executionRequestBytes)
  charlieSignature = sp.make_signature(charlie.secret_key, executionRequestBytes)
  danSignature = sp.make_signature(dan.secret_key, executionRequestBytes)

  # WHEN the request is sent to the multisignature contract with an incorrect chain id
  # THEN the request fails.
  signatures = {
   bob.public_key_hash:     bobSignature, 
   charlie.public_key_hash: charlieSignature,
   dan.public_key_hash:     danSignature,
  }
  signedExecutionRequest = (signatures, executionRequest)
  now = sp.timestamp(123)
  scenario += multiSigContract.submit(signedExecutionRequest).run(
    chain_id = sp.chain_id_cst("0x0011223344"),
    now = now,
    valid = False
  )

@sp.add_test(name = "submit - fails with less than threshold signatures")
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
    threshold = threshhold,
    signers = [ alice.public_key, bob.public_key, charlie.public_key, dan.public_key, eve.public_key ]
  )
  scenario += multiSigContract

  # AND a chain id.
  chainId = sp.chain_id_cst("0x9caecab9")

  # AND a store value contract with the multisig as the admin.
  storeContract = Store.StoreValueContract(value = 0, admin = multiSigContract.address)
  scenario += storeContract

  # AND a lambda is to update the value
  newValue = 1
  def updateLambda(unitParam):
    sp.set_type(unitParam, sp.TUnit)
    storeContractHandle = sp.contract(sp.TNat, storeContract.address, 'replace').open_some()
    sp.result([sp.transfer_operation(newValue, sp.mutez(0), storeContractHandle)])

  # AND a payload is correctly signed by less than the threshold.
  operationId = 1
  executionRequest = (chainId, (operationId, updateLambda))
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
  scenario += multiSigContract.submit(signedExecutionRequest).run(
    chain_id = chainId,
    now = now,
    valid = False
  )

@sp.add_test(name = "submit - does not count invalid signatures")
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
    threshold = threshhold,
    signers = [ alice.public_key, bob.public_key, charlie.public_key]
  )
  scenario += multiSigContract

  # AND a chain id.
  chainId = sp.chain_id_cst("0x9caecab9")

  # AND a store value contract with the multisig as the admin.
  storeContract = Store.StoreValueContract(value = 0, admin = multiSigContract.address)
  scenario += storeContract

  # AND a lambda is to update the value
  newValue = 1
  def updateLambda(unitParam):
    sp.set_type(unitParam, sp.TUnit)
    storeContractHandle = sp.contract(sp.TNat, storeContract.address, 'replace').open_some()
    sp.result([sp.transfer_operation(newValue, sp.mutez(0), storeContractHandle)])

  # AND a payload is signed by 3 signatures but 2 are invalid.
  operationId = 1
  executionRequest = (chainId, (operationId, updateLambda))
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
  scenario += multiSigContract.submit(signedExecutionRequest).run(
    chain_id = chainId,
    now = now,
    valid = False
  )

################################################################
# rotate
################################################################

@sp.add_test(name = "rotate - succeeds with all signatures")
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
    threshold = threshhold,
    signers = [ alice.public_key, bob.public_key, charlie.public_key, dan.public_key, eve.public_key ]
  )
  scenario += multiSigContract

  # AND a chain id.
  chainId = sp.chain_id_cst("0x9caecab9")

  # AND key data
  newThreshold = sp.nat(2)

  fred = sp.test_account("fred")
  george = sp.test_account("george")
  newKeyList = [ fred.public_key, george.public_key ]

  newKeyData = (newThreshold, newKeyList)

  # AND a payload is correctly signed by all parties.
  operationId = 1
  rotationRequest = (chainId, (operationId, newKeyData))
  rotationRequestBytes = sp.pack(rotationRequest)

  aliceSignature = sp.make_signature(alice.secret_key, rotationRequestBytes)
  bobSignature = sp.make_signature(bob.secret_key, rotationRequestBytes)
  charlieSignature = sp.make_signature(charlie.secret_key, rotationRequestBytes)
  danSignature = sp.make_signature(dan.secret_key, rotationRequestBytes)
  eveSignature = sp.make_signature(eve.secret_key, rotationRequestBytes)

  #  WHEN the request is sent to the multisignature contract.
  signatures = {
   alice.public_key_hash:   aliceSignature,
   bob.public_key_hash:     bobSignature, 
   charlie.public_key_hash: charlieSignature,
   dan.public_key_hash:     danSignature,
   eve.public_key_hash:     eveSignature 
  }
  signedRotationRequest = (signatures, rotationRequest)
  now = sp.timestamp(123)
  scenario += multiSigContract.rotate(signedRotationRequest).run(
    chain_id = chainId,
    now = now
  )

  # THEN the operationId has been updated
  scenario.verify(multiSigContract.data.operationId == operationId)

  # AND the key data has been updated.
  scenario.verify(multiSigContract.data.threshold == newThreshold)
  scenario.verify_equal(multiSigContract.data.signers, newKeyList)

@sp.add_test(name = "rotate - succeeds with threshold signatures")
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
    threshold = threshhold,
    signers = [ alice.public_key, bob.public_key, charlie.public_key, dan.public_key, eve.public_key ]
  )
  scenario += multiSigContract

  # AND a chain id.
  chainId = sp.chain_id_cst("0x9caecab9")

  # AND key data
  newThreshold = sp.nat(2)

  fred = sp.test_account("fred")
  george = sp.test_account("george")
  newKeyList = [ fred.public_key, george.public_key ]

  newKeyData = (newThreshold, newKeyList)

  # AND a payload is correctly signed by 3 parties.
  operationId = 1
  rotationRequest = (chainId, (operationId, newKeyData))
  rotationRequestBytes = sp.pack(rotationRequest)

  bobSignature = sp.make_signature(bob.secret_key, rotationRequestBytes)
  charlieSignature = sp.make_signature(charlie.secret_key, rotationRequestBytes)
  danSignature = sp.make_signature(dan.secret_key, rotationRequestBytes)

  #  WHEN the request is sent to the multisignature contract.
  signatures = {
   bob.public_key_hash:     bobSignature, 
   charlie.public_key_hash: charlieSignature,
   dan.public_key_hash:     danSignature,
  }
  signedRotationRequest = (signatures, rotationRequest)
  now = sp.timestamp(123)
  scenario += multiSigContract.rotate(signedRotationRequest).run(
    chain_id = chainId,
    now = now
  )

  # THEN the operationId has been updated
  scenario.verify(multiSigContract.data.operationId == operationId)

  # AND the key data has been updated.
  scenario.verify(multiSigContract.data.threshold == newThreshold)
  scenario.verify_equal(multiSigContract.data.signers, newKeyList)

@sp.add_test(name = "rotate - fails with bad operationId")
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
    threshold = threshhold,
    signers = [ alice.public_key, bob.public_key, charlie.public_key, dan.public_key, eve.public_key ]
  )
  scenario += multiSigContract

  # AND a chain id.
  chainId = sp.chain_id_cst("0x9caecab9")

  # AND key data
  newThreshold = sp.nat(2)

  fred = sp.test_account("fred")
  george = sp.test_account("george")
  newKeyList = [ fred.public_key, george.public_key ]

  newKeyData = (newThreshold, newKeyList)

  # AND a payload is correctly with a bad operationId
  operationId = 4 # Obviously wrong.
  rotationRequest = (chainId, (operationId, newKeyData))
  rotationRequestBytes = sp.pack(rotationRequest)

  bobSignature = sp.make_signature(bob.secret_key, rotationRequestBytes)
  charlieSignature = sp.make_signature(charlie.secret_key, rotationRequestBytes)
  danSignature = sp.make_signature(dan.secret_key, rotationRequestBytes)

  # WHEN the request is sent to the multisignature contract
  signatures = {
   bob.public_key_hash:     bobSignature, 
   charlie.public_key_hash: charlieSignature,
   dan.public_key_hash:     danSignature,
  }
  signedRotationRequest = (signatures, rotationRequest)
  now = sp.timestamp(123)

  # THEN the call fails.
  scenario += multiSigContract.rotate(signedRotationRequest).run(
    chain_id = chainId,
    now = now,
    valid = False
  )

@sp.add_test(name = "rotate - fails with bad chain id")
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
    threshold = threshhold,
    signers = [ alice.public_key, bob.public_key, charlie.public_key, dan.public_key, eve.public_key ]
  )
  scenario += multiSigContract

  # AND a chain id.
  chainId = sp.chain_id_cst("0x9caecab9")

  # AND key data
  newThreshold = sp.nat(2)

  fred = sp.test_account("fred")
  george = sp.test_account("george")
  newKeyList = [ fred.public_key, george.public_key ]

  newKeyData = (newThreshold, newKeyList)

  # AND a payload is correctly signed by 3 parties.
  operationId = 1
  rotationRequest = (chainId, (operationId, newKeyData))
  rotationRequestBytes = sp.pack(rotationRequest)

  bobSignature = sp.make_signature(bob.secret_key, rotationRequestBytes)
  charlieSignature = sp.make_signature(charlie.secret_key, rotationRequestBytes)
  danSignature = sp.make_signature(dan.secret_key, rotationRequestBytes)

  # WHEN the request is sent to the multisignature contract with an incorrect chain id
  # THEN the request fails.
  signatures = {
   bob.public_key_hash:     bobSignature, 
   charlie.public_key_hash: charlieSignature,
   dan.public_key_hash:     danSignature,
  }
  signedRotationRequest = (signatures, rotationRequest)
  now = sp.timestamp(123)
  scenario += multiSigContract.rotate(signedRotationRequest).run(
    chain_id = sp.chain_id_cst("0x0011223344"),
    now = now,
    valid = False
  )

@sp.add_test(name = "rotationRequest - fails with less than threshold signatures")
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
    threshold = threshhold,
    signers = [ alice.public_key, bob.public_key, charlie.public_key, dan.public_key, eve.public_key ]
  )
  scenario += multiSigContract

  # AND a chain id.
  chainId = sp.chain_id_cst("0x9caecab9")

  # AND key data
  newThreshold = sp.nat(2)

  fred = sp.test_account("fred")
  george = sp.test_account("george")
  newKeyList = [ fred.public_key, george.public_key ]

  newKeyData = (newThreshold, newKeyList)

  # AND a payload is correctly signed by less than the threshold.
  operationId = 1
  rotationRequest = (chainId, (operationId, newKeyData))
  rotationRequestBytes = sp.pack(rotationRequest)

  bobSignature = sp.make_signature(bob.secret_key, rotationRequestBytes)
  charlieSignature = sp.make_signature(charlie.secret_key, rotationRequestBytes)

  #  WHEN the request is sent to the multisignature contract.
  signatures = {
  bob.public_key_hash:     bobSignature, 
  charlie.public_key_hash: charlieSignature,
  }
  signedRotationRequest = (signatures, rotationRequest)
  now = sp.timestamp(123)

  # THEN it fails.
  scenario += multiSigContract.rotate(signedRotationRequest).run(
    chain_id = chainId,
    now = now,
    valid = False
  )

@sp.add_test(name = "rotate - does not count invalid signatures")
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
    threshold = threshhold,
    signers = [ alice.public_key, bob.public_key, charlie.public_key]
  )
  scenario += multiSigContract

  # AND a chain id.
  chainId = sp.chain_id_cst("0x9caecab9")

  # AND key data
  newThreshold = sp.nat(2)

  fred = sp.test_account("fred")
  george = sp.test_account("george")
  newKeyList = [ fred.public_key, george.public_key ]

  newKeyData = (newThreshold, newKeyList)

  # AND a payload is signed by 3 signatures but 2 are invalid.
  operationId = 1
  rotationRequest = (chainId, (operationId, newKeyData))
  rotationRequestBytes = sp.pack(rotationRequest)

  charlieSignature = sp.make_signature(charlie.secret_key, rotationRequestBytes)
  danSignature = sp.make_signature(dan.secret_key, rotationRequestBytes)
  eveSignature = sp.make_signature(eve.secret_key, rotationRequestBytes)

  #  WHEN the request is sent to the multisignature contract.
  signatures = {
    charlie.public_key_hash: charlieSignature,
    dan.public_key_hash: danSignature,
    eve.public_key_hash: eveSignature,
  }
  signedRotationRequest = (signatures, rotationRequest)
  now = sp.timestamp(123)

  # THEN it fails.
  scenario += multiSigContract.rotate(signedRotationRequest).run(
    chain_id = chainId,
    now = now,
    valid = False
  )

################################################################
# cancel
################################################################

@sp.add_test(name = "cancel - succeeds with all signatures")
def test():
  scenario = sp.test_scenario()

  # GIVEN a set of an accounts
  alice = sp.test_account("alice")
  bob = sp.test_account("bob")
  charlie = sp.test_account("charlie")
  dan = sp.test_account("dan")
  eve = sp.test_account("eve")

  # AND a timelock multisig with an operation loaded.
  threshhold = 3
  timelockSeconds = sp.nat(1)
  multiSigContract = MultiSigTimelock(
    threshold = threshhold,
    signers = [ alice.public_key, bob.public_key, charlie.public_key, dan.public_key, eve.public_key ],
    timelockSeconds = timelockSeconds
  )
  scenario += multiSigContract

  storeContract = Store.StoreValueContract(value = 0, admin = multiSigContract.address)
  scenario += storeContract

  chainId = sp.chain_id_cst("0x9caecab9")
  newValue = sp.nat(1)
  def updateLambda(unitParam):
    sp.set_type(unitParam, sp.TUnit)
    storeContractHandle = sp.contract(sp.TNat, storeContract.address, 'replace').open_some()
    sp.result([sp.transfer_operation(newValue, sp.mutez(0), storeContractHandle)])

  operationId = 1
  executionRequest = (chainId, (operationId, updateLambda))
  executionRequestBytes = sp.pack(executionRequest)

  bobSignature = sp.make_signature(bob.secret_key, executionRequestBytes)
  charlieSignature = sp.make_signature(charlie.secret_key, executionRequestBytes)
  danSignature = sp.make_signature(dan.secret_key, executionRequestBytes)

  signatures = {
   bob.public_key_hash:     bobSignature, 
   charlie.public_key_hash: charlieSignature,
   dan.public_key_hash:     danSignature,
  }
  signedExecutionRequest = (signatures, executionRequest)
  now = sp.timestamp(123)
  scenario += multiSigContract.submit(signedExecutionRequest).run(
    chain_id = chainId,
    now = now
  )

  # AND a cancellation request
  cancellationRequest = (chainId, (operationId + 1, operationId))

  # AND a payload is correctly signed by all parties.
  cancellationRequestBytes = sp.pack(cancellationRequest)

  aliceSignature = sp.make_signature(alice.secret_key, cancellationRequestBytes)
  bobSignature = sp.make_signature(bob.secret_key, cancellationRequestBytes)
  charlieSignature = sp.make_signature(charlie.secret_key, cancellationRequestBytes)
  danSignature = sp.make_signature(dan.secret_key, cancellationRequestBytes)
  eveSignature = sp.make_signature(eve.secret_key, cancellationRequestBytes)

  #  WHEN the request is sent to the multisignature contract.
  signatures = {
   alice.public_key_hash:   aliceSignature,
   bob.public_key_hash:     bobSignature, 
   charlie.public_key_hash: charlieSignature,
   dan.public_key_hash:     danSignature,
   eve.public_key_hash:     eveSignature 
  }
  signedCancellationRequest = (signatures, cancellationRequest)
  now = sp.timestamp(123)
  scenario += multiSigContract.cancel(signedCancellationRequest).run(
    chain_id = chainId,
    now = now
  )

  # THEN the timelock is cleared.
  scenario.verify(multiSigContract.data.timelock.contains(operationId) == False)

  # AND the operationId is incremented.
  scenario.verify(multiSigContract.data.operationId == operationId + 1)

@sp.add_test(name = "cancel - succeeds with threshold signatures")
def test():
  scenario = sp.test_scenario()

  # GIVEN a set of an accounts
  alice = sp.test_account("alice")
  bob = sp.test_account("bob")
  charlie = sp.test_account("charlie")
  dan = sp.test_account("dan")
  eve = sp.test_account("eve")

  # AND a timelock multisig with an operation loaded.
  threshhold = 3
  timelockSeconds = sp.nat(1)
  multiSigContract = MultiSigTimelock(
    threshold = threshhold,
    signers = [ alice.public_key, bob.public_key, charlie.public_key, dan.public_key, eve.public_key ],
    timelockSeconds = timelockSeconds
  )
  scenario += multiSigContract

  storeContract = Store.StoreValueContract(value = 0, admin = multiSigContract.address)
  scenario += storeContract

  chainId = sp.chain_id_cst("0x9caecab9")
  newValue = sp.nat(1)
  def updateLambda(unitParam):
    sp.set_type(unitParam, sp.TUnit)
    storeContractHandle = sp.contract(sp.TNat, storeContract.address, 'replace').open_some()
    sp.result([sp.transfer_operation(newValue, sp.mutez(0), storeContractHandle)])

  operationId = 1
  executionRequest = (chainId, (operationId, updateLambda))
  executionRequestBytes = sp.pack(executionRequest)

  bobSignature = sp.make_signature(bob.secret_key, executionRequestBytes)
  charlieSignature = sp.make_signature(charlie.secret_key, executionRequestBytes)
  danSignature = sp.make_signature(dan.secret_key, executionRequestBytes)

  signatures = {
   bob.public_key_hash:     bobSignature, 
   charlie.public_key_hash: charlieSignature,
   dan.public_key_hash:     danSignature,
  }
  signedExecutionRequest = (signatures, executionRequest)
  now = sp.timestamp(123)
  scenario += multiSigContract.submit(signedExecutionRequest).run(
    chain_id = chainId,
    now = now
  )

  # AND a cancellation request
  cancellationRequest = (chainId, (operationId + 1, operationId))

  # AND a payload is correctly signed by 3 parties.
  cancellationRequestBytes = sp.pack(cancellationRequest)

  bobSignature = sp.make_signature(bob.secret_key, cancellationRequestBytes)
  charlieSignature = sp.make_signature(charlie.secret_key, cancellationRequestBytes)
  danSignature = sp.make_signature(dan.secret_key, cancellationRequestBytes)

  #  WHEN the request is sent to the multisignature contract.
  signatures = {
   bob.public_key_hash:     bobSignature, 
   charlie.public_key_hash: charlieSignature,
   dan.public_key_hash:     danSignature,
  }
  signedCancellationRequest = (signatures, cancellationRequest)
  now = sp.timestamp(123)
  scenario += multiSigContract.cancel(signedCancellationRequest).run(
    chain_id = chainId,
    now = now
  )

  # THEN the timelock is cleared.
  scenario.verify(multiSigContract.data.timelock.contains(operationId) == False)

  # AND the operationId is incremented.
  scenario.verify(multiSigContract.data.operationId == operationId + 1)

@sp.add_test(name = "cancel - fails with bad operationId")
def test():
  scenario = sp.test_scenario()

  # GIVEN a set of an accounts
  alice = sp.test_account("alice")
  bob = sp.test_account("bob")
  charlie = sp.test_account("charlie")
  dan = sp.test_account("dan")
  eve = sp.test_account("eve")

  # AND a timelock multisig with an operation loaded.
  threshhold = 3
  timelockSeconds = sp.nat(1)
  multiSigContract = MultiSigTimelock(
    threshold = threshhold,
    signers = [ alice.public_key, bob.public_key, charlie.public_key, dan.public_key, eve.public_key ],
    timelockSeconds = timelockSeconds
  )
  scenario += multiSigContract

  storeContract = Store.StoreValueContract(value = 0, admin = multiSigContract.address)
  scenario += storeContract

  chainId = sp.chain_id_cst("0x9caecab9")
  newValue = sp.nat(1)
  def updateLambda(unitParam):
    sp.set_type(unitParam, sp.TUnit)
    storeContractHandle = sp.contract(sp.TNat, storeContract.address, 'replace').open_some()
    sp.result([sp.transfer_operation(newValue, sp.mutez(0), storeContractHandle)])

  operationId = 1
  executionRequest = (chainId, (operationId, updateLambda))
  executionRequestBytes = sp.pack(executionRequest)

  bobSignature = sp.make_signature(bob.secret_key, executionRequestBytes)
  charlieSignature = sp.make_signature(charlie.secret_key, executionRequestBytes)
  danSignature = sp.make_signature(dan.secret_key, executionRequestBytes)

  signatures = {
   bob.public_key_hash:     bobSignature, 
   charlie.public_key_hash: charlieSignature,
   dan.public_key_hash:     danSignature,
  }
  signedExecutionRequest = (signatures, executionRequest)
  now = sp.timestamp(123)
  scenario += multiSigContract.submit(signedExecutionRequest).run(
    chain_id = chainId,
    now = now
  )

  # AND a cancellation request with a bad operationId
  badOperationId = 4 # obviously wrong.
  cancellationRequest = (chainId, (badOperationId, operationId))
  cancellationRequestBytes = sp.pack(cancellationRequest)

  bobSignature = sp.make_signature(bob.secret_key, cancellationRequestBytes)
  charlieSignature = sp.make_signature(charlie.secret_key, cancellationRequestBytes)
  danSignature = sp.make_signature(dan.secret_key, cancellationRequestBytes)

  # WHEN the request is sent to the multisignature contract
  signatures = {
   bob.public_key_hash:     bobSignature, 
   charlie.public_key_hash: charlieSignature,
   dan.public_key_hash:     danSignature,
  }
  signedCancellationRequest = (signatures, cancellationRequest)
  now = sp.timestamp(123)

  # THEN the call fails.
  scenario += multiSigContract.cancel(signedCancellationRequest).run(
    chain_id = chainId,
    now = now,
    valid = False
  )

@sp.add_test(name = "cancel - fails with bad chain id")
def test():
  scenario = sp.test_scenario()

  # GIVEN a set of an accounts
  alice = sp.test_account("alice")
  bob = sp.test_account("bob")
  charlie = sp.test_account("charlie")
  dan = sp.test_account("dan")
  eve = sp.test_account("eve")

  # AND a timelock multisig with an operation loaded.
  threshhold = 3
  timelockSeconds = sp.nat(1)
  multiSigContract = MultiSigTimelock(
    threshold = threshhold,
    signers = [ alice.public_key, bob.public_key, charlie.public_key, dan.public_key, eve.public_key ],
    timelockSeconds = timelockSeconds
  )
  scenario += multiSigContract

  storeContract = Store.StoreValueContract(value = 0, admin = multiSigContract.address)
  scenario += storeContract

  chainId = sp.chain_id_cst("0x9caecab9")
  newValue = sp.nat(1)
  def updateLambda(unitParam):
    sp.set_type(unitParam, sp.TUnit)
    storeContractHandle = sp.contract(sp.TNat, storeContract.address, 'replace').open_some()
    sp.result([sp.transfer_operation(newValue, sp.mutez(0), storeContractHandle)])

  operationId = 1
  executionRequest = (chainId, (operationId, updateLambda))
  executionRequestBytes = sp.pack(executionRequest)

  bobSignature = sp.make_signature(bob.secret_key, executionRequestBytes)
  charlieSignature = sp.make_signature(charlie.secret_key, executionRequestBytes)
  danSignature = sp.make_signature(dan.secret_key, executionRequestBytes)

  signatures = {
   bob.public_key_hash:     bobSignature, 
   charlie.public_key_hash: charlieSignature,
   dan.public_key_hash:     danSignature,
  }
  signedExecutionRequest = (signatures, executionRequest)
  now = sp.timestamp(123)
  scenario += multiSigContract.submit(signedExecutionRequest).run(
    chain_id = chainId,
    now = now
  )

  # AND a cancellation request
  cancellationRequest = (chainId, (operationId + 1, operationId))
  cancellationRequestBytes = sp.pack(cancellationRequest)

  bobSignature = sp.make_signature(bob.secret_key, cancellationRequestBytes)
  charlieSignature = sp.make_signature(charlie.secret_key, cancellationRequestBytes)
  danSignature = sp.make_signature(dan.secret_key, cancellationRequestBytes)

  # WHEN the request is sent to the multisignature contract with an incorrect chain id
  # THEN the request fails.
  signatures = {
   bob.public_key_hash:     bobSignature, 
   charlie.public_key_hash: charlieSignature,
   dan.public_key_hash:     danSignature,
  }
  signedCancellationRequest = (signatures, cancellationRequest)
  now = sp.timestamp(123)
  scenario += multiSigContract.cancel(signedCancellationRequest).run(
    chain_id = sp.chain_id_cst("0x0011223344"),
    now = now,
    valid = False
  )

@sp.add_test(name = "cancel - fails with less than threshold signatures")
def test():
  scenario = sp.test_scenario()

  # GIVEN a set of an accounts
  alice = sp.test_account("alice")
  bob = sp.test_account("bob")
  charlie = sp.test_account("charlie")
  dan = sp.test_account("dan")
  eve = sp.test_account("eve")

  # AND a timelock multisig with an operation loaded.
  threshhold = 3
  timelockSeconds = sp.nat(1)
  multiSigContract = MultiSigTimelock(
    threshold = threshhold,
    signers = [ alice.public_key, bob.public_key, charlie.public_key, dan.public_key, eve.public_key ],
    timelockSeconds = timelockSeconds
  )
  scenario += multiSigContract

  storeContract = Store.StoreValueContract(value = 0, admin = multiSigContract.address)
  scenario += storeContract

  chainId = sp.chain_id_cst("0x9caecab9")
  newValue = sp.nat(1)
  def updateLambda(unitParam):
    sp.set_type(unitParam, sp.TUnit)
    storeContractHandle = sp.contract(sp.TNat, storeContract.address, 'replace').open_some()
    sp.result([sp.transfer_operation(newValue, sp.mutez(0), storeContractHandle)])

  operationId = 1
  executionRequest = (chainId, (operationId, updateLambda))
  executionRequestBytes = sp.pack(executionRequest)

  bobSignature = sp.make_signature(bob.secret_key, executionRequestBytes)
  charlieSignature = sp.make_signature(charlie.secret_key, executionRequestBytes)
  danSignature = sp.make_signature(dan.secret_key, executionRequestBytes)

  signatures = {
   bob.public_key_hash:     bobSignature, 
   charlie.public_key_hash: charlieSignature,
   dan.public_key_hash:     danSignature,
  }
  signedExecutionRequest = (signatures, executionRequest)
  now = sp.timestamp(123)
  scenario += multiSigContract.submit(signedExecutionRequest).run(
    chain_id = chainId,
    now = now
  )

  # AND a cancellation request
  cancellationRequest = (chainId, (operationId + 1, operationId))
  cancellationRequestBytes = sp.pack(cancellationRequest)

  # AND a payload is correctly signed by less than the threshold.
  bobSignature = sp.make_signature(bob.secret_key, cancellationRequestBytes)
  charlieSignature = sp.make_signature(charlie.secret_key, cancellationRequestBytes)

  #  WHEN the request is sent to the multisignature contract.
  signatures = {
   bob.public_key_hash:     bobSignature, 
   charlie.public_key_hash: charlieSignature,
  }
  signedCancellationRequest = (signatures, cancellationRequest)
  now = sp.timestamp(123)

  # THEN it fails.
  scenario += multiSigContract.cancel(signedCancellationRequest).run(
    chain_id = chainId,
    now = now,
    valid = False
  )

@sp.add_test(name = "cancel - does not count invalid signatures")
def test():
  scenario = sp.test_scenario()

  # GIVEN a set of an accounts
  alice = sp.test_account("alice")
  bob = sp.test_account("bob")
  charlie = sp.test_account("charlie")
  dan = sp.test_account("dan")
  eve = sp.test_account("eve")

  # AND a timelock multisig with an operation loaded.
  threshhold = 3
  timelockSeconds = sp.nat(1)
  multiSigContract = MultiSigTimelock(
    threshold = threshhold,
    signers = [ alice.public_key, bob.public_key, charlie.public_key],
    timelockSeconds = timelockSeconds
  )
  scenario += multiSigContract

  storeContract = Store.StoreValueContract(value = 0, admin = multiSigContract.address)
  scenario += storeContract

  chainId = sp.chain_id_cst("0x9caecab9")
  newValue = sp.nat(1)
  def updateLambda(unitParam):
    sp.set_type(unitParam, sp.TUnit)
    storeContractHandle = sp.contract(sp.TNat, storeContract.address, 'replace').open_some()
    sp.result([sp.transfer_operation(newValue, sp.mutez(0), storeContractHandle)])

  operationId = 1
  executionRequest = (chainId, (operationId, updateLambda))
  executionRequestBytes = sp.pack(executionRequest)

  aliceSignature = sp.make_signature(alice.secret_key, executionRequestBytes)
  bobSignature = sp.make_signature(bob.secret_key, executionRequestBytes)
  charlieSignature = sp.make_signature(charlie.secret_key, executionRequestBytes)

  signatures = {
    alice.public_key_hash: aliceSignature,
    bob.public_key_hash:     bobSignature,
    charlie.public_key_hash: charlieSignature
  }
  signedExecutionRequest = (signatures, executionRequest)
  now = sp.timestamp(123)
  scenario += multiSigContract.submit(signedExecutionRequest).run(
    chain_id = chainId,
    now = now
  )

  # AND a cancellation request
  cancellationRequest = (chainId, (operationId + 1, operationId))
  cancellationRequestBytes = sp.pack(cancellationRequest)

  # AND a payload is signed by 3 signatures but 2 are invalid.
  charlieSignature = sp.make_signature(charlie.secret_key, cancellationRequestBytes)
  danSignature = sp.make_signature(dan.secret_key, cancellationRequestBytes)
  eveSignature = sp.make_signature(eve.secret_key, cancellationRequestBytes)

  #  WHEN the request is sent to the multisignature contract.
  signatures = {
    charlie.public_key_hash: charlieSignature,
    dan.public_key_hash: danSignature,
    eve.public_key_hash: eveSignature,
  }
  signedCancellationRequest = (signatures, cancellationRequest)
  now = sp.timestamp(123)

  # THEN it fails.
  scenario += multiSigContract.cancel(signedCancellationRequest).run(
    chain_id = chainId,
    now = now,
    valid = False
  )

################################################################
# execute
################################################################

@sp.add_test(name = "execute - succeeds after timelock")
def test():
  scenario = sp.test_scenario()

  # GIVEN a set of an accounts
  alice = sp.test_account("alice")
  bob = sp.test_account("bob")
  charlie = sp.test_account("charlie")
  dan = sp.test_account("dan")
  eve = sp.test_account("eve")

  # AND a timelock multisig contract with a delay
  threshhold = 3
  timelockSeconds = sp.nat(1)
  multiSigContract = MultiSigTimelock(
    threshold = threshhold,
    signers = [ alice.public_key, bob.public_key, charlie.public_key, dan.public_key, eve.public_key ],
    timelockSeconds = timelockSeconds
  )
  scenario += multiSigContract

  # AND a chain id.
  chainId = sp.chain_id_cst("0x9caecab9")

  # AND a store value contract with the multisig as the admin.
  storeContract = Store.StoreValueContract(value = 0, admin = multiSigContract.address)
  scenario += storeContract

  # AND a lambda is to update the value
  newValue = sp.nat(1)
  def updateLambda(unitParam):
    sp.set_type(unitParam, sp.TUnit)
    storeContractHandle = sp.contract(sp.TNat, storeContract.address, 'replace').open_some()
    sp.result([sp.transfer_operation(newValue, sp.mutez(0), storeContractHandle)])

  # AND a payload is correctly signed by 3 parties.
  operationId = 1
  executionRequest = (chainId, (operationId, updateLambda))
  executionRequestBytes = sp.pack(executionRequest)

  bobSignature = sp.make_signature(bob.secret_key, executionRequestBytes)
  charlieSignature = sp.make_signature(charlie.secret_key, executionRequestBytes)
  danSignature = sp.make_signature(dan.secret_key, executionRequestBytes)

  #  AND the request is addded to the timelock
  signatures = {
   bob.public_key_hash:     bobSignature, 
   charlie.public_key_hash: charlieSignature,
   dan.public_key_hash:     danSignature,
  }
  signedExecutionRequest = (signatures, executionRequest)
  now = sp.timestamp(123)
  scenario += multiSigContract.submit(signedExecutionRequest).run(
    chain_id = chainId,
    now = now
  )

  # WHEN execute is called after the timelock.
  now = now.add_seconds(timelockSeconds * 2)
  scenario += multiSigContract.execute(operationId).run(
    now = now
  )

  # THEN the timelock is cleared
  scenario.verify(multiSigContract.data.timelock.contains(operationId) == False)

  # AND the value was updated.
  scenario.verify(storeContract.data.storedValue == newValue)
  
@sp.add_test(name = "execute - fails before timelock")
def test():
  scenario = sp.test_scenario()

  # GIVEN a set of an accounts
  alice = sp.test_account("alice")
  bob = sp.test_account("bob")
  charlie = sp.test_account("charlie")
  dan = sp.test_account("dan")
  eve = sp.test_account("eve")

  # AND a timelock multisig contract with a delay
  threshhold = 3
  timelockSeconds = sp.nat(1)
  multiSigContract = MultiSigTimelock(
    threshold = threshhold,
    signers = [ alice.public_key, bob.public_key, charlie.public_key, dan.public_key, eve.public_key ],
    timelockSeconds = timelockSeconds
  )
  scenario += multiSigContract

  # AND a chain id.
  chainId = sp.chain_id_cst("0x9caecab9")

  # AND a store value contract with the multisig as the admin.
  storeContract = Store.StoreValueContract(value = 0, admin = multiSigContract.address)
  scenario += storeContract

  # AND a lambda is to update the value
  newValue = sp.nat(1)
  def updateLambda(unitParam):
    sp.set_type(unitParam, sp.TUnit)
    storeContractHandle = sp.contract(sp.TNat, storeContract.address, 'replace').open_some()
    sp.result([sp.transfer_operation(newValue, sp.mutez(0), storeContractHandle)])

  # AND a payload is correctly signed by 3 parties.
  operationId = 1
  executionRequest = (chainId, (operationId, updateLambda))
  executionRequestBytes = sp.pack(executionRequest)

  bobSignature = sp.make_signature(bob.secret_key, executionRequestBytes)
  charlieSignature = sp.make_signature(charlie.secret_key, executionRequestBytes)
  danSignature = sp.make_signature(dan.secret_key, executionRequestBytes)

  #  AND the request is addded to the timelock
  signatures = {
   bob.public_key_hash:     bobSignature, 
   charlie.public_key_hash: charlieSignature,
   dan.public_key_hash:     danSignature,
  }
  signedExecutionRequest = (signatures, executionRequest)
  now = sp.timestamp(123)
  scenario += multiSigContract.submit(signedExecutionRequest).run(
    chain_id = chainId,
    now = now
  )

  # WHEN execute is called at the same time THEN it fails.
  scenario += multiSigContract.execute(operationId).run(
    now = now,
    valid = False
  )

@sp.add_test(name = "execute - executes multiple operations in the correct order")
def test():
  scenario = sp.test_scenario()

  # GIVEN a set of an accounts
  alice = sp.test_account("alice")
  bob = sp.test_account("bob")
  charlie = sp.test_account("charlie")
  dan = sp.test_account("dan")
  eve = sp.test_account("eve")

  # AND a timelock multisig contract with a delay
  threshhold = 3
  timelockSeconds = sp.nat(1)
  multiSigContract = MultiSigTimelock(
    threshold = threshhold,
    signers = [ alice.public_key, bob.public_key, charlie.public_key, dan.public_key, eve.public_key ],
    timelockSeconds = timelockSeconds
  )
  scenario += multiSigContract

  # AND a chain id.
  chainId = sp.chain_id_cst("0x9caecab9")

  # AND a store value contract with the multisig as the admin.
  storeContract = Store.StoreValueContract(value = 0, admin = multiSigContract.address)
  scenario += storeContract

  # AND a lambda is to update the value twice.
  finalValue = sp.nat(2)
  def updateLambda(unitParam):
    sp.set_type(unitParam, sp.TUnit)
    storeContractHandle = sp.contract(sp.TNat, storeContract.address, 'replace').open_some()
    sp.result([
      sp.transfer_operation(sp.nat(1), sp.mutez(0), storeContractHandle),
      sp.transfer_operation(finalValue, sp.mutez(0), storeContractHandle)
    ])

  # AND a payload is correctly signed by 3 parties.
  operationId = 1
  executionRequest = (chainId, (operationId, updateLambda))
  executionRequestBytes = sp.pack(executionRequest)

  bobSignature = sp.make_signature(bob.secret_key, executionRequestBytes)
  charlieSignature = sp.make_signature(charlie.secret_key, executionRequestBytes)
  danSignature = sp.make_signature(dan.secret_key, executionRequestBytes)

  #  AND the request is addded to the timelock
  signatures = {
   bob.public_key_hash:     bobSignature, 
   charlie.public_key_hash: charlieSignature,
   dan.public_key_hash:     danSignature,
  }
  signedExecutionRequest = (signatures, executionRequest)
  now = sp.timestamp(123)
  scenario += multiSigContract.submit(signedExecutionRequest).run(
    chain_id = chainId,
    now = now
  )

  # WHEN execute is called after the timelock.
  now = now.add_seconds(timelockSeconds * 2)
  scenario += multiSigContract.execute(operationId).run(
    now = now
  )

  # THEN the timelock is cleared
  scenario.verify(multiSigContract.data.timelock.contains(operationId) == False)

  # AND the value was updated.
  scenario.verify(storeContract.data.storedValue == finalValue)  

@sp.add_test(name = "execute - able to timelock and execute multiple operations")
def test():
  scenario = sp.test_scenario()

  # GIVEN a set of an accounts
  alice = sp.test_account("alice")
  bob = sp.test_account("bob")
  charlie = sp.test_account("charlie")
  dan = sp.test_account("dan")
  eve = sp.test_account("eve")

  # AND a timelock multisig contract with a delay
  threshhold = 3
  timelockSeconds = sp.nat(1)
  multiSigContract = MultiSigTimelock(
    threshold = threshhold,
    signers = [ alice.public_key, bob.public_key, charlie.public_key, dan.public_key, eve.public_key ],
    timelockSeconds = timelockSeconds
  )
  scenario += multiSigContract

  # AND a chain id.
  chainId = sp.chain_id_cst("0x9caecab9")

  # AND a store value contract with the multisig as the admin.
  storeContract = Store.StoreValueContract(value = 0, admin = multiSigContract.address)
  scenario += storeContract

  # AND two lambdas are provided.
  lambdaValue1 = sp.nat(1)
  def updateLambda1(unitParam):
    sp.set_type(unitParam, sp.TUnit)
    storeContractHandle = sp.contract(sp.TNat, storeContract.address, 'replace').open_some()
    sp.result([
      sp.transfer_operation(lambdaValue1, sp.mutez(0), storeContractHandle),
    ])

  lambdaValue2 = sp.nat(2)
  def updateLambda2(unitParam):
    sp.set_type(unitParam, sp.TUnit)
    storeContractHandle = sp.contract(sp.TNat, storeContract.address, 'replace').open_some()
    sp.result([
      sp.transfer_operation(lambdaValue2, sp.mutez(0), storeContractHandle),
    ])

  # AND lambda1's payload is correctly signed by 3 parties and added to the timelock
  operationId1 = 1
  executionRequest = (chainId, (operationId1, updateLambda1))
  executionRequestBytes = sp.pack(executionRequest)

  bobSignature = sp.make_signature(bob.secret_key, executionRequestBytes)
  charlieSignature = sp.make_signature(charlie.secret_key, executionRequestBytes)
  danSignature = sp.make_signature(dan.secret_key, executionRequestBytes)

  signatures = {
   bob.public_key_hash:     bobSignature, 
   charlie.public_key_hash: charlieSignature,
   dan.public_key_hash:     danSignature,
  }
  signedExecutionRequest1 = (signatures, executionRequest)
  now = sp.timestamp(123)
  scenario += multiSigContract.submit(signedExecutionRequest1).run(
    chain_id = chainId,
    now = now
  )

  # AND lambda2's payload is correctly signed by 3 parties and added to the timelock
  operationId2 = 2
  executionRequest = (chainId, (operationId2, updateLambda2))
  executionRequestBytes = sp.pack(executionRequest)

  bobSignature = sp.make_signature(bob.secret_key, executionRequestBytes)
  charlieSignature = sp.make_signature(charlie.secret_key, executionRequestBytes)
  danSignature = sp.make_signature(dan.secret_key, executionRequestBytes)

  signatures = {
   bob.public_key_hash:     bobSignature, 
   charlie.public_key_hash: charlieSignature,
   dan.public_key_hash:     danSignature,
  }
  signedExecutionRequest2 = (signatures, executionRequest)
  now = sp.timestamp(123)
  scenario += multiSigContract.submit(signedExecutionRequest2).run(
    chain_id = chainId,
    now = now
  )  

  # WHEN lambad1 is executed
  now = now.add_seconds(timelockSeconds * 2)
  scenario += multiSigContract.execute(operationId1).run(
    now = now
  )

  # THEN the first timelock is executed and the second still exists.
  scenario.verify(multiSigContract.data.timelock.contains(operationId1) == False)
  scenario.verify(multiSigContract.data.timelock.contains(operationId2) == True)

  # AND the value was updated.
  scenario.verify(storeContract.data.storedValue == lambdaValue1)  

  # WHEN lambad2 is executed
  now = now.add_seconds(timelockSeconds * 2)
  scenario += multiSigContract.execute(operationId2).run(
    now = now
  )

  # THEN the first timelock is executed and the second still exists.
  scenario.verify(multiSigContract.data.timelock.contains(operationId1) == False)
  scenario.verify(multiSigContract.data.timelock.contains(operationId2) == False)

  # AND the value was updated.
  scenario.verify(storeContract.data.storedValue == lambdaValue2)  

