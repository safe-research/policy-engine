import { loadFixture } from '@nomicfoundation/hardhat-network-helpers'
import { expect } from 'chai'
import { ZeroAddress } from 'ethers'
import { ethers } from 'hardhat'

import {
  buildMultiSendSafeTx,
  buildSafeTransaction,
  createConfiguration,
  createSafe,
  enableGuard,
  execTransaction,
  randomAddress,
  SafeOperation
} from '../src/utils'
import { Safe, TestFROST } from '../typechain-types'
import { deployMultiSendPolicy, deploySafeContracts, deploySafePolicyGuard, deploySafenetPolicy } from './deploy'
import {
  consensusDomainSeparator,
  encodeAttestation,
  epochRolloverMessage,
  pointFromScalar,
  signFrost,
  transactionProposalMessage,
  DOMAIN_TYPEHASH,
  EPOCH_ROLLOVER_TYPEHASH,
  TRANSACTION_PROPOSAL_TYPEHASH
} from './utils/frost'

// An arbitrary Consensus deployment the attestations are bound to; Safenet's own Consensus lives on
// Gnosis Chain, and only its address and chain ID reach the policy.
const CONSENSUS_CHAIN_ID = 100n
const CONSENSUS_ADDRESS = '0x1111111111111111111111111111111111111111'
const GENESIS_EPOCH = 7n
const GROUP_SECRET = 0x5afe5afe5afe5afe5afe5afe5afe5afe5afe5afe5afe5afe5afe5afe5afe5afen

describe('SafenetPolicy', function () {
  async function fixture() {
    const [, owner, other] = await ethers.getSigners()

    const { safePolicyGuard } = await deploySafePolicyGuard()
    const { safeProxyFactory, safe: safeSingleton, multiSend } = await deploySafeContracts()
    const safe = await createSafe({
      owners: [owner],
      guard: ZeroAddress, // No guard at this point
      saltNonce: BigInt(0xd),
      safeProxyFactory,
      singleton: safeSingleton
    })

    const groupKey = pointFromScalar(GROUP_SECRET)
    const { safenetPolicy } = await deploySafenetPolicy({
      consensusChainId: CONSENSUS_CHAIN_ID,
      consensusAddress: CONSENSUS_ADDRESS,
      initialEpoch: GENESIS_EPOCH,
      initialGroupKey: groupKey
    })
    const { multiSendPolicy } = await deployMultiSendPolicy()
    const testFrost = (await (await ethers.getContractFactory('TestFROST')).deploy()) as unknown as TestFROST

    const domainSeparator = consensusDomainSeparator(CONSENSUS_CHAIN_ID, CONSENSUS_ADDRESS)

    await owner.sendTransaction({ to: await safe.getAddress(), value: ethers.parseEther('10') })

    return {
      owner,
      other,
      safe,
      safePolicyGuard,
      safenetPolicy,
      multiSend,
      multiSendPolicy,
      testFrost,
      groupKey,
      domainSeparator
    }
  }

  /**
   * Attests a plain value transfer at the Safe's current nonce and returns the policy context.
   */
  async function attestTransfer({
    safe,
    testFrost,
    domainSeparator,
    to,
    value,
    secret = GROUP_SECRET,
    epoch = GENESIS_EPOCH,
    nonceOffset = 0n
  }: {
    safe: Safe
    testFrost: TestFROST
    domainSeparator: string
    to: string
    value: bigint
    secret?: bigint
    epoch?: bigint
    nonceOffset?: bigint
  }) {
    const nonce = (await safe.nonce()) + nonceOffset
    const safeTxHash = await safe.getTransactionHash(
      to,
      value,
      '0x',
      SafeOperation.Call,
      0,
      0,
      0,
      ZeroAddress,
      ZeroAddress,
      nonce
    )
    const oracle = randomAddress()
    const oracleDataHash = ethers.id('oracle-data')
    const message = transactionProposalMessage(domainSeparator, epoch, oracle, oracleDataHash, safeTxHash)
    const { groupKey, signature } = await signFrost(testFrost, secret, 0x1234abcdn, message)
    return encodeAttestation({ epoch, oracle, oracleDataHash, groupKey, signature })
  }

  describe('Consensus message derivation', function () {
    it('Should match the type hashes the library carries as literals', async function () {
      expect(DOMAIN_TYPEHASH).to.equal('0x47e79534a245952e8b16893a336b85a3d9ea9fa8c573f3d803afb92a79469218')
      expect(EPOCH_ROLLOVER_TYPEHASH).to.equal('0x13de01993286119c9a7628720a5b7d7c32841dbf2d23752b59de86a7e03fe1bf')
      expect(TRANSACTION_PROPOSAL_TYPEHASH).to.equal(
        '0x9c6706f5afdb1de99f5ad39011e7770ce471f51d78380634f6cedb21a648b8d0'
      )
    })

    it('Should derive the same domain separator as the policy', async function () {
      const { safenetPolicy, domainSeparator } = await loadFixture(fixture)
      expect(await safenetPolicy.getConsensusDomainSeparator()).to.equal(domainSeparator)
    })

    it('Should seed the genesis epoch and reject any other pair', async function () {
      const { safenetPolicy, groupKey } = await loadFixture(fixture)
      expect(await safenetPolicy.isKnownEpoch(groupKey, GENESIS_EPOCH)).to.equal(true)
      expect(await safenetPolicy.isKnownEpoch(groupKey, GENESIS_EPOCH + 1n)).to.equal(false)
      expect(await safenetPolicy.isKnownEpoch(pointFromScalar(2n), GENESIS_EPOCH)).to.equal(false)
    })
  })

  describe('Integration with SafePolicyGuard', function () {
    it('Should allow a transaction carrying a valid attestation', async function () {
      const { owner, safePolicyGuard, safe, safenetPolicy, testFrost, domainSeparator } = await loadFixture(fixture)

      const recipient = randomAddress()
      const value = ethers.parseEther('1')

      await enableGuard({
        owners: [owner],
        safe,
        safePolicyGuard,
        configurations: [createConfiguration({ policy: await safenetPolicy.getAddress() })]
      })

      const nonce = await safe.nonce()
      const context = await attestTransfer({ safe, testFrost, domainSeparator, to: recipient, value })

      await execTransaction({ owners: [owner], safe, to: recipient, value, additionalData: context })

      expect(await ethers.provider.getBalance(recipient)).to.equal(value)
      expect(await safenetPolicy.isAttestationSpent(safePolicyGuard, safe, nonce)).to.equal(true)
    })

    it('Should reject a transaction with no attestation', async function () {
      const { owner, safePolicyGuard, safe, safenetPolicy } = await loadFixture(fixture)

      await enableGuard({
        owners: [owner],
        safe,
        safePolicyGuard,
        configurations: [createConfiguration({ policy: await safenetPolicy.getAddress() })]
      })

      await expect(
        execTransaction({ owners: [owner], safe, to: randomAddress(), value: ethers.parseEther('1') })
      ).to.be.revertedWithCustomError(safePolicyGuard, 'PolicyReverted')
    })

    it('Should reject an attestation from an untrusted group key', async function () {
      const { owner, safePolicyGuard, safe, safenetPolicy, testFrost, domainSeparator } = await loadFixture(fixture)

      const recipient = randomAddress()
      const value = ethers.parseEther('1')

      await enableGuard({
        owners: [owner],
        safe,
        safePolicyGuard,
        configurations: [createConfiguration({ policy: await safenetPolicy.getAddress() })]
      })

      // Correctly signed, but by a key that was never recorded in the trusted forest.
      const context = await attestTransfer({
        safe,
        testFrost,
        domainSeparator,
        to: recipient,
        value,
        secret: GROUP_SECRET + 1n
      })

      await expect(
        execTransaction({ owners: [owner], safe, to: recipient, value, additionalData: context })
      ).to.be.revertedWithCustomError(safePolicyGuard, 'PolicyReverted')

      expect(await ethers.provider.getBalance(recipient)).to.equal(0n)
    })

    it('Should reject an attestation bound to a different transaction', async function () {
      const { owner, safePolicyGuard, safe, safenetPolicy, testFrost, domainSeparator } = await loadFixture(fixture)

      const value = ethers.parseEther('1')
      const attested = randomAddress()
      const actual = randomAddress()

      await enableGuard({
        owners: [owner],
        safe,
        safePolicyGuard,
        configurations: [createConfiguration({ policy: await safenetPolicy.getAddress() })]
      })

      const context = await attestTransfer({ safe, testFrost, domainSeparator, to: attested, value })

      // The signature is valid, but over the hash of a transfer to a different recipient.
      await expect(
        execTransaction({ owners: [owner], safe, to: actual, value, additionalData: context })
      ).to.be.revertedWithCustomError(safePolicyGuard, 'PolicyReverted')

      expect(await ethers.provider.getBalance(actual)).to.equal(0n)
    })

    it('Should not bind the refund parameters', async function () {
      // A known and accepted limitation: the policy interface does not carry `baseGas`, `gasToken`
      // or `refundReceiver`, so the derived hash is the same whatever they hold and an attestation
      // taken for an ordinary transaction also authorises a variant that sets them. Harmless only
      // because the guard requires `gasPrice == 0`, under which the Safe skips `handlePayment` and
      // none of the three can move value. Pinned so that supporting refunds breaks this test.
      const { owner, safePolicyGuard, safe, safenetPolicy, testFrost, domainSeparator } = await loadFixture(fixture)

      const recipient = randomAddress()
      const value = ethers.parseEther('1')

      await enableGuard({
        owners: [owner],
        safe,
        safePolicyGuard,
        configurations: [createConfiguration({ policy: await safenetPolicy.getAddress() })]
      })

      const context = await attestTransfer({ safe, testFrost, domainSeparator, to: recipient, value })

      await execTransaction({
        owners: [owner],
        safe,
        to: recipient,
        value,
        baseGas: 1,
        refundReceiver: randomAddress(),
        additionalData: context
      })

      expect(await ethers.provider.getBalance(recipient)).to.equal(value)
    })

    it('Should reject a context that is not a well-formed attestation', async function () {
      const { owner, safePolicyGuard, safe, safenetPolicy } = await loadFixture(fixture)

      await enableGuard({
        owners: [owner],
        safe,
        safePolicyGuard,
        configurations: [createConfiguration({ policy: await safenetPolicy.getAddress() })]
      })

      await expect(
        execTransaction({
          owners: [owner],
          safe,
          to: randomAddress(),
          value: ethers.parseEther('1'),
          additionalData: ethers.hexlify(ethers.randomBytes(128))
        })
      ).to.be.revertedWithCustomError(safePolicyGuard, 'PolicyReverted')
    })
  })

  describe('Replay', function () {
    it('Should authorise at most one check per Safe nonce', async function () {
      const { owner, safePolicyGuard, safe, safenetPolicy, multiSend, multiSendPolicy, testFrost, domainSeparator } =
        await loadFixture(fixture)

      const recipient = randomAddress()
      const value = ethers.parseEther('1')
      const multiSendSelector = multiSend.interface.getFunction('multiSend')?.selector

      // Combining the two is explicitly unsupported; this pins that it fails closed rather than
      // letting one attestation authorise every sub-transaction in a batch.
      await enableGuard({
        owners: [owner],
        safe,
        safePolicyGuard,
        configurations: [
          createConfiguration({ policy: await safenetPolicy.getAddress() }),
          createConfiguration({
            target: await multiSend.getAddress(),
            selector: multiSendSelector,
            operation: SafeOperation.DelegateCall,
            policy: await multiSendPolicy.getAddress()
          })
        ]
      })

      const nonce = await safe.nonce()
      const context = await attestTransfer({ safe, testFrost, domainSeparator, to: recipient, value })
      const transfer = buildSafeTransaction({ to: recipient, value, data: '0x', nonce })
      const multiSendTx = await buildMultiSendSafeTx(multiSend, [transfer, transfer], nonce)
      const repeated = ethers.solidityPacked(
        ['uint256', 'bytes', 'uint256', 'bytes'],
        [ethers.dataLength(context), context, ethers.dataLength(context), context]
      )

      await expect(
        execTransaction({
          owners: [owner],
          safe,
          to: await multiSend.getAddress(),
          data: multiSendTx.data,
          operation: SafeOperation.DelegateCall,
          additionalData: repeated
        })
      ).to.be.revertedWithCustomError(safePolicyGuard, 'PolicyReverted')

      expect(await ethers.provider.getBalance(recipient)).to.equal(0n)
    })
  })

  describe('Module path', function () {
    it('Should reject the module path outright', async function () {
      const { safe, safenetPolicy } = await loadFixture(fixture)

      // The engine sources `module` itself, so this is asserted directly against the policy.
      await expect(
        safenetPolicy.checkTransaction(safe, randomAddress(), 0n, '0x', SafeOperation.Call, randomAddress(), '0x', 0n)
      ).to.be.revertedWithCustomError(safenetPolicy, 'ModulePathUnsupported')
    })
  })

  describe('Epoch rollover', function () {
    it('Should record a new epoch from a rollover signed by the trusted group', async function () {
      const { safenetPolicy, testFrost, domainSeparator, groupKey } = await loadFixture(fixture)

      const newSecret = GROUP_SECRET + 42n
      const newGroupKey = pointFromScalar(newSecret)
      const proposedEpoch = GENESIS_EPOCH + 1n
      const rolloverBlock = 1234n

      const message = epochRolloverMessage(domainSeparator, GENESIS_EPOCH, proposedEpoch, rolloverBlock, newGroupKey)
      const { signature } = await signFrost(testFrost, GROUP_SECRET, 0xfeedn, message)

      await safenetPolicy.updateEpoch(groupKey, GENESIS_EPOCH, proposedEpoch, rolloverBlock, newGroupKey, signature)

      expect(await safenetPolicy.isKnownEpoch(newGroupKey, proposedEpoch)).to.equal(true)
    })

    it('Should reject a rollover signed by an unknown parent', async function () {
      const { safenetPolicy, testFrost, domainSeparator } = await loadFixture(fixture)

      const rogueSecret = GROUP_SECRET + 1n
      const rogueKey = pointFromScalar(rogueSecret)
      const newGroupKey = pointFromScalar(GROUP_SECRET + 42n)
      const proposedEpoch = GENESIS_EPOCH + 1n

      const message = epochRolloverMessage(domainSeparator, GENESIS_EPOCH, proposedEpoch, 0n, newGroupKey)
      const { signature } = await signFrost(testFrost, rogueSecret, 0xfeedn, message)

      await expect(
        safenetPolicy.updateEpoch(rogueKey, GENESIS_EPOCH, proposedEpoch, 0n, newGroupKey, signature)
      ).to.be.revertedWithCustomError(safenetPolicy, 'UnknownParent')

      expect(await safenetPolicy.isKnownEpoch(newGroupKey, proposedEpoch)).to.equal(false)
    })
  })

  describe('Deployment', function () {
    it('Should reject a zero Consensus address', async function () {
      const factory = await ethers.getContractFactory('SafenetPolicy')
      await expect(
        factory.deploy(CONSENSUS_CHAIN_ID, ZeroAddress, GENESIS_EPOCH, pointFromScalar(GROUP_SECRET))
      ).to.be.revertedWithCustomError(factory, 'InvalidAddress')
    })

    it('Should reject a genesis group key that is not a curve point', async function () {
      const factory = await ethers.getContractFactory('SafenetPolicy')
      await expect(
        factory.deploy(CONSENSUS_CHAIN_ID, CONSENSUS_ADDRESS, GENESIS_EPOCH, { x: 0n, y: 0n })
      ).to.be.revertedWithCustomError(factory, 'NotOnCurve')
    })
  })
})
