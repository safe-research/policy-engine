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
  FrostSignature,
  Point,
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
/** The secp256k1 field modulus, as `Secp256k1` carries it. */
const FIELD_MODULUS = 0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2fn

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

  describe('Attestation decoding', function () {
    // The policy reads the attestation straight out of the transaction's context, so what it
    // accepts is exactly what the ABI decoder accepts.
    it('Should reject an epoch word that is not a canonical uint64', async function () {
      const { safe, safenetPolicy } = await loadFixture(fixture)

      // The attestation is eight static words. A canonical epoch word decodes, and the check gets
      // as far as looking the group key up; a word with bits set above the 64th is not a `uint64`
      // at all and is rejected inside the decoder, which reverts with no reason.
      const word = (value: bigint) => ethers.zeroPadValue(ethers.toBeHex(value), 32)
      const attestation = (epoch: bigint) =>
        ethers.concat([word(epoch), word(1n), word(0n), word(1n), word(2n), word(3n), word(4n), word(5n)])
      expect(ethers.dataLength(attestation(GENESIS_EPOCH))).to.equal(256)

      const check = (context: string) =>
        safenetPolicy.checkTransaction(safe, ZeroAddress, 0n, '0x', SafeOperation.Call, ZeroAddress, context, 0n)

      // The group key `(1, 2)` is not the genesis key, so a successful decode lands here.
      await expect(check(attestation(GENESIS_EPOCH))).to.be.revertedWithCustomError(
        safenetPolicy,
        'UntrustedAttestationKey'
      )
      await expect(check(attestation((1n << 64n) | GENESIS_EPOCH))).to.be.revertedWithoutReason()
      await expect(check(attestation(2n ** 256n - 1n))).to.be.revertedWithoutReason()
    })
  })

  describe('Epoch rollover: signature binding', function () {
    const PROPOSED_EPOCH = GENESIS_EPOCH + 1n
    const ROLLOVER_BLOCK = 1234n
    const NEW_SECRET = GROUP_SECRET + 42n

    type Rollover = {
      parentKey: Point
      parentEpoch: bigint
      proposedEpoch: bigint
      rolloverBlock: bigint
      newGroupKey: Point
    }

    // One signature over one honest rollover, reused verbatim by every case below: each tampers
    // with a single field and asserts the specific rejection, so what these establish is which
    // fields the signature binds: a field left out of the signed message would let the capture in.
    async function rolloverFixture() {
      const base = await loadFixture(fixture)
      const { safenetPolicy, testFrost, domainSeparator, groupKey } = base

      const honest: Rollover = {
        parentKey: groupKey,
        parentEpoch: GENESIS_EPOCH,
        proposedEpoch: PROPOSED_EPOCH,
        rolloverBlock: ROLLOVER_BLOCK,
        newGroupKey: pointFromScalar(NEW_SECRET)
      }
      const message = epochRolloverMessage(
        domainSeparator,
        honest.parentEpoch,
        honest.proposedEpoch,
        honest.rolloverBlock,
        honest.newGroupKey
      )
      const { signature } = await signFrost(testFrost, GROUP_SECRET, 0xfeedn, message)

      const submit = (rollover: Rollover, sig: FrostSignature = signature) =>
        safenetPolicy.updateEpoch(
          rollover.parentKey,
          rollover.parentEpoch,
          rollover.proposedEpoch,
          rollover.rolloverBlock,
          rollover.newGroupKey,
          sig
        )

      return { ...base, honest, submit }
    }

    it('Should reject a captured signature re-pointed at another group key', async function () {
      const { safenetPolicy, honest, submit } = await rolloverFixture()

      const keys: [string, Point][] = [
        ['another valid successor key', pointFromScalar(NEW_SECRET + 1n)],
        ['the parent key itself', honest.parentKey],
        // The negation shares `x` and differs only in `y`, so binding `x` alone would let it pass.
        ['the negation of the signed key', { x: honest.newGroupKey.x, y: FIELD_MODULUS - honest.newGroupKey.y }]
      ]

      for (const [name, newGroupKey] of keys) {
        await expect(submit({ ...honest, newGroupKey }), name).to.be.revertedWithCustomError(
          safenetPolicy,
          'InvalidMulMulAddWitness'
        )
        expect(await safenetPolicy.isKnownEpoch(newGroupKey, honest.proposedEpoch), name).to.equal(false)
      }

      // Nor is the honest pair recorded: no half of the write survived a rejection.
      expect(await safenetPolicy.isKnownEpoch(honest.newGroupKey, honest.proposedEpoch)).to.equal(false)
    })

    it('Should reject a captured signature re-pointed at another proposed epoch', async function () {
      const { safenetPolicy, honest, submit } = await rolloverFixture()

      // Every value here is greater than the parent epoch, so the advance check is not what
      // rejects them.
      for (const proposedEpoch of [honest.proposedEpoch + 1n, honest.proposedEpoch + 100n, 2n ** 64n - 1n]) {
        await expect(submit({ ...honest, proposedEpoch }), `epoch ${proposedEpoch}`).to.be.revertedWithCustomError(
          safenetPolicy,
          'InvalidMulMulAddWitness'
        )
        expect(await safenetPolicy.isKnownEpoch(honest.newGroupKey, proposedEpoch)).to.equal(false)
      }
    })

    it('Should reject a captured signature re-pointed at another rollover block', async function () {
      const { safenetPolicy, honest, submit } = await rolloverFixture()

      // The rollover block is folded into the signed message but never read afterwards. Unchecked
      // is not unbound: it is inside the struct hash, so tampering with it invalidates the
      // signature all the same.
      for (const rolloverBlock of [honest.rolloverBlock + 1n, 0n, 2n ** 64n - 1n]) {
        await expect(submit({ ...honest, rolloverBlock }), `block ${rolloverBlock}`).to.be.revertedWithCustomError(
          safenetPolicy,
          'InvalidMulMulAddWitness'
        )
      }
      expect(await safenetPolicy.isKnownEpoch(honest.newGroupKey, honest.proposedEpoch)).to.equal(false)
    })

    it('Should reject a rollover signed for another Consensus deployment', async function () {
      const { safenetPolicy, testFrost, honest, submit } = await rolloverFixture()

      // The same fields and the same signer, but another `verifyingContract` or chain id: a
      // rollover of a different deployment, replayed here.
      const separators: [string, string][] = [
        [
          'another Consensus address',
          consensusDomainSeparator(CONSENSUS_CHAIN_ID, '0x2222222222222222222222222222222222222222')
        ],
        ['another Consensus chain', consensusDomainSeparator(CONSENSUS_CHAIN_ID + 1n, CONSENSUS_ADDRESS)]
      ]

      for (const [name, domainSeparator] of separators) {
        const message = epochRolloverMessage(
          domainSeparator,
          honest.parentEpoch,
          honest.proposedEpoch,
          honest.rolloverBlock,
          honest.newGroupKey
        )
        const { signature } = await signFrost(testFrost, GROUP_SECRET, 0xfeedn, message)
        await expect(submit(honest, signature), name).to.be.revertedWithCustomError(
          safenetPolicy,
          'InvalidMulMulAddWitness'
        )
      }
      expect(await safenetPolicy.isKnownEpoch(honest.newGroupKey, honest.proposedEpoch)).to.equal(false)
    })

    it('Should reject a tampered parent epoch and a non-advancing epoch ahead of the signature', async function () {
      const { safenetPolicy, honest, submit } = await rolloverFixture()

      // The parent epoch is bound too, but the `(parentKey, parentEpoch)` lookup runs first, so a
      // tampered parent epoch is rejected there rather than by the signature check.
      for (const parentEpoch of [honest.parentEpoch + 1n, honest.parentEpoch - 1n, 0n]) {
        await expect(
          submit({ ...honest, parentEpoch, proposedEpoch: parentEpoch + 1n }),
          `parent ${parentEpoch}`
        ).to.be.revertedWithCustomError(safenetPolicy, 'UnknownParent')
      }

      // The strict-advance guard is likewise ahead of the signature check.
      for (const proposedEpoch of [honest.parentEpoch, honest.parentEpoch - 1n, 0n]) {
        await expect(submit({ ...honest, proposedEpoch }), `proposed ${proposedEpoch}`).to.be.revertedWithCustomError(
          safenetPolicy,
          'EpochNotAdvancing'
        )
      }

      expect(await safenetPolicy.isKnownEpoch(honest.newGroupKey, honest.proposedEpoch)).to.equal(false)
    })

    it('Should still accept the honest rollover after every rejected variant', async function () {
      const { safenetPolicy, honest, submit } = await rolloverFixture()

      // The control for all of the above: the rejections were the tampering, and not a fixture
      // that could never have recorded anything.
      await expect(submit({ ...honest, proposedEpoch: honest.proposedEpoch + 1n })).to.be.reverted
      await expect(submit({ ...honest, rolloverBlock: 0n })).to.be.reverted
      await expect(submit({ ...honest, newGroupKey: pointFromScalar(NEW_SECRET + 1n) })).to.be.reverted

      await submit(honest)
      expect(await safenetPolicy.isKnownEpoch(honest.newGroupKey, honest.proposedEpoch)).to.equal(true)
      // The pair recorded is exact, not a range around it.
      expect(await safenetPolicy.isKnownEpoch(honest.newGroupKey, honest.proposedEpoch + 1n)).to.equal(false)
    })
  })

  describe('Curve checks', function () {
    // Two curve points with one small coordinate, so that coordinate plus the field modulus still
    // fits in a `uint256` -- the window above the modulus is only about 4.3e9 wide.
    const SMALL_X: Point = { x: 1n, y: 0x4218f20ae6c646b363db68605822fb14264ca8d2587fdd6fbc750d587e76a7een }
    const SMALL_Y: Point = { x: 0x1fe1e5ef3fceb5c135ab7741333ce5a6e80d68167653f6b2b24bcbcfaaaff507n, y: 1n }

    const onCurve = (p: Point) =>
      (p.y * p.y - (p.x * p.x * p.x + 7n)) % FIELD_MODULUS === 0n && p.x < FIELD_MODULUS && p.y < FIELD_MODULUS

    const deployWith = async (groupKey: Point) => {
      const factory = await ethers.getContractFactory('SafenetPolicy')
      return factory.deploy(CONSENSUS_CHAIN_ID, CONSENSUS_ADDRESS, GENESIS_EPOCH, groupKey)
    }

    it('Should reject a non-zero genesis group key that is off the curve', async function () {
      const factory = await ethers.getContractFactory('SafenetPolicy')

      // None of these is the zero point, which is the one off-curve value the unpacking exempts,
      // so each has to be caught by the curve equation itself.
      const offCurve: [string, Point][] = [
        ['both coordinates one', { x: 1n, y: 1n }],
        ['a zero y', { x: 1n, y: 0n }],
        ['a zero x', { x: 0n, y: 1n }],
        ['a curve point with y + 1', { x: SMALL_X.x, y: SMALL_X.y + 1n }],
        ['a curve point with x + 1', { x: SMALL_X.x + 1n, y: SMALL_X.y }]
      ]

      for (const [name, groupKey] of offCurve) {
        expect(groupKey.x !== 0n || groupKey.y !== 0n, name).to.equal(true)
        await expect(deployWith(groupKey), name).to.be.revertedWithCustomError(factory, 'NotOnCurve')
      }
    })

    it('Should reject a genesis coordinate that is not reduced modulo the field prime', async function () {
      const factory = await ethers.getContractFactory('SafenetPolicy')

      expect(onCurve(SMALL_X)).to.equal(true)
      expect(onCurve(SMALL_Y)).to.equal(true)
      // Both are accepted as they are, so the rejections below isolate the shift.
      await deployWith(SMALL_X)
      await deployWith(SMALL_Y)

      // Modular arithmetic is unchanged by adding the modulus, so only a range check can reject
      // these: the curve equation still holds for both.
      const shifted: [string, Point][] = [
        ['x above the modulus', { x: SMALL_X.x + FIELD_MODULUS, y: SMALL_X.y }],
        ['y above the modulus', { x: SMALL_Y.x, y: SMALL_Y.y + FIELD_MODULUS }]
      ]
      for (const [name, groupKey] of shifted) {
        expect((groupKey.y * groupKey.y - (groupKey.x * groupKey.x * groupKey.x + 7n)) % FIELD_MODULUS, name).to.equal(
          0n
        )
        await expect(deployWith(groupKey), name).to.be.revertedWithCustomError(factory, 'NotOnCurve')
      }
    })

    it('Should accept a genuine curve point and its negation as the genesis key', async function () {
      const generated = pointFromScalar(GROUP_SECRET)

      // The negation shares `x`, so accepting both is what shows the check is on the equation and
      // not on some property of one coordinate.
      const accepted: [string, Point][] = [
        ['the group key', generated],
        ['its negation', { x: generated.x, y: FIELD_MODULUS - generated.y }],
        ['a small-x curve point', SMALL_X],
        ['a small-y curve point', SMALL_Y]
      ]

      for (const [name, groupKey] of accepted) {
        const deployed = await deployWith(groupKey)
        expect(await deployed.isKnownEpoch(groupKey, GENESIS_EPOCH), name).to.equal(true)
      }
    })

    it('Should reject an off-curve new group key before verifying the signature', async function () {
      const { safenetPolicy, testFrost, domainSeparator, groupKey } = await loadFixture(fixture)

      const proposedEpoch = GENESIS_EPOCH + 1n
      const rolloverBlock = 1234n
      // A well-formed signature over the honest message, so a rejection below is the curve check
      // and not a signature failure.
      const newGroupKey = pointFromScalar(GROUP_SECRET + 42n)
      const message = epochRolloverMessage(domainSeparator, GENESIS_EPOCH, proposedEpoch, rolloverBlock, newGroupKey)
      const { signature } = await signFrost(testFrost, GROUP_SECRET, 0xfeedn, message)

      const offCurve: [string, Point][] = [
        ['both coordinates one', { x: 1n, y: 1n }],
        ['a zero y', { x: 1n, y: 0n }],
        ['a curve point above the modulus', { x: SMALL_X.x + FIELD_MODULUS, y: SMALL_X.y }],
        // Unlike the unpacking, this call site has no exemption for the zero point.
        ['the zero point', { x: 0n, y: 0n }]
      ]

      for (const [name, bad] of offCurve) {
        await expect(
          safenetPolicy.updateEpoch(groupKey, GENESIS_EPOCH, proposedEpoch, rolloverBlock, bad, signature),
          name
        ).to.be.revertedWithCustomError(safenetPolicy, 'NotOnCurve')
        expect(await safenetPolicy.isKnownEpoch(bad, proposedEpoch), name).to.equal(false)
      }

      // Control: the same call with the key the signature was made over is recorded.
      await safenetPolicy.updateEpoch(groupKey, GENESIS_EPOCH, proposedEpoch, rolloverBlock, newGroupKey, signature)
      expect(await safenetPolicy.isKnownEpoch(newGroupKey, proposedEpoch)).to.equal(true)
    })

    it('Should reject a signature commitment that is off the curve', async function () {
      const { safenetPolicy, testFrost, domainSeparator, groupKey } = await loadFixture(fixture)

      const proposedEpoch = GENESIS_EPOCH + 1n
      const newGroupKey = pointFromScalar(GROUP_SECRET + 42n)
      const message = epochRolloverMessage(domainSeparator, GENESIS_EPOCH, proposedEpoch, 0n, newGroupKey)
      const { signature } = await signFrost(testFrost, GROUP_SECRET, 0xfeedn, message)

      const rollover = (r: Point) =>
        safenetPolicy.updateEpoch(groupKey, GENESIS_EPOCH, proposedEpoch, 0n, newGroupKey, { r, z: signature.z })

      await expect(rollover({ x: 1n, y: 1n })).to.be.revertedWithCustomError(safenetPolicy, 'NotOnCurve')
      await expect(rollover({ x: SMALL_X.x + FIELD_MODULUS, y: SMALL_X.y })).to.be.revertedWithCustomError(
        safenetPolicy,
        'NotOnCurve'
      )
      // The commitment is serialized into the challenge before it is ever unpacked, and that is
      // where the zero point dies -- so the unpacking's exemption for it is unreachable from here.
      await expect(rollover({ x: 0n, y: 0n })).to.be.revertedWithCustomError(safenetPolicy, 'NotOnCurve')

      // The contrast: a commitment that is a curve point, but the wrong one, passes every curve
      // check and fails at the group-equation comparison instead.
      await expect(rollover(pointFromScalar(0xbeefn))).to.be.revertedWithCustomError(
        safenetPolicy,
        'InvalidMulMulAddWitness'
      )

      expect(await safenetPolicy.isKnownEpoch(newGroupKey, proposedEpoch)).to.equal(false)
    })
  })
})
