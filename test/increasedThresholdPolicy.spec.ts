import { loadFixture } from '@nomicfoundation/hardhat-network-helpers'
import { expect } from 'chai'
import { Signer, ZeroAddress } from 'ethers'
import { ethers } from 'hardhat'

import {
  buildMultiSendSafeTx,
  buildSafeTransaction,
  buildSignatureBytes,
  calculateSafeMessageHash,
  createConfiguration,
  createSafe,
  enableGuard,
  encodeIncreasedThresholdConfig,
  execTransaction,
  preApprovedSignature,
  randomAddress,
  safeSignTypedData,
  SafeOperation,
  SafeSignature
} from '../src/utils'
import { Safe } from '../typechain-types'
import {
  deployIncreasedThresholdPolicy,
  deployMultiSendPolicy,
  deploySafeContracts,
  deploySafePolicyGuard
} from './deploy'

describe('IncreasedThresholdPolicy', function () {
  // A 4-owner, 2-of-4 Safe, so `threshold + 1` and `owners - maxAbsent` can differ.
  async function fixture() {
    const [, owner, second, third, fourth] = await ethers.getSigners()
    const owners = [owner, second, third, fourth]

    const { safePolicyGuard } = await deploySafePolicyGuard()
    const { safeProxyFactory, safe: safeSingleton, multiSend } = await deploySafeContracts()
    const safe = await createSafe({
      owners,
      threshold: 2,
      guard: ZeroAddress, // No guard at this point
      saltNonce: BigInt(0xe),
      safeProxyFactory,
      singleton: safeSingleton
    })

    const { increasedThresholdPolicy } = await deployIncreasedThresholdPolicy()
    const { multiSendPolicy } = await deployMultiSendPolicy()
    const accessSelector = await (await ethers.getContractFactory('TestAccessSelector')).deploy()

    await owner.sendTransaction({ to: await safe.getAddress(), value: ethers.parseEther('10') })

    return {
      owner,
      owners,
      safe,
      safePolicyGuard,
      increasedThresholdPolicy,
      multiSend,
      multiSendPolicy,
      accessSelector,
      safeProxyFactory,
      safeSingleton
    }
  }

  /** Signs the pending transaction with `signers` and packs it as policy context. */
  async function signAsContext(safe: Safe, signers: Signer[], to: string, value: bigint) {
    const safeTx = buildSafeTransaction({ to, value, data: '0x', nonce: await safe.nonce() })
    const safeAddress = await safe.getAddress()
    const signatures = await Promise.all(signers.map((signer) => safeSignTypedData(signer, safeAddress, safeTx)))
    return buildSignatureBytes(signatures)
  }

  describe('Required signatures', function () {
    it('Should require all but maxAbsent owners, floored at threshold + 1', async function () {
      const { owner, owners, safe, increasedThresholdPolicy, accessSelector } = await loadFixture(fixture)

      const target = randomAddress()
      const access = await accessSelector.create(target, '0x00000000', SafeOperation.Call)

      // 4 owners, threshold 2, so `min(4, 3) = 3` is the floor from the elevated threshold.
      const cases = [
        { maxAbsent: 0, expected: 4n }, // max(3, 4 - 0) = 4, every owner
        { maxAbsent: 1, expected: 3n }, // max(3, 4 - 1) = 3
        { maxAbsent: 2, expected: 3n }, // max(3, 4 - 2) = 3, elevated threshold wins
        { maxAbsent: 9, expected: 3n } // subtraction saturates, leaving threshold + 1
      ]

      for (const { maxAbsent, expected } of cases) {
        await increasedThresholdPolicy.connect(owner).configure(safe, access, encodeIncreasedThresholdConfig(maxAbsent))
        expect(await increasedThresholdPolicy.getRequiredSignatures(owner, safe, access)).to.equal(expected)
        expect(await increasedThresholdPolicy.getMaxAbsentOwners(owner, safe, access)).to.equal(BigInt(maxAbsent))
      }

      // Never more than the owner count, so the requirement is always satisfiable.
      expect(cases.every(({ expected }) => expected <= BigInt(owners.length))).to.equal(true)
    })

    it('Should cap the requirement at the owner count for an N-of-N Safe', async function () {
      // `threshold + 1` exceeds the owner count here, so the upper clamp is what keeps the
      // requirement satisfiable -- it degrades to "every owner", the strongest available.
      const { owners, increasedThresholdPolicy, accessSelector, safeProxyFactory, safeSingleton } =
        await loadFixture(fixture)

      const allOwners = owners.slice(0, 3)
      const nOfN = await createSafe({
        owners: allOwners,
        threshold: allOwners.length,
        guard: ZeroAddress,
        saltNonce: BigInt(0xf),
        safeProxyFactory,
        singleton: safeSingleton
      })
      const access = await accessSelector.create(randomAddress(), '0x00000000', SafeOperation.Call)
      const [configurer] = allOwners

      for (const maxAbsent of [0, 1, 5]) {
        await increasedThresholdPolicy
          .connect(configurer)
          .configure(nOfN, access, encodeIncreasedThresholdConfig(maxAbsent))
        expect(await increasedThresholdPolicy.getRequiredSignatures(configurer, nOfN, access)).to.equal(
          BigInt(allOwners.length)
        )
      }
    })

    it('Should demand every owner for an unconfigured access selector', async function () {
      const { owner, safe, increasedThresholdPolicy, accessSelector } = await loadFixture(fixture)

      const access = await accessSelector.create(randomAddress(), '0x00000000', SafeOperation.Call)
      // Nothing configured reads `maxAbsent` as 0, which demands all four owners.
      expect(await increasedThresholdPolicy.getRequiredSignatures(owner, safe, access)).to.equal(4n)
    })
  })

  describe('Integration with SafePolicyGuard', function () {
    it('Should allow a transaction carrying the required signatures', async function () {
      const { owners, safe, safePolicyGuard, increasedThresholdPolicy } = await loadFixture(fixture)

      const target = randomAddress()
      const value = ethers.parseEther('1')

      await enableGuard({
        owners,
        safe,
        safePolicyGuard,
        configurations: [
          createConfiguration({
            target,
            policy: await increasedThresholdPolicy.getAddress(),
            data: encodeIncreasedThresholdConfig(1) // requires 3 of 4
          })
        ]
      })

      const context = await signAsContext(safe, owners.slice(0, 3), target, value)
      await execTransaction({
        owners: owners.slice(0, 3),
        safe,
        to: target,
        value,
        additionalData: context,
        signingMethod: 'signMessage'
      })

      expect(await ethers.provider.getBalance(target)).to.equal(value)
    })

    it('Should reject a transaction carrying only the Safe threshold', async function () {
      const { owners, safe, safePolicyGuard, increasedThresholdPolicy } = await loadFixture(fixture)

      const target = randomAddress()
      const value = ethers.parseEther('1')

      await enableGuard({
        owners,
        safe,
        safePolicyGuard,
        configurations: [
          createConfiguration({
            target,
            policy: await increasedThresholdPolicy.getAddress(),
            data: encodeIncreasedThresholdConfig(1) // requires 3 of 4
          })
        ]
      })

      // Two signatures satisfy the Safe itself, but not the elevated requirement.
      const context = await signAsContext(safe, owners.slice(0, 2), target, value)
      await expect(
        execTransaction({
          owners: owners.slice(0, 2),
          safe,
          to: target,
          value,
          additionalData: context,
          signingMethod: 'signMessage'
        })
      ).to.be.revertedWithCustomError(safePolicyGuard, 'PolicyReverted')

      expect(await ethers.provider.getBalance(target)).to.equal(0n)
    })

    it('Should reject a transaction carrying no context at all', async function () {
      const { owners, safe, safePolicyGuard, increasedThresholdPolicy } = await loadFixture(fixture)

      const target = randomAddress()

      await enableGuard({
        owners,
        safe,
        safePolicyGuard,
        configurations: [
          createConfiguration({
            target,
            policy: await increasedThresholdPolicy.getAddress(),
            data: encodeIncreasedThresholdConfig(1)
          })
        ]
      })

      await expect(
        execTransaction({
          owners: owners.slice(0, 2),
          safe,
          to: target,
          value: ethers.parseEther('1'),
          signingMethod: 'signMessage'
        })
      ).to.be.revertedWithCustomError(safePolicyGuard, 'PolicyReverted')
    })
  })

  describe('Replay', function () {
    it('Should not let a batch spend the same signatures twice', async function () {
      const { owners, safe, safePolicyGuard, increasedThresholdPolicy, multiSend, multiSendPolicy } =
        await loadFixture(fixture)

      const target = randomAddress()
      const value = ethers.parseEther('1')
      const multiSendSelector = multiSend.interface.getFunction('multiSend')?.selector

      await enableGuard({
        owners,
        safe,
        safePolicyGuard,
        configurations: [
          createConfiguration({
            target,
            policy: await increasedThresholdPolicy.getAddress(),
            data: encodeIncreasedThresholdConfig(1)
          }),
          createConfiguration({
            target: await multiSend.getAddress(),
            selector: multiSendSelector,
            operation: SafeOperation.DelegateCall,
            policy: await multiSendPolicy.getAddress()
          })
        ]
      })

      // Owners sign the sub-transaction's derived hash, so both occurrences would otherwise be
      // satisfied by the same signatures.
      const nonce = await safe.nonce()
      const transfer = buildSafeTransaction({ to: target, value, data: '0x', nonce })
      const safeAddress = await safe.getAddress()
      const signatures = await Promise.all(
        owners.slice(0, 3).map((signer) => safeSignTypedData(signer, safeAddress, transfer))
      )
      const context = buildSignatureBytes(signatures)
      const multiSendTx = await buildMultiSendSafeTx(multiSend, [transfer, transfer], nonce)
      const repeated = ethers.solidityPacked(
        ['uint256', 'bytes', 'uint256', 'bytes'],
        [ethers.dataLength(context), context, ethers.dataLength(context), context]
      )

      await expect(
        execTransaction({
          owners: owners.slice(0, 3),
          safe,
          to: await multiSend.getAddress(),
          data: multiSendTx.data,
          operation: SafeOperation.DelegateCall,
          additionalData: repeated,
          signingMethod: 'signMessage'
        })
      ).to.be.revertedWithCustomError(safePolicyGuard, 'PolicyReverted')

      expect(await ethers.provider.getBalance(target)).to.equal(0n)
    })
  })

  describe('Module path', function () {
    it('Should reject the module path outright', async function () {
      const { safe, increasedThresholdPolicy } = await loadFixture(fixture)

      // The engine sources `module` itself, so this is asserted directly against the policy.
      await expect(
        increasedThresholdPolicy.checkTransaction(
          safe,
          randomAddress(),
          0n,
          '0x',
          SafeOperation.Call,
          randomAddress(),
          '0x',
          0n
        )
      ).to.be.revertedWithCustomError(increasedThresholdPolicy, 'ModulePathUnsupported')
    })
  })

  describe('Signature modes', function () {
    /** The 100-byte `Error(string)` payload the Safe produces for a `GS0xx` code. */
    const gs = (code: string) =>
      ethers.concat(['0x08c379a0', ethers.AbiCoder.defaultAbiCoder().encode(['string'], [code])])

    /** A `v == 0` contract-signature chunk: `[r = signer][s = offset of the dynamic part][v = 0]`. */
    const contractChunk = (signer: string, offset: number) =>
      ethers.solidityPacked(['uint256', 'uint256', 'uint8'], [signer, offset, 0])

    // The policy hands the context to `Safe.checkNSignatures`, so every signature mode the Safe
    // supports is reachable through it. These assert the Safe's own reason for each verdict, since
    // a bare `PolicyReverted` would be satisfied by the policy rejecting the context for any reason
    // at all -- including one that never reached the signature check.
    async function signatureModesFixture() {
      const base = await loadFixture(fixture)
      const { owners, safePolicyGuard, increasedThresholdPolicy, accessSelector, safeProxyFactory, safeSingleton } =
        base
      const eoaOwners = owners.slice(0, 3)
      const [owner, , , contractOwner] = owners

      const { compatibilityFallbackHandler } = await deploySafeContracts()
      // The ERC-1271 owner: a Safe with the compatibility handler, whose `isValidSignature`
      // validates against its own single owner.
      const contractSigner = await createSafe({
        owners: [contractOwner],
        guard: ZeroAddress,
        saltNonce: BigInt(0x1271),
        fallbackHandler: await compatibilityFallbackHandler.getAddress(),
        safeProxyFactory,
        singleton: safeSingleton
      })
      const contractSignerAddress = await contractSigner.getAddress()

      // A 3-owner, 2-of-3 Safe of its own, so the contract signer can be promoted to a fourth owner
      // while no guard is installed yet.
      const safe = await createSafe({
        owners: eoaOwners,
        threshold: 2,
        guard: ZeroAddress,
        saltNonce: BigInt(0x17),
        safeProxyFactory,
        singleton: safeSingleton
      })
      await execTransaction({
        owners: eoaOwners.slice(0, 2),
        safe,
        to: await safe.getAddress(),
        data: safe.interface.encodeFunctionData('addOwnerWithThreshold', [contractSignerAddress, 2]),
        signingMethod: 'signMessage'
      })

      const target = randomAddress()
      await enableGuard({
        owners: eoaOwners.slice(0, 2),
        safe,
        safePolicyGuard,
        configurations: [
          createConfiguration({
            target,
            policy: await increasedThresholdPolicy.getAddress(),
            data: encodeIncreasedThresholdConfig(1) // 4 owners, 1 absent, so 3 signatures
          })
        ]
      })
      await owner.sendTransaction({ to: await safe.getAddress(), value: ethers.parseEther('10') })

      const access = await accessSelector.create(target, '0x00000000', SafeOperation.Call)
      expect(await increasedThresholdPolicy.getRequiredSignatures(safePolicyGuard, safe, access)).to.equal(3n)

      return {
        ...base,
        eoaOwners,
        contractOwner,
        contractSigner,
        contractSignerAddress,
        safe,
        target,
        policy: await increasedThresholdPolicy.getAddress()
      }
    }

    /** The hash the policy derives for the transaction currently being checked. */
    const policyHash = async (safe: Safe, to: string, value: bigint) =>
      safe.getTransactionHash(
        to,
        value,
        '0x',
        SafeOperation.Call,
        0,
        0,
        0,
        ZeroAddress,
        ZeroAddress,
        await safe.nonce()
      )

    /** A plain-ECDSA EIP-712 chunk, `v in {27, 28}`. */
    async function ecdsaChunk(safe: Safe, signer: Signer, to: string, value: bigint): Promise<SafeSignature> {
      const safeTx = buildSafeTransaction({ to, value, data: '0x', nonce: await safe.nonce() })
      return safeSignTypedData(signer, await safe.getAddress(), safeTx)
    }

    /** An ERC-1271 signature by the contract-owner Safe over `dataHash`, as its handler expects. */
    async function contractSignature(contractSigner: Safe, contractOwner: Signer, dataHash: string) {
      const { chainId } = await ethers.provider.getNetwork()
      const messageHash = await calculateSafeMessageHash(await contractSigner.getAddress(), dataHash, Number(chainId))
      // The Safe accepts an `eth_sign` chunk once `v` is shifted by 4.
      return (await contractOwner.signMessage(ethers.getBytes(messageHash))).replace(/1b$/, '1f').replace(/1c$/, '20')
    }

    const send = (signers: Signer[], safe: Safe, to: string, value: bigint, context: string) =>
      execTransaction({ owners: signers, safe, to, value, additionalData: context, signingMethod: 'signMessage' })

    it('Should reject an approved-hash signature with no prior approveHash', async function () {
      const { eoaOwners, safe, safePolicyGuard, policy, target } = await signatureModesFixture()
      const value = ethers.parseEther('1')
      const [first, second, third] = eoaOwners

      // The policy passes `executor = address(0)`, which makes the Safe demand a recorded
      // `approvedHashes` entry for a `v == 1` chunk rather than accepting the sender.
      const context = buildSignatureBytes([
        await ecdsaChunk(safe, first, target, value),
        await ecdsaChunk(safe, second, target, value),
        { signer: await third.getAddress(), data: await preApprovedSignature(third) }
      ])
      expect(ethers.dataLength(context)).to.equal(3 * 65)

      await expect(send(eoaOwners.slice(0, 2), safe, target, value, context))
        .to.be.revertedWithCustomError(safePolicyGuard, 'PolicyReverted')
        .withArgs(policy, gs('GS025'))
      expect(await ethers.provider.getBalance(target)).to.equal(0n)
    })

    it('Should accept an approved-hash signature once that owner approved the hash', async function () {
      const { eoaOwners, safe, target } = await signatureModesFixture()
      const value = ethers.parseEther('1')
      const [first, second, third] = eoaOwners

      const dataHash = await policyHash(safe, target, value)
      await safe.connect(third).approveHash(dataHash)

      const context = buildSignatureBytes([
        await ecdsaChunk(safe, first, target, value),
        await ecdsaChunk(safe, second, target, value),
        { signer: await third.getAddress(), data: await preApprovedSignature(third) }
      ])

      await send(eoaOwners.slice(0, 2), safe, target, value, context)
      expect(await ethers.provider.getBalance(target)).to.equal(value)
    })

    it('Should reject signatures given in descending owner order', async function () {
      const { eoaOwners, safe, safePolicyGuard, policy, target } = await signatureModesFixture()
      const value = ethers.parseEther('1')

      const chunks = await Promise.all(eoaOwners.map((signer) => ecdsaChunk(safe, signer, target, value)))
      const ascending = buildSignatureBytes(chunks)
      // The same three signatures, order reversed: the only difference from an accepted context.
      const descending = ethers.concat(
        [...chunks].sort((a, b) => b.signer.toLowerCase().localeCompare(a.signer.toLowerCase())).map((c) => c.data)
      )
      expect(descending).to.not.equal(ascending)

      await expect(send(eoaOwners.slice(0, 2), safe, target, value, descending))
        .to.be.revertedWithCustomError(safePolicyGuard, 'PolicyReverted')
        .withArgs(policy, gs('GS026'))

      // Control: the ascending permutation of the very same signatures is accepted.
      await send(eoaOwners.slice(0, 2), safe, target, value, ascending)
      expect(await ethers.provider.getBalance(target)).to.equal(value)
    })

    it('Should accept an ERC-1271 signature and reject one pointing into the static part', async function () {
      const { eoaOwners, contractOwner, contractSigner, contractSignerAddress, safe, safePolicyGuard, policy, target } =
        await signatureModesFixture()
      const value = ethers.parseEther('1')

      const signature = await contractSignature(contractSigner, contractOwner, await policyHash(safe, target, value))
      const chunks = await Promise.all(eoaOwners.slice(0, 2).map((s) => ecdsaChunk(safe, s, target, value)))
      // Three static chunks are 195 bytes, so the dynamic part begins exactly there.
      const build = (offset: number) =>
        ethers.concat([
          buildSignatureBytes([
            ...chunks,
            { signer: contractSignerAddress, data: contractChunk(contractSignerAddress, offset) }
          ]),
          ethers.AbiCoder.defaultAbiCoder().encode(['uint256'], [ethers.dataLength(signature)]),
          signature
        ])
      expect(ethers.dataLength(build(195))).to.equal(195 + 32 + 65)

      // An `s` pointing inside the static part is rejected before the validator is ever called.
      await expect(send(eoaOwners.slice(0, 2), safe, target, value, build(100)))
        .to.be.revertedWithCustomError(safePolicyGuard, 'PolicyReverted')
        .withArgs(policy, gs('GS021'))

      await send(eoaOwners.slice(0, 2), safe, target, value, build(195))
      expect(await ethers.provider.getBalance(target)).to.equal(value)
    })

    it('Should propagate the validator own rejection of an ERC-1271 signature', async function () {
      const { eoaOwners, contractSigner, contractSignerAddress, safe, safePolicyGuard, policy, target } =
        await signatureModesFixture()
      const value = ethers.parseEther('1')
      const [first, second] = eoaOwners

      // Signed by an owner of the outer Safe, who is not an owner of the contract signer.
      const signature = await contractSignature(contractSigner, first, await policyHash(safe, target, value))
      const context = ethers.concat([
        buildSignatureBytes([
          await ecdsaChunk(safe, first, target, value),
          await ecdsaChunk(safe, second, target, value),
          { signer: contractSignerAddress, data: contractChunk(contractSignerAddress, 195) }
        ]),
        ethers.AbiCoder.defaultAbiCoder().encode(['uint256'], [ethers.dataLength(signature)]),
        signature
      ])

      // The inner Safe's own `checkSignatures` reverts and that reason bubbles out of the
      // validator call, so the outer Safe never reaches its own "invalid signature" branch.
      await expect(send(eoaOwners.slice(0, 2), safe, target, value, context))
        .to.be.revertedWithCustomError(safePolicyGuard, 'PolicyReverted')
        .withArgs(policy, gs('GS026'))
      expect(await ethers.provider.getBalance(target)).to.equal(0n)
    })
  })
})
