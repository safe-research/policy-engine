import { loadFixture } from '@nomicfoundation/hardhat-network-helpers'
import { expect } from 'chai'
import { Signer, ZeroAddress } from 'ethers'
import { ethers } from 'hardhat'

import {
  buildMultiSendSafeTx,
  buildSafeTransaction,
  buildSignatureBytes,
  createConfiguration,
  createSafe,
  enableGuard,
  encodeIncreasedThresholdConfig,
  execTransaction,
  randomAddress,
  safeSignTypedData,
  SafeOperation
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
})
