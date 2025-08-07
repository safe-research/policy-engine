import { loadFixture } from '@nomicfoundation/hardhat-network-helpers'
import { expect } from 'chai'
import { ZeroAddress } from 'ethers'
import { ethers } from 'hardhat'

import { createSafe, SafeOperation, execTransaction, randomAddress, randomSelector } from '../src/utils'
import { deploySafeContracts, deploySafePolicyGuard, deployMockPolicy } from './deploy'

describe('PolicyEngine Edge Cases', function () {
  async function fixture() {
    const [, owner] = await ethers.getSigners()

    const { safePolicyGuard } = await deploySafePolicyGuard()
    const { safeProxyFactory, safe: safeSingleton } = await deploySafeContracts()
    const safe = await createSafe({
      owner,
      guard: ZeroAddress,
      saltNonce: BigInt(0x9),
      safeProxyFactory,
      singleton: safeSingleton
    })

    const { mockPolicy } = await deployMockPolicy()

    const TestAccessSelectorFactory = await ethers.getContractFactory('TestAccessSelector')
    const accessSelector = await TestAccessSelectorFactory.deploy()

    return { owner, safe, safePolicyGuard, mockPolicy, accessSelector }
  }

  describe('Selector Decoding Edge Cases', function () {
    it('Should handle empty calldata correctly', async function () {
      const { safePolicyGuard, safe, accessSelector } = await loadFixture(fixture)

      // Test with empty data (should use zero selector and fallback to operation-only access)
      const [_access, _policy] = await safePolicyGuard.getPolicy(
        await safe.getAddress(),
        ZeroAddress,
        '0x',
        SafeOperation.Call
      )

      // Should create fallback selector for CALL operation when no exact match
      const expectedFallbackAccess = await accessSelector.createFallback(SafeOperation.Call)

      expect(_access).to.equal(expectedFallbackAccess) // Should use fallback selector
    })

    it('Should revert with invalid selector length (1-3 bytes)', async function () {
      const { safePolicyGuard, safe } = await loadFixture(fixture)

      // Test with 1 byte data
      await expect(
        safePolicyGuard.getPolicy(await safe.getAddress(), ZeroAddress, '0x12', SafeOperation.Call)
      ).to.be.revertedWithCustomError(safePolicyGuard, 'InvalidSelector')

      // Test with 2 bytes data
      await expect(
        safePolicyGuard.getPolicy(await safe.getAddress(), ZeroAddress, '0x1234', SafeOperation.Call)
      ).to.be.revertedWithCustomError(safePolicyGuard, 'InvalidSelector')

      // Test with 3 bytes data
      await expect(
        safePolicyGuard.getPolicy(await safe.getAddress(), ZeroAddress, '0x123456', SafeOperation.Call)
      ).to.be.revertedWithCustomError(safePolicyGuard, 'InvalidSelector')
    })

    it('Should handle exactly 4 bytes of data correctly', async function () {
      const { safePolicyGuard, safe } = await loadFixture(fixture)

      const selector = '0x12345678'
      const [_access, policy] = await safePolicyGuard.getPolicy(
        await safe.getAddress(),
        ZeroAddress,
        selector,
        SafeOperation.Call
      )

      expect(policy).to.equal(ZeroAddress) // No policy configured, should be zero
    })
  })

  describe('Policy Configuration Edge Cases', function () {
    it('Should handle empty configuration arrays', async function () {
      const { safePolicyGuard } = await loadFixture(fixture)

      // Should not revert with empty configuration
      await expect(safePolicyGuard.configureImmediately([])).to.not.be.reverted
    })

    it('Should handle policy overwrite correctly', async function () {
      const { owner, safe, safePolicyGuard, mockPolicy } = await loadFixture(fixture)

      const target = ZeroAddress
      const selector = randomSelector()
      const operation = SafeOperation.Call

      // Deploy a second mock policy
      const MockPolicyFactory = await ethers.getContractFactory('MockPolicy')
      const secondMockPolicy = await MockPolicyFactory.deploy()

      // Configure first policy through Safe transaction
      await execTransaction({
        owners: [owner],
        safe,
        to: await safePolicyGuard.getAddress(),
        data: safePolicyGuard.interface.encodeFunctionData('configureImmediately', [
          [
            {
              target,
              selector,
              operation,
              policy: await mockPolicy.getAddress(),
              data: '0x'
            }
          ]
        ])
      })

      // Verify first policy is set
      const [, firstPolicy] = await safePolicyGuard.getPolicy(await safe.getAddress(), target, selector, operation)
      expect(firstPolicy).to.equal(await mockPolicy.getAddress())

      // Configure second policy for same access selector (should overwrite)
      await execTransaction({
        owners: [owner],
        safe,
        to: await safePolicyGuard.getAddress(),
        data: safePolicyGuard.interface.encodeFunctionData('configureImmediately', [
          [
            {
              target,
              selector,
              operation,
              policy: await secondMockPolicy.getAddress(),
              data: '0x'
            }
          ]
        ])
      })

      const [_retrievedAccess, retrievedPolicy] = await safePolicyGuard.getPolicy(
        await safe.getAddress(),
        target,
        selector,
        operation
      )

      // The policy should be the second one now (overwritten)
      expect(retrievedPolicy).to.equal(await secondMockPolicy.getAddress())
    })
  })

  describe('AccessSelector Library Edge Cases', function () {
    it('Should correctly pack and unpack access selectors', async function () {
      const TestAccessSelectorFactory = await ethers.getContractFactory('TestAccessSelector')
      const accessSelector = await TestAccessSelectorFactory.deploy()

      const target = randomAddress()
      const selector = randomSelector()
      const operation = SafeOperation.DelegateCall

      const packed = await accessSelector.create(target, selector, operation)

      // Verify unpacking
      expect(await accessSelector.getTarget(packed)).to.equal(target)
      expect(await accessSelector.getSelector(packed)).to.equal(selector)
      expect(await accessSelector.getOperation(packed)).to.equal(operation)
    })

    it('Should create correct fallback selectors', async function () {
      const { accessSelector } = await loadFixture(fixture)

      const callFallback = await accessSelector.createFallback(SafeOperation.Call)
      const delegateCallFallback = await accessSelector.createFallback(SafeOperation.DelegateCall)

      // Fallback selectors should have zero address and selector
      expect(await accessSelector.getTarget(callFallback)).to.equal(ZeroAddress)
      expect(await accessSelector.getSelector(callFallback)).to.equal('0x00000000')
      expect(await accessSelector.getOperation(callFallback)).to.equal(SafeOperation.Call)

      expect(await accessSelector.getTarget(delegateCallFallback)).to.equal(ZeroAddress)
      expect(await accessSelector.getSelector(delegateCallFallback)).to.equal('0x00000000')
      expect(await accessSelector.getOperation(delegateCallFallback)).to.equal(SafeOperation.DelegateCall)
    })
  })
})
