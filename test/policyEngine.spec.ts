import { loadFixture } from '@nomicfoundation/hardhat-network-helpers'
import { expect } from 'chai'
import { ZeroAddress } from 'ethers'
import { ethers, network } from 'hardhat'

import {
  createSafe,
  SafeOperation,
  enableGuard,
  execTransaction,
  randomAddress,
  randomSelector,
  createConfiguration
} from '../src/utils'
import { deployAllowPolicy, deploySafeContracts, deploySafePolicyGuard, deployMockPolicy } from './deploy'

describe('PolicyEngine Edge Cases', function () {
  async function fixture() {
    const [, owner] = await ethers.getSigners()

    const { safePolicyGuard } = await deploySafePolicyGuard()
    const { safeProxyFactory, safe: safeSingleton } = await deploySafeContracts()
    const safe = await createSafe({
      owners: [owner],
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

      // Create configuration for first policy
      const firstConfiguration = [
        createConfiguration({ target, selector, operation, policy: await mockPolicy.getAddress() })
      ]

      // Configure first policy through Safe transaction
      await execTransaction({
        owners: [owner],
        safe,
        to: await safePolicyGuard.getAddress(),
        data: safePolicyGuard.interface.encodeFunctionData('configureImmediately', [firstConfiguration])
      })

      // Verify first policy is set
      const [, firstPolicy] = await safePolicyGuard.getPolicy(await safe.getAddress(), target, selector, operation)
      expect(firstPolicy).to.equal(await mockPolicy.getAddress())

      // Configure second policy
      const secondConfiguration = [
        createConfiguration({ target, selector, operation, policy: await secondMockPolicy.getAddress() })
      ]

      // Configure second policy for same access selector (should overwrite)
      await execTransaction({
        owners: [owner],
        safe,
        to: await safePolicyGuard.getAddress(),
        data: safePolicyGuard.interface.encodeFunctionData('configureImmediately', [secondConfiguration])
      })

      const [, retrievedPolicy] = await safePolicyGuard.getPolicy(await safe.getAddress(), target, selector, operation)

      // The policy should be the second one now (overwritten)
      expect(retrievedPolicy).to.equal(await secondMockPolicy.getAddress())
    })

    it('Should handle clearing policy correctly', async function () {
      const { owner, safe, safePolicyGuard, mockPolicy } = await loadFixture(fixture)

      const target = ZeroAddress
      const selector = randomSelector()
      const operation = SafeOperation.Call

      const configuration = [
        createConfiguration({ target, selector, operation, policy: await mockPolicy.getAddress() })
      ]

      // Configure first policy through Safe transaction
      await execTransaction({
        owners: [owner],
        safe,
        to: await safePolicyGuard.getAddress(),
        data: safePolicyGuard.interface.encodeFunctionData('configureImmediately', [configuration])
      })

      // Verify first policy is set
      const [, firstPolicy] = await safePolicyGuard.getPolicy(await safe.getAddress(), target, selector, operation)
      expect(firstPolicy).to.equal(await mockPolicy.getAddress())

      const clearConfiguration = [
        createConfiguration({ target, selector, operation, policy: ZeroAddress }) // Clear policy
      ]

      // Configure second policy for same access selector (should overwrite)
      await execTransaction({
        owners: [owner],
        safe,
        to: await safePolicyGuard.getAddress(),
        data: safePolicyGuard.interface.encodeFunctionData('configureImmediately', [clearConfiguration])
      })

      const [, retrievedPolicy] = await safePolicyGuard.getPolicy(await safe.getAddress(), target, selector, operation)

      // The policy should be the Zero Address now (cleared)
      expect(retrievedPolicy).to.equal(ZeroAddress)
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

  describe('Policy selection', function () {
    it('Should prefer an exact match over the fallback', async function () {
      const { owner, safe, safePolicyGuard, mockPolicy } = await loadFixture(fixture)
      const { allowPolicy } = await deployAllowPolicy()
      const target = randomAddress()

      // The fallback denies (MockPolicy returns a zero magic value) and the exact match allows, so
      // a success can only mean the exact match was selected.
      await mockPolicy.setRevertTransaction(true)
      await enableGuard({
        owners: [owner],
        safe,
        safePolicyGuard,
        configurations: [
          createConfiguration({ policy: await mockPolicy.getAddress() }),
          createConfiguration({ target, policy: await allowPolicy.getAddress() })
        ]
      })

      await expect(execTransaction({ owners: [owner], safe, to: target })).to.not.be.reverted

      // Any other target falls through to the denying fallback.
      await expect(execTransaction({ owners: [owner], safe, to: randomAddress() }))
        .to.be.revertedWithCustomError(safePolicyGuard, 'AccessDenied')
        .withArgs(await mockPolicy.getAddress())
    })

    it('Should not let a DELEGATECALL fallback authorize a CALL', async function () {
      const { owner, safe, safePolicyGuard } = await loadFixture(fixture)
      const { allowPolicy } = await deployAllowPolicy()

      // The operation is part of the access selector, so the two fallbacks are separate keys.
      await enableGuard({
        owners: [owner],
        safe,
        safePolicyGuard,
        configurations: [
          createConfiguration({ operation: SafeOperation.DelegateCall, policy: await allowPolicy.getAddress() })
        ]
      })

      await expect(execTransaction({ owners: [owner], safe, to: randomAddress() }))
        .to.be.revertedWithCustomError(safePolicyGuard, 'AccessDenied')
        .withArgs(ZeroAddress)
    })
  })

  describe('Denial reasons', function () {
    async function guardedFixture() {
      const base = await loadFixture(fixture)
      const { owner, safe, safePolicyGuard, mockPolicy } = base
      const target = randomAddress()

      await enableGuard({
        owners: [owner],
        safe,
        safePolicyGuard,
        configurations: [createConfiguration({ target, policy: await mockPolicy.getAddress() })]
      })

      return { ...base, target }
    }

    it('Should forward a policy own revert data', async function () {
      const { owner, safe, safePolicyGuard, mockPolicy, target } = await guardedFixture()
      await mockPolicy.setRevertCheckWithReason(true)

      await expect(execTransaction({ owners: [owner], safe, to: target }))
        .to.be.revertedWithCustomError(safePolicyGuard, 'PolicyReverted')
        .withArgs(await mockPolicy.getAddress(), mockPolicy.interface.encodeErrorResult('MockDenied', [42]))
    })

    it('Should report a wrong magic value as AccessDenied, not PolicyReverted', async function () {
      const { owner, safe, safePolicyGuard, mockPolicy, target } = await guardedFixture()

      // The policy returns successfully but with the wrong magic value, which is a denial rather
      // than a revert and so keeps the `AccessDenied` shape.
      await mockPolicy.setRevertTransaction(true)

      await expect(execTransaction({ owners: [owner], safe, to: target }))
        .to.be.revertedWithCustomError(safePolicyGuard, 'AccessDenied')
        .withArgs(await mockPolicy.getAddress())
    })

    it('Should report no configured policy as AccessDenied with the zero address', async function () {
      const { owner, safe, safePolicyGuard } = await guardedFixture()

      await expect(execTransaction({ owners: [owner], safe, to: randomAddress() }))
        .to.be.revertedWithCustomError(safePolicyGuard, 'AccessDenied')
        .withArgs(ZeroAddress)
    })
  })

  describe('Policies with no usable return', function () {
    // A policy whose return data cannot be decoded -- no code at all, fewer than 32 bytes, or the
    // calldata echoed back -- fails inside the ABI decoder at the call site, which is outside the
    // `try`/`catch` around the policy call. So the whole entry point reverts with empty data
    // rather than with `PolicyConfigurationFailed` or `AccessDenied`, and the fail-closed direction
    // is the only thing these can land on.

    /** An address that echoes its calldata: the identity precompile. */
    const ECHOING_ADDRESS = '0x0000000000000000000000000000000000000004'
    /** Runtime returning four zero bytes for any call, fewer than a `bytes4` return needs. */
    const SHORT_RETURN_CODE = '0x60046000f3'
    /** Runtime echoing its calldata for any call. */
    const ECHO_CODE = '0x365f5f37365ff3'

    async function configuredFixture() {
      const base = await loadFixture(fixture)
      const { owner, safe, safePolicyGuard } = base

      // Deployed here rather than taken from the fixture, since these tests overwrite its code.
      const policy = await (await ethers.getContractFactory('MockPolicy')).deploy()
      const policyAddress = await policy.getAddress()
      const target = randomAddress()

      await enableGuard({
        owners: [owner],
        safe,
        safePolicyGuard,
        configurations: [createConfiguration({ target, policy: policyAddress })]
      })

      /** A guarded transaction whose check reaches the configured policy. */
      const check = () => execTransaction({ owners: [owner], safe, to: target })
      /** Replaces the configured policy's code, which no path through the engine can do. */
      const plant = (code: string) => network.provider.send('hardhat_setCode', [policyAddress, code])

      return { ...base, policyAddress, target, check, plant }
    }

    it('Should reject configuring an account with no code as a policy', async function () {
      const { owner, safePolicyGuard } = await loadFixture(fixture)

      const configuration = createConfiguration({ target: randomAddress(), policy: randomAddress() })
      await expect(safePolicyGuard.connect(owner).configureImmediately([configuration])).to.be.revertedWithoutReason()
    })

    it('Should reject configuring an address that echoes its calldata as a policy', async function () {
      const { owner, safePolicyGuard } = await loadFixture(fixture)

      // `configure` is echoed back, so the first word decoded as its `bool` return is the selector
      // followed by the head of the first argument, which is neither 0 nor 1.
      const configuration = createConfiguration({ target: randomAddress(), policy: ECHOING_ADDRESS })
      await expect(safePolicyGuard.connect(owner).configureImmediately([configuration])).to.be.revertedWithoutReason()
    })

    it('Should revert without a reason when a configured policy has lost its code', async function () {
      const { check, plant } = await configuredFixture()

      await expect(check()).to.not.be.reverted
      await plant('0x')
      await expect(check()).to.be.revertedWithoutReason()
    })

    it('Should revert without a reason when a configured policy returns fewer than 32 bytes', async function () {
      const { check, plant } = await configuredFixture()

      await plant(SHORT_RETURN_CODE)
      await expect(check()).to.be.revertedWithoutReason()
    })

    it('Should revert without a reason when a configured policy echoes its calldata', async function () {
      const { check, plant } = await configuredFixture()

      await plant(ECHO_CODE)
      await expect(check()).to.be.revertedWithoutReason()
    })
  })
})
