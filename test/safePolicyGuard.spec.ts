import { loadFixture, time } from '@nomicfoundation/hardhat-network-helpers'
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
  getConfigurationRoot,
  getGuard,
  POLICY_CONTEXT_TYPE_HASH,
  preApprovedSignature,
  randomAddress,
  randomSelector,
  SafeOperation
} from '../src/utils'
import { deployAllowPolicy, deploySafePolicyGuard, deploySafeContracts, deployMockPolicy } from './deploy'

// Mirrors ReentrantMockPolicy.Mode.
enum ReentrantMockPolicyMode {
  None,
  ReenterGuardEntry,
  ReenterEngine,
  WriteState
}

describe('SafePolicyGuard', function () {
  async function fixture() {
    const [, owner, other] = await ethers.getSigners()

    // Deploy the SafePolicyGuard contract
    const {
      safePolicyGuard,
      options: { delay }
    } = await deploySafePolicyGuard()

    // Deploy the Safe contracts
    const { safeProxyFactory, safe: safeSingleton } = await deploySafeContracts()
    const safe = await createSafe({
      owner,
      guard: ZeroAddress, // No guard at this point
      saltNonce: BigInt(0x1),
      safeProxyFactory,
      singleton: safeSingleton
    })

    // Deploy Mock Policy contract
    const { mockPolicy } = await deployMockPolicy()

    // Deploy Test Access Selector
    const AccessSelectorFactory = await ethers.getContractFactory('TestAccessSelector')
    const accessSelector = await AccessSelectorFactory.deploy()

    return { owner, other, safePolicyGuard, safe, delay, mockPolicy, accessSelector }
  }

  describe('constructor', function () {
    it('Should set the delay', async function () {
      const { safePolicyGuard, delay } = await loadFixture(fixture)
      expect(await safePolicyGuard.DELAY()).to.equal(delay)
    })
  })

  describe('supportsInterface', function () {
    it('Should support the PolicyEngine interface', async function () {
      const { safePolicyGuard } = await loadFixture(fixture)
      expect(await safePolicyGuard.supportsInterface('0x04a9e3cd')).to.equal(true)
    })

    it('Should support the SafeModuleGuard interface', async function () {
      const { safePolicyGuard } = await loadFixture(fixture)
      expect(await safePolicyGuard.supportsInterface('0x58401ed8')).to.equal(true)
    })

    it('Should support the SafeTransactionGuard interface', async function () {
      const { safePolicyGuard } = await loadFixture(fixture)
      expect(await safePolicyGuard.supportsInterface('0xe6d7a83a')).to.equal(true)
    })

    it('Should support the ERC165 interface', async function () {
      const { safePolicyGuard } = await loadFixture(fixture)
      expect(await safePolicyGuard.supportsInterface('0x01ffc9a7')).to.equal(true)
    })
  })

  describe('configureImmediately', function () {
    it('Should be able to configure immediately', async function () {
      const { owner, safePolicyGuard, safe, mockPolicy, accessSelector } = await loadFixture(fixture)

      // Configuration parameters
      const configuration = [
        createConfiguration({
          target: randomAddress(),
          selector: randomSelector(),
          policy: await mockPolicy.getAddress()
        })
      ]

      // Check if any configuration is set
      const [initialAccess, initialPolicy] = await safePolicyGuard.getPolicy(
        await safe.getAddress(),
        configuration[0].target,
        configuration[0].selector,
        configuration[0].operation
      )

      // Check that the access is fallback access and policy is ZeroAddress
      expect(initialAccess).to.equal(await accessSelector.createFallback(configuration[0].operation))
      expect(initialPolicy).to.equal(ZeroAddress)

      // Call the configure immediately function on safe using execTransaction helper function
      await execTransaction({
        owners: [owner],
        safe,
        to: await safePolicyGuard.getAddress(),
        data: safePolicyGuard.interface.encodeFunctionData('configureImmediately', [configuration])
      })

      // Check if the configuration is set
      const [updatedAccess, updatedPolicy] = await safePolicyGuard.getPolicy(
        await safe.getAddress(),
        configuration[0].target,
        configuration[0].selector,
        configuration[0].operation
      )

      // Calculate the expected access using the access selector
      const expectedAccess = await accessSelector.create(
        configuration[0].target,
        configuration[0].selector,
        configuration[0].operation
      )

      // Check that the access is set correctly
      expect(updatedAccess).to.equal(expectedAccess)
      expect(initialAccess).to.not.equal(updatedAccess)
      expect(updatedPolicy).to.equal(await mockPolicy.getAddress())
    })

    it('Should revert if the configuration is not valid', async function () {
      const { owner, safePolicyGuard, safe, mockPolicy } = await loadFixture(fixture)

      // Configuration parameters
      const configuration = [
        createConfiguration({
          target: randomAddress(),
          selector: randomSelector(),
          policy: await mockPolicy.getAddress()
        })
      ]

      // Revert the configuration
      await mockPolicy.setRevertConfigure(true)

      // Call the configure immediately function on safe using execTransaction helper function
      await expect(
        execTransaction({
          owners: [owner],
          safe,
          to: await safePolicyGuard.getAddress(),
          data: safePolicyGuard.interface.encodeFunctionData('configureImmediately', [configuration])
        })
      ).to.be.revertedWithCustomError(safePolicyGuard, 'PolicyConfigurationFailed') // Actual error is `PolicyConfigurationFailed`
    })

    it('Should be able to configure fallback policy immediately (CALL)', async function () {
      const { owner, safePolicyGuard, safe, mockPolicy, accessSelector } = await loadFixture(fixture)

      // Configuration parameters
      const configuration = [createConfiguration({ policy: await mockPolicy.getAddress() })]

      // Check if any configuration is set
      const [initialAccess, initialPolicy] = await safePolicyGuard.getPolicy(
        await safe.getAddress(),
        configuration[0].target,
        configuration[0].selector,
        configuration[0].operation
      )

      // Check that the access is fallback access and policy is ZeroAddress
      const expectedFallbackAccess = await accessSelector.createFallback(configuration[0].operation)
      expect(initialAccess).to.equal(expectedFallbackAccess)
      expect(initialPolicy).to.equal(ZeroAddress)

      // Call the configure immediately function on safe using execTransaction helper function
      await execTransaction({
        owners: [owner],
        safe,
        to: await safePolicyGuard.getAddress(),
        data: safePolicyGuard.interface.encodeFunctionData('configureImmediately', [configuration])
      })

      // Check if the configuration is set
      const [updatedAccess, updatedPolicy] = await safePolicyGuard.getPolicy(
        await safe.getAddress(),
        configuration[0].target,
        configuration[0].selector,
        configuration[0].operation
      )

      // Calculate the expected access using the access selector
      const expectedAccess = await accessSelector.create(
        configuration[0].target,
        configuration[0].selector,
        configuration[0].operation
      )

      // Check that the access is set correctly
      expect(updatedAccess).to.equal(expectedAccess)
      expect(initialAccess).to.equal(updatedAccess) // Access should not change for fallback
      expect(updatedPolicy).to.equal(await mockPolicy.getAddress())
    })

    it('Should be able to configure fallback policy immediately (DELEGATECALL)', async function () {
      const { owner, safePolicyGuard, safe, mockPolicy, accessSelector } = await loadFixture(fixture)

      // Configuration parameters
      const configuration = [
        createConfiguration({
          operation: SafeOperation.DelegateCall,
          policy: await mockPolicy.getAddress()
        })
      ]

      // Check if any configuration is set
      const [initialAccess, initialPolicy] = await safePolicyGuard.getPolicy(
        await safe.getAddress(),
        configuration[0].target,
        configuration[0].selector,
        configuration[0].operation
      )

      // Check that the access is fallback access and policy is ZeroAddress
      expect(initialAccess).to.equal(await accessSelector.createFallback(configuration[0].operation))
      expect(initialPolicy).to.equal(ZeroAddress)

      // Call the configure immediately function on safe using execTransaction helper function
      await execTransaction({
        owners: [owner],
        safe,
        to: await safePolicyGuard.getAddress(),
        data: safePolicyGuard.interface.encodeFunctionData('configureImmediately', [configuration])
      })

      // Check if the configuration is set
      const [updatedAccess, updatedPolicy] = await safePolicyGuard.getPolicy(
        await safe.getAddress(),
        configuration[0].target,
        configuration[0].selector,
        configuration[0].operation
      )

      // Calculate the expected access using the access selector
      const expectedAccess = await accessSelector.create(
        configuration[0].target,
        configuration[0].selector,
        configuration[0].operation
      )

      // Check that the access is set correctly
      expect(updatedAccess).to.equal(expectedAccess)
      expect(initialAccess).to.equal(updatedAccess) // Access should not change for fallback
      expect(updatedPolicy).to.equal(await mockPolicy.getAddress())
    })

    it('Should not be able to configure immediately if the guard is enabled', async function () {
      // IMPORTANT: This test case assumes that the access selector for the `configureImmediately()` is not allowed.
      const { owner, safePolicyGuard, safe, mockPolicy } = await loadFixture(fixture)

      // Configuration parameters
      const configuration = [
        createConfiguration({
          target: randomAddress(),
          selector: randomSelector(),
          policy: await mockPolicy.getAddress()
        })
      ]

      // Enable the guard on safe
      await enableGuard({ owner, safe, safePolicyGuard })

      // Call the configure immediately function on safe using execTransaction helper function
      await expect(
        execTransaction({
          owners: [owner],
          safe,
          to: await safePolicyGuard.getAddress(),
          data: safePolicyGuard.interface.encodeFunctionData('configureImmediately', [configuration])
        })
      )
        .to.be.revertedWithCustomError(safePolicyGuard, 'AccessDenied')
        .withArgs(ZeroAddress)
    })

    it('Should not be able to configure immediately even when a policy permits calling the guard', async function () {
      // The guard check is not enough on its own to keep `configureImmediately` unreachable: a
      // permissive fallback lets the call through, which would defeat the delay entirely.
      const { owner, safePolicyGuard, safe, mockPolicy } = await loadFixture(fixture)
      const guardAddress = await safePolicyGuard.getAddress()

      await enableGuard({
        owner,
        safe,
        safePolicyGuard,
        configurations: [createConfiguration({ policy: await mockPolicy.getAddress() })]
      })

      await expect(
        execTransaction({
          owners: [owner],
          safe,
          to: guardAddress,
          data: safePolicyGuard.interface.encodeFunctionData('configureImmediately', [
            [createConfiguration({ target: randomAddress(), policy: await mockPolicy.getAddress() })]
          ])
        })
      ).to.be.revertedWithCustomError(safePolicyGuard, 'GuardAlreadyEnabled')
    })

    it('Should not be able to configure immediately when only the module guard is enabled', async function () {
      const { owner, safePolicyGuard, safe, mockPolicy } = await loadFixture(fixture)
      const guardAddress = await safePolicyGuard.getAddress()

      await execTransaction({
        owners: [owner],
        safe,
        to: await safe.getAddress(),
        data: safe.interface.encodeFunctionData('setModuleGuard', [guardAddress])
      })

      await expect(
        execTransaction({
          owners: [owner],
          safe,
          to: guardAddress,
          data: safePolicyGuard.interface.encodeFunctionData('configureImmediately', [
            [createConfiguration({ policy: await mockPolicy.getAddress() })]
          ])
        })
      ).to.be.revertedWithCustomError(safePolicyGuard, 'GuardAlreadyEnabled')
    })

    it('Should be able to configure immediately again after the guard is removed', async function () {
      // The documented re-bootstrap flow: once the guard is off, the pre-guard path is available
      // again to clean up the policy that allowed its removal.
      const { owner, safePolicyGuard, safe, mockPolicy } = await loadFixture(fixture)
      const guardAddress = await safePolicyGuard.getAddress()
      const { allowPolicy } = await deployAllowPolicy()

      // Allow `setGuard` so the guard can be removed, then enable the guard.
      await enableGuard({
        owner,
        safe,
        safePolicyGuard,
        configurations: [
          createConfiguration({
            target: await safe.getAddress(),
            selector: safe.interface.getFunction('setGuard')?.selector,
            policy: await allowPolicy.getAddress()
          })
        ]
      })

      // Remove the guard, which the AllowPolicy above permits.
      await execTransaction({
        owners: [owner],
        safe,
        to: await safe.getAddress(),
        data: safe.interface.encodeFunctionData('setGuard', [ZeroAddress])
      })

      await expect(
        execTransaction({
          owners: [owner],
          safe,
          to: guardAddress,
          data: safePolicyGuard.interface.encodeFunctionData('configureImmediately', [
            [createConfiguration({ target: randomAddress(), policy: await mockPolicy.getAddress() })]
          ])
        })
      ).to.not.be.reverted
    })

    it('Should let a caller that is not a Safe configure its own policies', async function () {
      // The guard probes for an installed guard with `staticcall(getStorageAt)`. A caller with no
      // such function and no fallback makes that call revert outright, which must read as "no guard
      // installed" rather than propagate -- policy state is namespaced by `msg.sender`, so a
      // non-Safe caller configuring itself is legitimate.
      const { safePolicyGuard, mockPolicy } = await loadFixture(fixture)
      const configurer = await (await ethers.getContractFactory('TestNonSafeConfigurer')).deploy()
      const target = randomAddress()

      await expect(
        configurer.configure(safePolicyGuard, [createConfiguration({ target, policy: await mockPolicy.getAddress() })])
      ).to.not.be.reverted

      const [, policy] = await safePolicyGuard.getPolicy(configurer, target, '0x00000000', SafeOperation.Call)
      expect(policy).to.equal(await mockPolicy.getAddress())
    })

    it('Should not read revert data from a failed guard-slot probe', async function () {
      // A caller whose `getStorageAt` reverts with a payload shaped exactly like a successful answer,
      // planting the guard's own address in the word the guard reads. Only the call status separates
      // this from a real answer: dropping that check makes the guard read the plant, decide it is
      // already installed, and refuse the configuration.
      const { safePolicyGuard, mockPolicy } = await loadFixture(fixture)
      const configurer = await (await ethers.getContractFactory('TestRevertingStorageConfigurer')).deploy()
      const target = randomAddress()

      await expect(
        configurer.configure(safePolicyGuard, [createConfiguration({ target, policy: await mockPolicy.getAddress() })])
      ).to.not.be.reverted

      const [, policy] = await safePolicyGuard.getPolicy(configurer, target, '0x00000000', SafeOperation.Call)
      expect(policy).to.equal(await mockPolicy.getAddress())
    })
  })

  describe('requestConfiguration', function () {
    it('Should be able to request configuration without guard', async function () {
      const { owner, safePolicyGuard, safe, delay, mockPolicy } = await loadFixture(fixture)

      // Configuration parameters
      const configuration = [
        createConfiguration({
          target: randomAddress(),
          selector: randomSelector(),
          policy: await mockPolicy.getAddress()
        })
      ]

      // Configuration root
      const configurationRoot = getConfigurationRoot(configuration)

      // Getting the timestamp of the configuration request
      const configurationRequestTimestamp = BigInt(await time.latest()) + 1n

      // Call the request configuration function on safe using execTransaction helper function
      await execTransaction({
        owners: [owner],
        safe,
        to: await safePolicyGuard.getAddress(),
        data: safePolicyGuard.interface.encodeFunctionData('requestConfiguration', [configurationRoot])
      })

      // Check if the configuration request is set
      const configurationApplyTimestamp = await safePolicyGuard.rootConfigured(
        await safe.getAddress(),
        configurationRoot
      )
      expect(configurationApplyTimestamp).to.equal(configurationRequestTimestamp + delay)
    })

    it('Should be able to request configuration with guard', async function () {
      const { owner, safePolicyGuard, safe, delay, mockPolicy } = await loadFixture(fixture)

      // Configuration parameters
      const configuration = [
        createConfiguration({
          target: randomAddress(),
          selector: randomSelector(),
          policy: await mockPolicy.getAddress()
        })
      ]

      // Configuration root
      const configurationRoot = getConfigurationRoot(configuration)

      // Enable the guard on safe
      await enableGuard({ owner, safe, safePolicyGuard })

      // Getting the timestamp of the configuration request
      const configurationRequestTimestamp = BigInt(await time.latest()) + 1n

      // Call the request configuration function on safe using execTransaction helper function
      await execTransaction({
        owners: [owner],
        safe,
        to: await safePolicyGuard.getAddress(),
        data: safePolicyGuard.interface.encodeFunctionData('requestConfiguration', [configurationRoot])
      })

      // Check if the configuration request is set
      const configurationApplyTimestamp = await safePolicyGuard.rootConfigured(
        await safe.getAddress(),
        configurationRoot
      )
      expect(configurationApplyTimestamp).to.equal(configurationRequestTimestamp + delay)
    })

    it('Should not be able to request configuration if the root is already configured', async function () {
      const { owner, safePolicyGuard, safe, mockPolicy } = await loadFixture(fixture)

      // Configuration parameters
      const configuration = [
        createConfiguration({
          target: randomAddress(),
          selector: randomSelector(),
          policy: await mockPolicy.getAddress()
        })
      ]

      // Configuration root
      const configurationRoot = getConfigurationRoot(configuration)

      // Call the request configuration function on safe using execTransaction helper function
      await execTransaction({
        owners: [owner],
        safe,
        to: await safePolicyGuard.getAddress(),
        data: safePolicyGuard.interface.encodeFunctionData('requestConfiguration', [configurationRoot])
      })

      // Call the request configuration function again on safe using execTransaction helper function
      await expect(
        execTransaction({
          owners: [owner],
          safe,
          to: await safePolicyGuard.getAddress(),
          data: safePolicyGuard.interface.encodeFunctionData('requestConfiguration', [configurationRoot])
        })
      ).to.be.revertedWithCustomError(safePolicyGuard, 'RootAlreadyConfigured') // Actual error is `RootAlreadyConfigured`
    })

    it('Should emit an event when the configuration is requested', async function () {
      const { owner, safePolicyGuard, safe, delay, mockPolicy } = await loadFixture(fixture)

      // Configuration parameters
      const configuration = [
        createConfiguration({
          target: randomAddress(),
          selector: randomSelector(),
          policy: await mockPolicy.getAddress()
        })
      ]

      // Configuration root
      const configurationRoot = getConfigurationRoot(configuration)

      // Getting the timestamp of the configuration request
      const configurationRequestTimestamp = BigInt(await time.latest()) + 1n

      // Call the request configuration function on safe using execTransaction helper function
      await expect(
        execTransaction({
          owners: [owner],
          safe,
          to: await safePolicyGuard.getAddress(),
          data: safePolicyGuard.interface.encodeFunctionData('requestConfiguration', [configurationRoot])
        })
      )
        .to.emit(safePolicyGuard, 'RootConfigured')
        .withArgs(await safe.getAddress(), configurationRoot, configurationRequestTimestamp + delay)
    })
  })

  describe('applyConfiguration', function () {
    it('Should be able to apply configuration without guard', async function () {
      const { owner, safePolicyGuard, safe, delay, mockPolicy, accessSelector } = await loadFixture(fixture)

      // Configuration parameters
      const configuration = [
        createConfiguration({
          target: randomAddress(),
          selector: randomSelector(),
          policy: await mockPolicy.getAddress()
        })
      ]

      // Configuration root
      const configurationRoot = getConfigurationRoot(configuration)

      // Call the request configuration function on safe using execTransaction helper function
      await execTransaction({
        owners: [owner],
        safe,
        to: await safePolicyGuard.getAddress(),
        data: safePolicyGuard.interface.encodeFunctionData('requestConfiguration', [configurationRoot])
      })

      // Increase the time to the delay
      await time.increase(delay)

      // Call the apply configuration function on safe using execTransaction helper function
      await execTransaction({
        owners: [owner],
        safe,
        to: await safePolicyGuard.getAddress(),
        data: safePolicyGuard.interface.encodeFunctionData('applyConfiguration', [configuration])
      })

      // Check if the configuration is set
      const [updatedAccess, updatedPolicy] = await safePolicyGuard.getPolicy(
        await safe.getAddress(),
        configuration[0].target,
        configuration[0].selector,
        configuration[0].operation
      )

      // Calculate the expected access using the access selector
      const expectedAccess = await accessSelector.create(
        configuration[0].target,
        configuration[0].selector,
        configuration[0].operation
      )

      // Check that the configuration is set correctly
      expect(updatedAccess).to.equal(expectedAccess)
      expect(updatedPolicy).to.equal(await mockPolicy.getAddress())
    })

    it('Should be able to apply configuration with guard', async function () {
      const { owner, safePolicyGuard, safe, delay, mockPolicy, accessSelector } = await loadFixture(fixture)

      // Configuration parameters
      const configuration = [
        createConfiguration({
          target: randomAddress(),
          selector: randomSelector(),
          policy: await mockPolicy.getAddress()
        })
      ]

      // Configuration root
      const configurationRoot = getConfigurationRoot(configuration)

      // Enable the guard on safe
      await enableGuard({ owner, safe, safePolicyGuard })

      // Call the request configuration function on safe using execTransaction helper function
      await execTransaction({
        owners: [owner],
        safe,
        to: await safePolicyGuard.getAddress(),
        data: safePolicyGuard.interface.encodeFunctionData('requestConfiguration', [configurationRoot])
      })

      // Increase the time to the delay
      await time.increase(delay)

      // Call the apply configuration function on safe using execTransaction helper function
      await execTransaction({
        owners: [owner],
        safe,
        to: await safePolicyGuard.getAddress(),
        data: safePolicyGuard.interface.encodeFunctionData('applyConfiguration', [configuration])
      })

      // Check if the configuration is set
      const [updatedAccess, updatedPolicy] = await safePolicyGuard.getPolicy(
        await safe.getAddress(),
        configuration[0].target,
        configuration[0].selector,
        configuration[0].operation
      )

      // Calculate the expected access using the access selector
      const expectedAccess = await accessSelector.create(
        configuration[0].target,
        configuration[0].selector,
        configuration[0].operation
      )

      // Check that the configuration is set correctly
      expect(updatedAccess).to.equal(expectedAccess)
      expect(updatedPolicy).to.equal(await mockPolicy.getAddress())
    })

    it('Should not be able to apply configuration if the root is not configured', async function () {
      const { owner, safePolicyGuard, safe, mockPolicy } = await loadFixture(fixture)

      // Configuration parameters
      const configuration = [
        createConfiguration({
          target: randomAddress(),
          selector: randomSelector(),
          policy: await mockPolicy.getAddress()
        })
      ]

      // Call the apply configuration function on safe using execTransaction helper function
      await expect(
        execTransaction({
          owners: [owner],
          safe,
          to: await safePolicyGuard.getAddress(),
          data: safePolicyGuard.interface.encodeFunctionData('applyConfiguration', [configuration])
        })
      ).to.be.revertedWithCustomError(safePolicyGuard, 'RootNotConfigured') // Actual error is `RootNotConfigured`
    })

    it('Should not be able to apply configuration if the root configuration delay is not passed yet', async function () {
      const { owner, safePolicyGuard, safe, mockPolicy } = await loadFixture(fixture)

      // Configuration parameters
      const configuration = [
        createConfiguration({
          target: randomAddress(),
          selector: randomSelector(),
          policy: await mockPolicy.getAddress()
        })
      ]

      // Configuration root
      const configurationRoot = getConfigurationRoot(configuration)

      // Call the request configuration function on safe using execTransaction helper function
      await execTransaction({
        owners: [owner],
        safe,
        to: await safePolicyGuard.getAddress(),
        data: safePolicyGuard.interface.encodeFunctionData('requestConfiguration', [configurationRoot])
      })

      // Call the apply configuration function on safe using execTransaction helper function
      await expect(
        execTransaction({
          owners: [owner],
          safe,
          to: await safePolicyGuard.getAddress(),
          data: safePolicyGuard.interface.encodeFunctionData('applyConfiguration', [configuration])
        })
      ).to.be.revertedWithCustomError(safePolicyGuard, 'RootConfigurationPending') // Actual error is `RootConfigurationPending`
    })

    it('Should emit an event when the configuration is applied (confirmed)', async function () {
      const { owner, safePolicyGuard, safe, delay, mockPolicy } = await loadFixture(fixture)

      // Configuration parameters
      const configuration = [
        createConfiguration({
          target: randomAddress(),
          selector: randomSelector(),
          policy: await mockPolicy.getAddress()
        })
      ]

      // Configuration root
      const configurationRoot = getConfigurationRoot(configuration)

      // Call the request configuration function on safe using execTransaction helper function
      await execTransaction({
        owners: [owner],
        safe,
        to: await safePolicyGuard.getAddress(),
        data: safePolicyGuard.interface.encodeFunctionData('requestConfiguration', [configurationRoot])
      })

      // Increase the time to the delay
      await time.increase(delay)

      // Call the apply configuration function on safe using execTransaction helper function
      await expect(
        execTransaction({
          owners: [owner],
          safe,
          to: await safePolicyGuard.getAddress(),
          data: safePolicyGuard.interface.encodeFunctionData('applyConfiguration', [configuration])
        })
      )
        .to.emit(safePolicyGuard, 'PolicyConfirmed')
        .withArgs(
          await safe.getAddress(),
          configuration[0].target,
          configuration[0].selector,
          configuration[0].operation,
          configuration[0].policy,
          configuration[0].data
        )
    })

    it('Should emit an event with the root when the configuration is applied', async function () {
      const { owner, safePolicyGuard, safe, delay, mockPolicy } = await loadFixture(fixture)

      // Configuration parameters
      const configuration = [
        createConfiguration({
          target: randomAddress(),
          selector: randomSelector(),
          policy: await mockPolicy.getAddress()
        })
      ]

      // Configuration root
      const configurationRoot = getConfigurationRoot(configuration)

      // Call the request configuration function on safe using execTransaction helper function
      await execTransaction({
        owners: [owner],
        safe,
        to: await safePolicyGuard.getAddress(),
        data: safePolicyGuard.interface.encodeFunctionData('requestConfiguration', [configurationRoot])
      })

      // Increase the time to the delay
      await time.increase(delay)

      // Call the apply configuration function on safe using execTransaction helper function
      await expect(
        execTransaction({
          owners: [owner],
          safe,
          to: await safePolicyGuard.getAddress(),
          data: safePolicyGuard.interface.encodeFunctionData('applyConfiguration', [configuration])
        })
      )
        .to.emit(safePolicyGuard, 'RootApplied')
        .withArgs(await safe.getAddress(), configurationRoot)
    })

    it('Should not emit RootApplied when configuring immediately', async function () {
      const { owner, safePolicyGuard, safe, mockPolicy } = await loadFixture(fixture)

      // Configuration parameters
      const configuration = [
        createConfiguration({
          target: randomAddress(),
          selector: randomSelector(),
          policy: await mockPolicy.getAddress()
        })
      ]

      // `configureImmediately` bypasses the delay and has no root to report
      await expect(
        execTransaction({
          owners: [owner],
          safe,
          to: await safePolicyGuard.getAddress(),
          data: safePolicyGuard.interface.encodeFunctionData('configureImmediately', [configuration])
        })
      ).to.not.emit(safePolicyGuard, 'RootApplied')
    })
  })

  describe('invalidateRoot', function () {
    it('Should be able to invalidate configuration without guard', async function () {
      const { owner, safePolicyGuard, safe, mockPolicy } = await loadFixture(fixture)

      // Configuration parameters
      const configuration = [
        createConfiguration({
          target: randomAddress(),
          selector: randomSelector(),
          policy: await mockPolicy.getAddress()
        })
      ]

      // Configuration root
      const configurationRoot = getConfigurationRoot(configuration)

      // Call the request configuration function on safe using execTransaction helper function
      await execTransaction({
        owners: [owner],
        safe,
        to: await safePolicyGuard.getAddress(),
        data: safePolicyGuard.interface.encodeFunctionData('requestConfiguration', [configurationRoot])
      })

      // Call the invalidate root function on safe using execTransaction helper function
      await execTransaction({
        owners: [owner],
        safe,
        to: await safePolicyGuard.getAddress(),
        data: safePolicyGuard.interface.encodeFunctionData('invalidateRoot', [configurationRoot])
      })

      // Check if the configuration is invalidated
      const configurationApplyTimestamp = await safePolicyGuard.rootConfigured(
        await safe.getAddress(),
        configurationRoot
      )
      expect(configurationApplyTimestamp).to.equal(0)
    })

    it('Should be able to invalidate configuration with guard', async function () {
      const { owner, safePolicyGuard, safe, mockPolicy } = await loadFixture(fixture)

      // Configuration parameters
      const configuration = [
        createConfiguration({
          target: randomAddress(),
          selector: randomSelector(),
          policy: await mockPolicy.getAddress()
        })
      ]

      // Configuration root
      const configurationRoot = getConfigurationRoot(configuration)

      // Enable the guard on safe
      await enableGuard({ owner, safe, safePolicyGuard })

      // Call the request configuration function on safe using execTransaction helper function
      await execTransaction({
        owners: [owner],
        safe,
        to: await safePolicyGuard.getAddress(),
        data: safePolicyGuard.interface.encodeFunctionData('requestConfiguration', [configurationRoot])
      })

      // Call the invalidate root function on safe using execTransaction helper function
      await execTransaction({
        owners: [owner],
        safe,
        to: await safePolicyGuard.getAddress(),
        data: safePolicyGuard.interface.encodeFunctionData('invalidateRoot', [configurationRoot])
      })

      // Check if the configuration is invalidated
      const configurationApplyTimestamp = await safePolicyGuard.rootConfigured(
        await safe.getAddress(),
        configurationRoot
      )
      expect(configurationApplyTimestamp).to.equal(0)
    })

    it('Should not be able to invalidate configuration if the root is not configured', async function () {
      const { owner, safePolicyGuard, safe } = await loadFixture(fixture)

      // Configuration root
      const configurationRoot = getConfigurationRoot([])

      // Call the invalidate root function on safe using execTransaction helper function
      await expect(
        execTransaction({
          owners: [owner],
          safe,
          to: await safePolicyGuard.getAddress(),
          data: safePolicyGuard.interface.encodeFunctionData('invalidateRoot', [configurationRoot])
        })
      )
        .to.be.revertedWithCustomError(safePolicyGuard, 'RootNotConfigured')
        .withArgs(configurationRoot) // Actual error is `RootNotConfigured(configureRoot)`
    })

    it('Should emit an event when the configuration is invalidated', async function () {
      const { owner, safePolicyGuard, safe, mockPolicy } = await loadFixture(fixture)

      // Configuration parameters
      const configuration = [
        createConfiguration({
          target: randomAddress(),
          selector: randomSelector(),
          policy: await mockPolicy.getAddress()
        })
      ]

      // Configuration root
      const configurationRoot = getConfigurationRoot(configuration)

      // Call the request configuration function on safe using execTransaction helper function
      await execTransaction({
        owners: [owner],
        safe,
        to: await safePolicyGuard.getAddress(),
        data: safePolicyGuard.interface.encodeFunctionData('requestConfiguration', [configurationRoot])
      })

      // Call the invalidate root function on safe using execTransaction helper function
      await expect(
        execTransaction({
          owners: [owner],
          safe,
          to: await safePolicyGuard.getAddress(),
          data: safePolicyGuard.interface.encodeFunctionData('invalidateRoot', [configurationRoot])
        })
      )
        .to.emit(safePolicyGuard, 'RootInvalidated')
        .withArgs(await safe.getAddress(), configurationRoot)
    })
  })

  describe('checkTransaction', function () {
    it('Should be able to block normal transactions when guard is enabled', async function () {
      const { owner, safePolicyGuard, safe } = await loadFixture(fixture)

      // Enable the guard on safe
      await enableGuard({ owner, safe, safePolicyGuard })

      // Try to execute a transaction that is not configured
      await expect(
        execTransaction({
          owners: [owner],
          safe,
          to: randomAddress()
        })
      )
        .to.be.revertedWithCustomError(safePolicyGuard, 'AccessDenied')
        .withArgs(ZeroAddress)
    })

    it('Should revert when safeTxGas is non-zero', async function () {
      const { safePolicyGuard } = await loadFixture(fixture)

      // A non-zero `safeTxGas` must be rejected before any policy lookup. Call the transaction
      // guard entry point directly so the revert originates in the guard (not routed through a
      // full Safe execution).
      const checkTransaction = safePolicyGuard.getFunction(
        'checkTransaction(address,uint256,bytes,uint8,uint256,uint256,uint256,address,address,bytes,address)'
      )
      await expect(
        checkTransaction(
          randomAddress(),
          0n,
          '0x',
          SafeOperation.Call,
          1n,
          0n,
          0n,
          ZeroAddress,
          ZeroAddress,
          '0x',
          ZeroAddress
        )
      ).to.be.revertedWithCustomError(safePolicyGuard, 'NonZeroSafeTxGas')
    })

    it('Should revert when safeTxGas is non-zero through a Safe execution', async function () {
      // The unit test above asserts the ordering (rejected before policy lookup, since no policy is
      // configured there); this one asserts the Safe actually forwards `safeTxGas` to the guard.
      const { owner, safePolicyGuard, safe, mockPolicy } = await loadFixture(fixture)
      const target = randomAddress()
      await enableGuard({
        owner,
        safe,
        safePolicyGuard,
        configurations: [createConfiguration({ target, policy: await mockPolicy.getAddress() })]
      })

      await expect(
        execTransaction({ owners: [owner], safe, to: target, safeTxGas: 100_000n })
      ).to.be.revertedWithCustomError(safePolicyGuard, 'NonZeroSafeTxGas')
    })

    it('Should revert when gasPrice is non-zero', async function () {
      const { owner, safePolicyGuard, safe, mockPolicy } = await loadFixture(fixture)
      const target = randomAddress()
      await enableGuard({
        owner,
        safe,
        safePolicyGuard,
        configurations: [createConfiguration({ target, policy: await mockPolicy.getAddress() })]
      })

      await expect(execTransaction({ owners: [owner], safe, to: target, gasPrice: 1n })).to.be.revertedWithCustomError(
        safePolicyGuard,
        'NonZeroGasPrice'
      )
    })

    it('Should revert a direct engine checkTransaction outside a top-level check (NotChecking)', async function () {
      const { safePolicyGuard, safe } = await loadFixture(fixture)

      // The engine `checkTransaction` (6-arg) is only reachable while a top-level guard check is
      // in progress. Calling it directly (no `_enterCheck`) must revert.
      const engineCheck = safePolicyGuard.getFunction('checkTransaction(address,address,uint256,bytes,uint8,bytes)')
      await expect(
        engineCheck(await safe.getAddress(), randomAddress(), 0n, '0x', SafeOperation.Call, '0x')
      ).to.be.revertedWithCustomError(safePolicyGuard, 'NotChecking')
    })
  })

  describe('checkModuleTransaction', function () {
    it('Should be able to block module transactions when guard is enabled', async function () {
      const { owner, safePolicyGuard, safe } = await loadFixture(fixture)

      // Deploy Test Module
      const TestModuleFactory = await ethers.getContractFactory('TestModule')
      const testModule = await TestModuleFactory.deploy()

      // Enable the module on safe
      await execTransaction({
        owners: [owner],
        safe,
        to: await safe.getAddress(),
        data: safe.interface.encodeFunctionData('enableModule', [await testModule.getAddress()])
      })

      // Enable the guard on safe as ModuleGuard (Using Safe v1.5.0)
      await execTransaction({
        owners: [owner],
        safe,
        to: await safe.getAddress(),
        data: safe.interface.encodeFunctionData('setModuleGuard', [await safePolicyGuard.getAddress()])
      })

      // Try to execute a transaction that is not configured through the module
      await expect(testModule.executeTx(await safe.getAddress(), randomAddress(), 0, '0x', SafeOperation.Call))
        .to.be.revertedWithCustomError(safePolicyGuard, 'AccessDenied')
        .withArgs(ZeroAddress)
    })
  })

  describe('Guard removal', function () {
    it('Should remove the guard after the delay via a single batch', async function () {
      // The documented flow: request an AllowPolicy for `setGuard`, wait out the delay, then apply
      // it and remove the guard in one MultiSend.
      const { owner, safePolicyGuard, safe, delay } = await loadFixture(fixture)
      const { allowPolicy } = await deployAllowPolicy()
      const { multiSend } = await deploySafeContracts()

      await enableGuard({
        owner,
        safe,
        safePolicyGuard,
        configurations: [
          createConfiguration({
            target: await multiSend.getAddress(),
            selector: multiSend.interface.getFunction('multiSend')?.selector,
            operation: SafeOperation.DelegateCall,
            policy: await allowPolicy.getAddress()
          })
        ]
      })

      const configurations = [
        createConfiguration({
          target: await safe.getAddress(),
          selector: safe.interface.getFunction('setGuard')?.selector,
          policy: await allowPolicy.getAddress()
        })
      ]

      await execTransaction({
        owners: [owner],
        safe,
        to: await safePolicyGuard.getAddress(),
        data: safePolicyGuard.interface.encodeFunctionData('requestConfiguration', [
          getConfigurationRoot(configurations)
        ])
      })
      await time.increase(delay)

      const batch = await buildMultiSendSafeTx(
        multiSend,
        [
          buildSafeTransaction({
            to: await safePolicyGuard.getAddress(),
            data: safePolicyGuard.interface.encodeFunctionData('applyConfiguration', [configurations]),
            nonce: 0
          }),
          buildSafeTransaction({
            to: await safe.getAddress(),
            data: safe.interface.encodeFunctionData('setGuard', [ZeroAddress]),
            nonce: 1
          })
        ],
        await safe.nonce()
      )

      await execTransaction({
        owners: [owner],
        safe,
        to: await multiSend.getAddress(),
        data: batch.data,
        operation: SafeOperation.DelegateCall
      })

      expect(await getGuard(safe)).to.equal(ZeroAddress)
    })
  })

  describe('Context decoding', function () {
    // Context rides in the Safe `signatures` tail as a `SignatureExtension` envelope:
    // [payload][uint256 payloadLength][bytes32 typeHash]. The terminal type hash is what keeps
    // unrelated signature data -- an EIP-1271 contract signature, say -- from being read as context.
    //
    // These assert on the context the guard actually handed the policy, rather than on a downstream
    // policy's verdict, because two different decodings can produce the same verdict.
    async function contextFixture() {
      const base = await loadFixture(fixture)
      const { owner, safe, safePolicyGuard } = base

      const recorder = await (await ethers.getContractFactory('ContextRecorderPolicy')).deploy()
      const target = randomAddress()

      await enableGuard({
        owner,
        safe,
        safePolicyGuard,
        configurations: [createConfiguration({ target, policy: await recorder.getAddress() })]
      })

      return { ...base, recorder, target }
    }

    it('Should treat signatures not ending in the type hash as carrying no context', async function () {
      const { owner, safe, recorder, target } = await contextFixture()

      // A raw 32-byte tail appended with NO envelope -- structurally what an EIP-1271 contract
      // signature's trailing data looks like. The value is deliberately small enough to be a
      // plausible length: the previous format read this final word as one and would have sliced 32
      // bytes of the signature out as context.
      const signatures = ethers.solidityPacked(['bytes', 'uint256'], [await preApprovedSignature(owner), 32n])

      await safe
        .connect(owner)
        .execTransaction(target, 0n, '0x', SafeOperation.Call, 0n, 0n, 0n, ZeroAddress, ZeroAddress, signatures)

      expect(await recorder.lastContext()).to.equal('0x')
    })

    it('Should decode the payload of a well-formed envelope', async function () {
      const { owner, safe, recorder, target } = await contextFixture()
      const payload = ethers.id('some policy context')

      await execTransaction({ owners: [owner], safe, to: target, additionalData: payload })

      expect(await recorder.lastContext()).to.equal(payload)
    })

    it('Should revert on a malformed envelope claiming the type hash', async function () {
      const { owner, safe, safePolicyGuard, target } = await contextFixture()

      // Terminal word is the type hash, but the declared payload length runs past the front of the
      // blob. Claiming the type and then being malformed is an error, not "no context".
      const signatures = ethers.solidityPacked(
        ['bytes', 'uint256', 'bytes32'],
        [await preApprovedSignature(owner), ethers.MaxUint256, POLICY_CONTEXT_TYPE_HASH]
      )

      await expect(
        safe
          .connect(owner)
          .execTransaction(target, 0n, '0x', SafeOperation.Call, 0n, 0n, 0n, ZeroAddress, ZeroAddress, signatures)
      ).to.be.revertedWithCustomError(safePolicyGuard, 'MalformedSignatureExtension')
    })
  })

  describe('Execution outcome', function () {
    // Checks run pre-execution only, so a policy's writes commit with the transaction. These pin
    // that a failed execution still rolls them back on both authorization paths.
    async function statefulFixture() {
      const base = await loadFixture(fixture)
      const { owner, safe, safePolicyGuard } = base

      const statefulPolicy = await (await ethers.getContractFactory('ReentrantMockPolicy')).deploy()
      await statefulPolicy.setMode(ReentrantMockPolicyMode.WriteState)

      const testModule = await (await ethers.getContractFactory('TestModule')).deploy()

      await enableGuard({
        owner,
        safe,
        safePolicyGuard,
        configurations: [createConfiguration({ policy: await statefulPolicy.getAddress() })],
        module: await testModule.getAddress(),
        moduleGuard: true
      })

      // A contract with neither `receive` nor a matching function reverts on a 0-value empty call.
      const revertingTarget = await statefulPolicy.getAddress()

      return { ...base, statefulPolicy, testModule, revertingTarget }
    }

    it('Should revert a module transaction whose execution failed', async function () {
      const { safe, safePolicyGuard, statefulPolicy, testModule, revertingTarget } = await statefulFixture()

      expect(await statefulPolicy.writes()).to.equal(0n)

      // `execTransactionFromModule` returns `false` rather than reverting, so without the
      // after-execution check the policy's write would commit against an action that never happened.
      await expect(
        testModule.executeTx(await safe.getAddress(), revertingTarget, 0, '0x', SafeOperation.Call)
      ).to.be.revertedWithCustomError(safePolicyGuard, 'ModuleExecutionFailed')

      expect(await statefulPolicy.writes()).to.equal(0n)
    })

    it('Should keep a successful module transaction working', async function () {
      const { safe, statefulPolicy, testModule } = await statefulFixture()

      await testModule.executeTx(await safe.getAddress(), randomAddress(), 0, '0x', SafeOperation.Call)

      expect(await statefulPolicy.writes()).to.equal(1n)
    })

    it('Should revert a transaction whose execution failed', async function () {
      const { owner, safe, statefulPolicy, revertingTarget } = await statefulFixture()

      // The Safe already reverts this itself given `safeTxGas == 0` and `gasPrice == 0`; asserted
      // here as the transaction-path counterpart of the module case above.
      expect(await statefulPolicy.writes()).to.equal(0n)
      await expect(execTransaction({ owners: [owner], safe, to: revertingTarget })).to.be.reverted
      expect(await statefulPolicy.writes()).to.equal(0n)
    })

    it('Should reject the after-execution hooks reporting failure', async function () {
      const { safePolicyGuard } = await loadFixture(fixture)

      await expect(safePolicyGuard.checkAfterExecution(ethers.ZeroHash, false)).to.be.revertedWithCustomError(
        safePolicyGuard,
        'ExecutionFailed'
      )
      await expect(safePolicyGuard.checkAfterModuleExecution(ethers.ZeroHash, false)).to.be.revertedWithCustomError(
        safePolicyGuard,
        'ModuleExecutionFailed'
      )

      // Success is a no-op, so the hooks stay callable without any bookkeeping.
      await expect(safePolicyGuard.checkAfterExecution(ethers.ZeroHash, true)).to.not.be.reverted
      await expect(safePolicyGuard.checkAfterModuleExecution(ethers.ZeroHash, true)).to.not.be.reverted
    })
  })
})
