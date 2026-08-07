import { loadFixture, time } from '@nomicfoundation/hardhat-network-helpers'
import { expect } from 'chai'
import { ZeroAddress } from 'ethers'
import { ethers } from 'hardhat'

import {
  createConfiguration,
  createSafe,
  execTransaction,
  getConfigurationRoot,
  randomAddress,
  randomSelector,
  SafeOperation
} from '../src/utils'
import { deployAllowPolicy, deploySafePolicyGuard, deploySafeContracts, deployMockPolicy } from './deploy'

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
      await execTransaction({
        owners: [owner],
        safe,
        to: await safe.getAddress(),
        data: safe.interface.encodeFunctionData('setGuard', [await safePolicyGuard.getAddress()])
      })

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

      await execTransaction({
        owners: [owner],
        safe,
        to: guardAddress,
        data: safePolicyGuard.interface.encodeFunctionData('configureImmediately', [
          [createConfiguration({ policy: await mockPolicy.getAddress() })]
        ])
      })
      await execTransaction({
        owners: [owner],
        safe,
        to: await safe.getAddress(),
        data: safe.interface.encodeFunctionData('setGuard', [guardAddress])
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
      await execTransaction({
        owners: [owner],
        safe,
        to: guardAddress,
        data: safePolicyGuard.interface.encodeFunctionData('configureImmediately', [
          [
            createConfiguration({
              target: await safe.getAddress(),
              selector: safe.interface.getFunction('setGuard')?.selector,
              policy: await allowPolicy.getAddress()
            })
          ]
        ])
      })
      await execTransaction({
        owners: [owner],
        safe,
        to: await safe.getAddress(),
        data: safe.interface.encodeFunctionData('setGuard', [guardAddress])
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
      await execTransaction({
        owners: [owner],
        safe,
        to: await safe.getAddress(),
        data: safe.interface.encodeFunctionData('setGuard', [await safePolicyGuard.getAddress()])
      })

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
      await execTransaction({
        owners: [owner],
        safe,
        to: await safe.getAddress(),
        data: safe.interface.encodeFunctionData('setGuard', [await safePolicyGuard.getAddress()])
      })

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
      await execTransaction({
        owners: [owner],
        safe,
        to: await safe.getAddress(),
        data: safe.interface.encodeFunctionData('setGuard', [await safePolicyGuard.getAddress()])
      })

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
      await execTransaction({
        owners: [owner],
        safe,
        to: await safe.getAddress(),
        data: safe.interface.encodeFunctionData('setGuard', [await safePolicyGuard.getAddress()])
      })

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
})
