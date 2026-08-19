import { loadFixture, time } from '@nomicfoundation/hardhat-network-helpers'
import { expect } from 'chai'

import {
  createConfiguration,
  enableGuard,
  execTransaction,
  getConfigurationRoot,
  randomAddress,
  randomSelector
} from '../src/utils'
import { safePolicyGuardFixture as fixture } from './fixtures'

describe('SafePolicyGuard -- delayed configuration', function () {
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
})
