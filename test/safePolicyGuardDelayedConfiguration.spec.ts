import { loadFixture, time } from '@nomicfoundation/hardhat-network-helpers'
import { expect } from 'chai'

import { ONE_DAY_IN_SECONDS } from '../lib/constants'
import {
  createConfiguration,
  enableGuard,
  execTransaction,
  getConfigurationRoot,
  randomAddress,
  randomSelector
} from '../src/utils'
import { deploySafePolicyGuard } from './deploy'
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
      await enableGuard({ owners: [owner], safe, safePolicyGuard })

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
      await enableGuard({ owners: [owner], safe, safePolicyGuard })

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
      await enableGuard({ owners: [owner], safe, safePolicyGuard })

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
  describe('Application window', function () {
    // A matured root stays applicable for EXPIRY and is then dead, so a root requested during a
    // past compromise cannot be held in reserve and applied instantly later.
    async function requestedRoot() {
      const ctx = await loadFixture(fixture)
      const configuration = [
        createConfiguration({
          target: randomAddress(),
          selector: randomSelector(),
          policy: await ctx.mockPolicy.getAddress()
        })
      ]
      const root = getConfigurationRoot(configuration)
      await ctx.safePolicyGuard.connect(ctx.owner).requestConfiguration(root)
      return { ...ctx, configuration, root }
    }

    it('Should apply at the start of the window', async function () {
      const { owner, safePolicyGuard, delay, configuration } = await requestedRoot()

      await time.increase(delay)
      await expect(safePolicyGuard.connect(owner).applyConfiguration(configuration)).to.emit(
        safePolicyGuard,
        'RootApplied'
      )
    })

    it('Should apply just before the window closes', async function () {
      const { owner, safePolicyGuard, delay, expiry, configuration } = await requestedRoot()

      // The window is half-open: applicable for `expiry` seconds from maturity.
      await time.increase(delay + expiry - 2n)
      await expect(safePolicyGuard.connect(owner).applyConfiguration(configuration)).to.emit(
        safePolicyGuard,
        'RootApplied'
      )
    })

    it('Should reject a root past its window', async function () {
      const { owner, safePolicyGuard, delay, expiry, configuration } = await requestedRoot()

      await time.increase(delay + expiry)
      await expect(safePolicyGuard.connect(owner).applyConfiguration(configuration)).to.be.revertedWithCustomError(
        safePolicyGuard,
        'RootConfigurationExpired'
      )
    })

    it('Should let an expired root be requested again without invalidating it', async function () {
      const { owner, safePolicyGuard, delay, expiry, configuration, root } = await requestedRoot()

      await time.increase(delay + expiry)
      await expect(safePolicyGuard.connect(owner).requestConfiguration(root)).to.emit(safePolicyGuard, 'RootConfigured')

      // The fresh request restarts the delay, so it is not immediately applicable.
      await expect(safePolicyGuard.connect(owner).applyConfiguration(configuration)).to.be.revertedWithCustomError(
        safePolicyGuard,
        'RootConfigurationPending'
      )

      await time.increase(delay)
      await expect(safePolicyGuard.connect(owner).applyConfiguration(configuration)).to.emit(
        safePolicyGuard,
        'RootApplied'
      )
    })

    it('Should still reject re-requesting a root inside its window', async function () {
      const { owner, safePolicyGuard, delay, root } = await requestedRoot()

      await time.increase(delay)
      await expect(safePolicyGuard.connect(owner).requestConfiguration(root))
        .to.be.revertedWithCustomError(safePolicyGuard, 'RootAlreadyConfigured')
        .withArgs(root)
    })

    it('Should expire a root even when there is no delay', async function () {
      // The window is independent of the delay. A guard with no waiting period still expires its
      // requests -- otherwise a zero-delay deployment would silently keep roots alive forever.
      const { owner, mockPolicy } = await loadFixture(fixture)
      const { safePolicyGuard: noDelayGuard } = await deploySafePolicyGuard({ delay: 0n, expiry: ONE_DAY_IN_SECONDS })

      const configuration = [
        createConfiguration({
          target: randomAddress(),
          selector: randomSelector(),
          policy: await mockPolicy.getAddress()
        })
      ]
      const root = getConfigurationRoot(configuration)

      await noDelayGuard.connect(owner).requestConfiguration(root)
      await time.increase(ONE_DAY_IN_SECONDS)

      await expect(noDelayGuard.connect(owner).applyConfiguration(configuration)).to.be.revertedWithCustomError(
        noDelayGuard,
        'RootConfigurationExpired'
      )
    })

    it('Should still allow an expired root to be invalidated', async function () {
      const { owner, safePolicyGuard, delay, expiry, root } = await requestedRoot()

      await time.increase(delay + expiry)
      await expect(safePolicyGuard.connect(owner).invalidateRoot(root)).to.emit(safePolicyGuard, 'RootInvalidated')
      expect(await safePolicyGuard.rootConfigured(owner, root)).to.equal(0n)
    })
  })
})
