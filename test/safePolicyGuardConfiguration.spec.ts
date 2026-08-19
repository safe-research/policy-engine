import { loadFixture } from '@nomicfoundation/hardhat-network-helpers'
import { expect } from 'chai'
import { ZeroAddress } from 'ethers'
import { ethers } from 'hardhat'

import {
  createConfiguration,
  enableGuard,
  execTransaction,
  randomAddress,
  randomSelector,
  SafeOperation
} from '../src/utils'
import { deployAllowPolicy } from './deploy'
import { safePolicyGuardFixture as fixture } from './fixtures'

describe('SafePolicyGuard -- immediate configuration', function () {
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
      await enableGuard({ owners: [owner], safe, safePolicyGuard })

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
        owners: [owner],
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
        owners: [owner],
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
})
