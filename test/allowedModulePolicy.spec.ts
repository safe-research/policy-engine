import { loadFixture } from '@nomicfoundation/hardhat-network-helpers'
import { expect } from 'chai'
import { ZeroAddress } from 'ethers'
import { ethers } from 'hardhat'

import { createConfiguration, createSafe, execTransaction, randomAddress, SafeOperation } from '../src/utils'
import { deploySafePolicyGuard, deploySafeContracts, deployAllowedModulePolicy } from './deploy'

describe('AllowedModulePolicy', function () {
  async function fixture() {
    const [, owner, other] = await ethers.getSigners()

    // Deploy the SafePolicyGuard contract
    const { safePolicyGuard } = await deploySafePolicyGuard()

    // Deploy the Safe contracts
    const { safeProxyFactory, safe: safeSingleton } = await deploySafeContracts()
    const safe = await createSafe({
      owner,
      guard: ZeroAddress, // No guard at this point
      saltNonce: BigInt(0x8),
      safeProxyFactory,
      singleton: safeSingleton
    })

    // Deploy AllowedModulePolicy contract
    const { allowedModulePolicy } = await deployAllowedModulePolicy()

    // Deploy TestModule contract
    const TestModuleFactory = await ethers.getContractFactory('TestModule')
    const testModule = await TestModuleFactory.deploy()

    return {
      owner,
      other,
      safePolicyGuard,
      safe,
      allowedModulePolicy,
      testModule
    }
  }

  describe('Unit tests', function () {
    it('Should not allow a module that was not configured', async function () {
      const { owner, safe, allowedModulePolicy, testModule } = await loadFixture(fixture)

      const safeAddress = await safe.getAddress()
      const moduleAddress = await testModule.getAddress()
      const randomModuleAddress = randomAddress()

      // Configure only one module
      await allowedModulePolicy.connect(owner).configure(
        safeAddress,
        0, // AccessSelector doesn't matter for this policy
        ethers.AbiCoder.defaultAbiCoder().encode(['address'], [moduleAddress])
      )

      // Check that the configured module is allowed
      expect(await allowedModulePolicy.isModuleAllowed(owner, safeAddress, moduleAddress)).to.be.true

      // Check that the random module is not allowed
      expect(await allowedModulePolicy.isModuleAllowed(owner, safeAddress, randomModuleAddress)).to.be.false
    })

    it('Should return the magic value for allowed module in checkTransaction', async function () {
      const { safe, allowedModulePolicy, testModule } = await loadFixture(fixture)

      const safeAddress = await safe.getAddress()
      const moduleAddress = await testModule.getAddress()

      // Configure the module
      await allowedModulePolicy.configure(
        safeAddress,
        0, // AccessSelector doesn't matter for this policy
        ethers.AbiCoder.defaultAbiCoder().encode(['address'], [moduleAddress])
      )

      // Create context with module address
      const context = ethers.AbiCoder.defaultAbiCoder().encode(['address'], [moduleAddress])

      // Call checkTransaction and verify it returns the magic value
      const result = await allowedModulePolicy.checkTransaction(
        safeAddress,
        randomAddress(), // to address (doesn't matter for this policy)
        0, // value (doesn't matter for this policy)
        '0x', // data (doesn't matter for this policy)
        SafeOperation.Call,
        context,
        0 // AccessSelector.T (doesn't matter for this policy)
      )

      // This should match IPolicy.checkTransaction.selector
      expect(result).to.equal('0x2c5dcbd7')
    })

    it('Should revert on checkTransaction for non-allowed module', async function () {
      const { safe, allowedModulePolicy } = await loadFixture(fixture)

      const safeAddress = await safe.getAddress()
      const randomModuleAddress = randomAddress()

      // Create context with a random non-configured module address
      const context = ethers.AbiCoder.defaultAbiCoder().encode(['address'], [randomModuleAddress])

      // Call checkTransaction and expect it to revert
      await expect(
        allowedModulePolicy.checkTransaction(safeAddress, randomAddress(), 0, '0x', SafeOperation.Call, context, 0)
      ).to.be.revertedWithCustomError(allowedModulePolicy, 'UnauthorizedModule')
    })
  })

  describe('Integration with SafePolicyGuard', function () {
    it('Should allow transactions from configured modules', async function () {
      const { owner, safe, safePolicyGuard, allowedModulePolicy, testModule } = await loadFixture(fixture)

      const testModuleAddress = await testModule.getAddress()
      const target = randomAddress()

      // Enable the module on safe
      await execTransaction({
        owners: [owner],
        safe,
        to: await safe.getAddress(),
        data: safe.interface.encodeFunctionData('enableModule', [testModuleAddress])
      })

      const configurations = [
        createConfiguration({
          target: target,
          policy: await allowedModulePolicy.getAddress(),
          data: ethers.AbiCoder.defaultAbiCoder().encode(['address'], [testModuleAddress])
        })
      ]

      // Configure the policy with our test module directly
      await execTransaction({
        owners: [owner],
        safe,
        to: await safePolicyGuard.getAddress(),
        data: safePolicyGuard.interface.encodeFunctionData('configureImmediately', [configurations])
      })

      // Set the module as allowed for this safe in the policy
      expect(
        await allowedModulePolicy.isModuleAllowed(
          await safePolicyGuard.getAddress(),
          await safe.getAddress(),
          testModuleAddress
        )
      ).to.be.true

      // Enable the guard specifically for modules
      await execTransaction({
        owners: [owner],
        safe,
        to: await safe.getAddress(),
        data: safe.interface.encodeFunctionData('setModuleGuard', [await safePolicyGuard.getAddress()])
      })

      // The module transaction should succeed
      await testModule.executeTx(await safe.getAddress(), target, 0, '0x', SafeOperation.Call)
    })

    it('Should block transactions from unauthorized modules', async function () {
      const { owner, safe, safePolicyGuard, allowedModulePolicy } = await loadFixture(fixture)

      const unauthorizedModule = await (await ethers.getContractFactory('TestModule')).deploy()
      const unauthorizedModuleAddress = await unauthorizedModule.getAddress()
      const testModuleAddress = randomAddress() // Different module address
      const target = randomAddress()

      // Enable the module on safe
      await execTransaction({
        owners: [owner],
        safe,
        to: await safe.getAddress(),
        data: safe.interface.encodeFunctionData('enableModule', [unauthorizedModuleAddress])
      })

      const configurations = [
        createConfiguration({
          target: target,
          policy: await allowedModulePolicy.getAddress(),
          data: ethers.AbiCoder.defaultAbiCoder().encode(['address'], [testModuleAddress])
        })
      ]

      // Set up the guard with the policy for test module
      await execTransaction({
        owners: [owner],
        safe,
        to: await safePolicyGuard.getAddress(),
        data: safePolicyGuard.interface.encodeFunctionData('configureImmediately', [configurations])
      })

      // Enable the guard for modules
      await execTransaction({
        owners: [owner],
        safe,
        to: await safe.getAddress(),
        data: safe.interface.encodeFunctionData('setModuleGuard', [await safePolicyGuard.getAddress()])
      })

      // The module is not in the allowed list, so it should be blocked
      await expect(
        unauthorizedModule.executeTx(await safe.getAddress(), target, 0, '0x', SafeOperation.Call)
      ).to.be.revertedWithCustomError(safePolicyGuard, 'AccessDenied')
    })
  })
})
