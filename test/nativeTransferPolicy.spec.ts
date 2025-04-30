import { loadFixture } from '@nomicfoundation/hardhat-network-helpers'
import { expect } from 'chai'
import { ZeroAddress } from 'ethers'
import { ethers } from 'hardhat'

import { createConfiguration, createSafe, execTransaction, SafeOperation } from '../src/utils'
import { deploySafeContracts, deploySafePolicyGuard, deployNativeTransferPolicy } from './deploy'

describe('NativeTransferPolicy', function () {
  async function fixture() {
    const [, owner, recipient, other] = await ethers.getSigners()

    // Deploy the SafePolicyGuard contract
    const { safePolicyGuard } = await deploySafePolicyGuard()

    // Deploy the Safe contracts
    const { safeProxyFactory, safe: safeSingleton } = await deploySafeContracts()
    const safe = await createSafe({
      owner,
      guard: ZeroAddress, // No guard at this point
      saltNonce: BigInt(0x5),
      safeProxyFactory,
      singleton: safeSingleton
    })

    // Deploy NativeTransferPolicy contract
    const { nativeTransferPolicy } = await deployNativeTransferPolicy()

    // Fund the Safe with some ETH
    await owner.sendTransaction({
      to: await safe.getAddress(),
      value: ethers.parseEther('10')
    })

    return {
      owner,
      recipient,
      other,
      safe,
      safePolicyGuard,
      nativeTransferPolicy
    }
  }

  describe('Integration with SafePolicyGuard', function () {
    it('Should allow native transfer with value > 0', async function () {
      const { owner, recipient, safePolicyGuard, safe, nativeTransferPolicy } = await loadFixture(fixture)

      const amount = ethers.parseEther('1')

      // Configure the native transfer policy
      const configurations = [
        createConfiguration({
          policy: await nativeTransferPolicy.getAddress()
        })
      ]

      // Configure the policy
      await execTransaction({
        owners: [owner],
        safe,
        to: await safePolicyGuard.getAddress(),
        data: safePolicyGuard.interface.encodeFunctionData('configureImmediately', [configurations])
      })

      // Enable the guard on safe
      await execTransaction({
        owners: [owner],
        safe,
        to: await safe.getAddress(),
        data: safe.interface.encodeFunctionData('setGuard', [await safePolicyGuard.getAddress()])
      })

      // Get initial balances
      const initialRecipientBalance = await ethers.provider.getBalance(await recipient.getAddress())
      const initialSafeBalance = await ethers.provider.getBalance(await safe.getAddress())

      // Execute the native transfer transaction
      await execTransaction({
        owners: [owner],
        safe,
        to: await recipient.getAddress(),
        value: amount
      })

      // Verify the transfer was successful
      const finalRecipientBalance = await ethers.provider.getBalance(await recipient.getAddress())
      const finalSafeBalance = await ethers.provider.getBalance(await safe.getAddress())

      expect(finalRecipientBalance - initialRecipientBalance).to.equal(amount)
      expect(initialSafeBalance - finalSafeBalance).to.equal(amount)
    })

    it('Should not allow native transfer with value = 0', async function () {
      const { owner, recipient, safePolicyGuard, safe, nativeTransferPolicy } = await loadFixture(fixture)

      // Configure the native transfer policy
      const configurations = [
        createConfiguration({
          policy: await nativeTransferPolicy.getAddress()
        })
      ]

      // Configure the policy
      await execTransaction({
        owners: [owner],
        safe,
        to: await safePolicyGuard.getAddress(),
        data: safePolicyGuard.interface.encodeFunctionData('configureImmediately', [configurations])
      })

      // Enable the guard on safe
      await execTransaction({
        owners: [owner],
        safe,
        to: await safe.getAddress(),
        data: safe.interface.encodeFunctionData('setGuard', [await safePolicyGuard.getAddress()])
      })

      // Try to execute a native transfer transaction with zero value (Default value is 0)
      await expect(
        execTransaction({
          owners: [owner],
          safe,
          to: await recipient.getAddress()
        })
      ).to.be.revertedWithCustomError(safePolicyGuard, 'AccessDenied')
    })

    it('Should not allow non-native transfer transactions', async function () {
      const { owner, recipient, safePolicyGuard, safe, nativeTransferPolicy } = await loadFixture(fixture)

      const amount = ethers.parseEther('1')

      // Configure the native transfer policy
      const configurations = [
        createConfiguration({
          policy: await nativeTransferPolicy.getAddress()
        })
      ]

      // Configure the policy
      await execTransaction({
        owners: [owner],
        safe,
        to: await safePolicyGuard.getAddress(),
        data: safePolicyGuard.interface.encodeFunctionData('configureImmediately', [configurations])
      })

      // Enable the guard on safe
      await execTransaction({
        owners: [owner],
        safe,
        to: await safe.getAddress(),
        data: safe.interface.encodeFunctionData('setGuard', [await safePolicyGuard.getAddress()])
      })

      // Try to execute a transaction with data (non-native transfer)
      await expect(
        execTransaction({
          owners: [owner],
          safe,
          to: await recipient.getAddress(),
          value: amount,
          data: '0x1234' // Non-empty data
        })
      ).to.be.revertedWithCustomError(safePolicyGuard, 'InvalidSelector')
    })
  })

  describe('Policy Configuration', function () {
    it('Should only be able to configure native transfer transactions', async function () {
      const { owner, safePolicyGuard, safe, nativeTransferPolicy } = await loadFixture(fixture)

      // Trying to configure with non-zero selector
      const configurations = [
        createConfiguration({
          selector: '0x12345678', // Non-zero selector
          policy: await nativeTransferPolicy.getAddress()
        })
      ]

      // Configure the policy
      await expect(
        execTransaction({
          owners: [owner],
          safe,
          to: await safePolicyGuard.getAddress(),
          data: safePolicyGuard.interface.encodeFunctionData('configureImmediately', [configurations])
        })
      ).to.be.revertedWithCustomError(safePolicyGuard, 'PolicyConfigurationFailed')
    })

    it('Should only allow CALL operations', async function () {
      const { owner, safePolicyGuard, safe, nativeTransferPolicy } = await loadFixture(fixture)

      // Trying to configure with DELEGATECALL operation
      const configurations = [
        createConfiguration({
          operation: SafeOperation.DelegateCall,
          policy: await nativeTransferPolicy.getAddress()
        })
      ]

      // Configure the policy
      await expect(
        execTransaction({
          owners: [owner],
          safe,
          to: await safePolicyGuard.getAddress(),
          data: safePolicyGuard.interface.encodeFunctionData('configureImmediately', [configurations])
        })
      ).to.be.revertedWithCustomError(safePolicyGuard, 'PolicyConfigurationFailed')
    })
  })
})
