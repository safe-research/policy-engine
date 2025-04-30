import { loadFixture } from '@nomicfoundation/hardhat-network-helpers'
import { expect } from 'chai'
import { ZeroAddress } from 'ethers'
import { ethers } from 'hardhat'

import { createConfiguration, createSafe, execTransaction, randomAddress } from '../src/utils'
import { deploySafePolicyGuard, deploySafeContracts, deployAllowPolicy } from './deploy'

describe('AllowPolicy', function () {
  async function fixture() {
    const [, owner, other] = await ethers.getSigners()

    // Deploy the SafePolicyGuard contract
    const { safePolicyGuard } = await deploySafePolicyGuard()

    // Deploy the Safe contracts
    const { safeProxyFactory, safe: safeSingleton } = await deploySafeContracts()
    const safe = await createSafe({
      owner,
      guard: ZeroAddress, // No guard at this point
      saltNonce: BigInt(0x2),
      safeProxyFactory,
      singleton: safeSingleton
    })

    // Deploy AllowPolicy contract
    const { allowPolicy } = await deployAllowPolicy()

    // Deploy Test Access Selector
    const AccessSelectorFactory = await ethers.getContractFactory('TestAccessSelector')
    const accessSelector = await AccessSelectorFactory.deploy()

    return { owner, other, safePolicyGuard, safe, allowPolicy, accessSelector }
  }

  describe('Integration with SafePolicyGuard', function () {
    it('Should allow particular transaction when configured through allow policy', async function () {
      const { owner, safePolicyGuard, safe, allowPolicy } = await loadFixture(fixture)

      const target = randomAddress()
      const value = ethers.parseEther('1')

      const configurations = [createConfiguration({ target, policy: await allowPolicy.getAddress() })]

      // Configure the allow policy to send some value to the target
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

      // Send some ETH from owner to the safe for next transaction
      await owner.sendTransaction({
        to: await safe.getAddress(),
        value
      })

      // Try to execute the particular transaction
      await execTransaction({
        owners: [owner],
        safe,
        to: target,
        value
      })

      // Verify the transaction was executed by checking the target's balance
      expect(await ethers.provider.getBalance(target)).to.equal(value)
    })

    it('Should not allow any transaction which is not configured through allow policy', async function () {
      const { owner, safe, safePolicyGuard } = await loadFixture(fixture)

      const target = randomAddress()
      const value = ethers.parseEther('1')

      // Enable the guard on safe
      await execTransaction({
        owners: [owner],
        safe,
        to: await safe.getAddress(),
        data: safe.interface.encodeFunctionData('setGuard', [await safePolicyGuard.getAddress()])
      })

      // Try to execute a random transaction
      await expect(
        execTransaction({
          owners: [owner],
          safe,
          to: target,
          value
        })
      )
        .to.be.revertedWithCustomError(safePolicyGuard, 'AccessDenied')
        .withArgs(ZeroAddress)
    })
  })
})
