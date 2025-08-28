import { loadFixture } from '@nomicfoundation/hardhat-network-helpers'
import { expect } from 'chai'
import { ZeroAddress } from 'ethers'
import { ethers } from 'hardhat'

import { createConfiguration, createSafe, execTransaction, randomAddress } from '../src/utils'
import { deploySafePolicyGuard, deploySafeContracts, deployAllowPolicy, deployDenyPolicy } from './deploy'

describe('DenyPolicy', function () {
  async function fixture() {
    const [, owner, other] = await ethers.getSigners()

    // Deploy the SafePolicyGuard contract
    const { safePolicyGuard } = await deploySafePolicyGuard()

    // Deploy the Safe contracts
    const { safeProxyFactory, safe: safeSingleton } = await deploySafeContracts()
    const safe = await createSafe({
      owner,
      guard: ZeroAddress, // No guard at this point
      saltNonce: BigInt(0xa),
      safeProxyFactory,
      singleton: safeSingleton
    })

    // Deploy AllowPolicy contract
    const { allowPolicy } = await deployAllowPolicy()
    const { denyPolicy } = await deployDenyPolicy()

    // Deploy Test Access Selector
    const AccessSelectorFactory = await ethers.getContractFactory('TestAccessSelector')
    const accessSelector = await AccessSelectorFactory.deploy()

    // Configure the AllowPolicy as a fallback to allow any transactions
    const configurations = [createConfiguration({ policy: await allowPolicy.getAddress() })]
    await execTransaction({
      owners: [owner],
      safe,
      to: await safePolicyGuard.getAddress(),
      data: safePolicyGuard.interface.encodeFunctionData('configureImmediately', [configurations])
    })

    return { owner, other, safePolicyGuard, safe, denyPolicy, accessSelector }
  }

  describe('Integration with SafePolicyGuard', function () {
    it('Should deny particular transaction when configured through deny policy', async function () {
      const { owner, safePolicyGuard, safe, denyPolicy } = await loadFixture(fixture)

      const target = randomAddress()
      const value = ethers.parseEther('1')

      const configurations = [createConfiguration({ target, policy: await denyPolicy.getAddress() })]

      // Configure the deny policy to send some value to the target
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
      await expect(
        execTransaction({
          owners: [owner],
          safe,
          to: target,
          value
        })
      )
        .to.be.revertedWithCustomError(safePolicyGuard, 'AccessDenied')
        .withArgs(denyPolicy)

      // Verify the transaction was not executed by checking the target's balance
      expect(await ethers.provider.getBalance(target)).to.equal(0n)
    })
  })
})
