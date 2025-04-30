import { loadFixture } from '@nomicfoundation/hardhat-network-helpers'
import { expect } from 'chai'
import { ZeroAddress } from 'ethers'
import { ethers } from 'hardhat'

import { createConfiguration, createSafe, execTransaction, randomAddress, SafeOperation } from '../src/utils'
import { deploySafeContracts, deploySafePolicyGuard, deployERC20ApprovePolicy, deployTestERC20Token } from './deploy'

describe('ERC20ApprovePolicy', function () {
  async function fixture() {
    const [, owner, spender, other] = await ethers.getSigners()

    // Deploy the SafePolicyGuard contract
    const { safePolicyGuard } = await deploySafePolicyGuard()

    // Deploy the Safe contracts
    const { safeProxyFactory, safe: safeSingleton } = await deploySafeContracts()
    const safe = await createSafe({
      owner,
      guard: ZeroAddress, // No guard at this point
      saltNonce: BigInt(0x3),
      safeProxyFactory,
      singleton: safeSingleton
    })

    // Deploy ERC20ApprovePolicy contract
    const { erc20ApprovePolicy } = await deployERC20ApprovePolicy()

    // Deploy Test ERC20 Token contract
    const { token } = await deployTestERC20Token()

    return {
      owner,
      spender,
      other,
      safe,
      safePolicyGuard,
      erc20ApprovePolicy,
      token
    }
  }

  describe('Integration with SafePolicyGuard', function () {
    it('Should allow approve transaction when spender is configured', async function () {
      const { owner, safePolicyGuard, safe, erc20ApprovePolicy, token } = await loadFixture(fixture)

      const spender = randomAddress()
      const amount = ethers.parseEther('100')

      // Configure the ERC20 approve policy
      const spenderData = [
        {
          spender,
          allowed: true
        }
      ]

      const configurations = [
        createConfiguration({
          target: await token.getAddress(),
          selector: token.interface.getFunction('approve').selector,
          policy: await erc20ApprovePolicy.getAddress(),
          data: ethers.AbiCoder.defaultAbiCoder().encode(['tuple(address spender, bool allowed)[]'], [spenderData])
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

      // Verify there was no previous approval
      expect(await token.allowance(await safe.getAddress(), spender)).to.equal(0)

      // Try to execute the approve transaction
      await execTransaction({
        owners: [owner],
        safe,
        to: await token.getAddress(),
        data: token.interface.encodeFunctionData('approve', [spender, amount])
      })

      // Verify the approval was successful
      expect(await token.allowance(await safe.getAddress(), spender)).to.equal(amount)
    })

    it('Should not allow approve transaction when spender is not configured', async function () {
      const { owner, safePolicyGuard, safe, erc20ApprovePolicy, token } = await loadFixture(fixture)

      const spender = randomAddress()
      const amount = ethers.parseEther('100')

      // Configure the ERC20 approve policy with no signer
      const spenderData: { spender: string; allowed: boolean }[] = []

      const configurations = [
        createConfiguration({
          target: await token.getAddress(),
          selector: token.interface.getFunction('approve').selector,
          policy: await erc20ApprovePolicy.getAddress(),
          data: ethers.AbiCoder.defaultAbiCoder().encode(['tuple(address spender, bool allowed)[]'], [spenderData])
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

      // Try to execute the approve transaction
      await expect(
        execTransaction({
          owners: [owner],
          safe,
          to: await token.getAddress(),
          data: token.interface.encodeFunctionData('approve', [spender, amount])
        })
      ).to.be.revertedWithCustomError(safePolicyGuard, 'AccessDenied')
    })

    it('Should not allow non-approve transactions', async function () {
      const { owner, safePolicyGuard, safe, erc20ApprovePolicy, token } = await loadFixture(fixture)

      const spender = randomAddress()
      const amount = ethers.parseEther('100')

      // Configure the ERC20 approve policy
      const spenderData = [
        {
          spender,
          allowed: true
        }
      ]

      const configurations = [
        createConfiguration({
          target: await token.getAddress(),
          selector: token.interface.getFunction('approve').selector,
          policy: await erc20ApprovePolicy.getAddress(),
          data: ethers.AbiCoder.defaultAbiCoder().encode(['tuple(address spender, bool allowed)[]'], [spenderData])
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

      // Try to execute a transfer transaction (non-approve)
      await expect(
        execTransaction({
          owners: [owner],
          safe,
          to: await token.getAddress(),
          data: token.interface.encodeFunctionData('transfer', [spender, amount])
        })
      ).to.be.revertedWithCustomError(safePolicyGuard, 'AccessDenied')
    })

    it('Should allow zero amount approvals even for unconfigured spenders', async function () {
      const { owner, safePolicyGuard, safe, erc20ApprovePolicy, token } = await loadFixture(fixture)

      const spender = randomAddress()
      const amount = ethers.parseEther('1')

      // Configure the ERC20 approve policy with no spender
      const spenderData: { spender: string; allowed: boolean }[] = []

      const configurations = [
        createConfiguration({
          target: await token.getAddress(),
          selector: token.interface.getFunction('approve').selector,
          policy: await erc20ApprovePolicy.getAddress(),
          data: ethers.AbiCoder.defaultAbiCoder().encode(['tuple(address spender, bool allowed)[]'], [spenderData])
        })
      ]

      // Approve the amount for the configured spender in Safe
      await execTransaction({
        owners: [owner],
        safe,
        to: await token.getAddress(),
        data: token.interface.encodeFunctionData('approve', [spender, amount])
      })

      // Verify the approval was successful
      expect(await token.allowance(await safe.getAddress(), spender)).to.equal(amount)

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

      // Try to execute the zero amount approve transaction
      await execTransaction({
        owners: [owner],
        safe,
        to: await token.getAddress(),
        data: token.interface.encodeFunctionData('approve', [spender, 0])
      })

      // Verify the approval was successful
      expect(await token.allowance(await safe.getAddress(), spender)).to.equal(0)
    })
  })
  describe('Policy Configuration', function () {
    it('Should only be able to configure ERC20 approve transactions', async function () {
      const { owner, safePolicyGuard, safe, erc20ApprovePolicy, token } = await loadFixture(fixture)

      // Configure the ERC20 approve policy
      const spenderData = [
        {
          spender: randomAddress(),
          allowed: true
        }
      ]

      // Trying to configure a non-approve transaction
      const configurations = [
        createConfiguration({
          target: await token.getAddress(),
          selector: token.interface.getFunction('transfer').selector, // Non-approve function
          policy: await erc20ApprovePolicy.getAddress(),
          data: ethers.AbiCoder.defaultAbiCoder().encode(['tuple(address spender, bool allowed)[]'], [spenderData])
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
      ).to.be.revertedWithCustomError(erc20ApprovePolicy, 'InvalidSelector')
    })

    it('Should only be able to configure CALL operations', async function () {
      const { owner, safePolicyGuard, safe, erc20ApprovePolicy, token } = await loadFixture(fixture)

      // Configure the ERC20 approve policy
      const spenderData = [
        {
          spender: randomAddress(),
          allowed: true
        }
      ]

      // Trying to configure a non-approve transaction
      const configurations = [
        createConfiguration({
          target: await token.getAddress(),
          selector: token.interface.getFunction('approve').selector,
          policy: await erc20ApprovePolicy.getAddress(),
          data: ethers.AbiCoder.defaultAbiCoder().encode(['tuple(address spender, bool allowed)[]'], [spenderData]),
          operation: SafeOperation.DelegateCall // Non-CALL operation
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
      ).to.be.revertedWithCustomError(erc20ApprovePolicy, 'InvalidOperation')
    })
  })
})
