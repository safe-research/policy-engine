import { loadFixture } from '@nomicfoundation/hardhat-network-helpers'
import { expect } from 'chai'
import { ZeroAddress } from 'ethers'
import { ethers } from 'hardhat'

import {
  createConfiguration,
  createSafe,
  encodeAllowlistConfig,
  execTransaction,
  randomAddress,
  SafeOperation
} from '../src/utils'
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
      const configurations = [
        createConfiguration({
          target: await token.getAddress(),
          selector: token.interface.getFunction('approve').selector,
          policy: await erc20ApprovePolicy.getAddress(),
          data: encodeAllowlistConfig([spender])
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

      // Configure the ERC20 approve policy with no spender
      const configurations = [
        createConfiguration({
          target: await token.getAddress(),
          selector: token.interface.getFunction('approve').selector,
          policy: await erc20ApprovePolicy.getAddress(),
          data: encodeAllowlistConfig([])
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
      )
        .to.be.revertedWithCustomError(safePolicyGuard, 'PolicyReverted')
        .withArgs(
          await erc20ApprovePolicy.getAddress(),
          erc20ApprovePolicy.interface.encodeErrorResult('Unauthorized', [])
        )
    })

    it('Should not allow non-approve transactions', async function () {
      const { owner, safePolicyGuard, safe, erc20ApprovePolicy, token } = await loadFixture(fixture)

      const spender = randomAddress()
      const amount = ethers.parseEther('100')

      // Configure the ERC20 approve policy
      const configurations = [
        createConfiguration({
          target: await token.getAddress(),
          selector: token.interface.getFunction('approve').selector,
          policy: await erc20ApprovePolicy.getAddress(),
          data: encodeAllowlistConfig([spender])
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
      const configurations = [
        createConfiguration({
          target: await token.getAddress(),
          selector: token.interface.getFunction('approve').selector,
          policy: await erc20ApprovePolicy.getAddress(),
          data: encodeAllowlistConfig([])
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

      // Trying to configure a non-approve transaction
      const configurations = [
        createConfiguration({
          target: await token.getAddress(),
          selector: token.interface.getFunction('transfer').selector, // Non-approve function
          policy: await erc20ApprovePolicy.getAddress(),
          data: encodeAllowlistConfig([randomAddress()])
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

      // Trying to configure a DELEGATECALL operation
      const configurations = [
        createConfiguration({
          target: await token.getAddress(),
          selector: token.interface.getFunction('approve').selector,
          policy: await erc20ApprovePolicy.getAddress(),
          data: encodeAllowlistConfig([randomAddress()]),
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

    it('Should reject calldata that is not an ERC-20 approve', async function () {
      // `configure` pins the selector, so the engine can only route `approve` calldata here. This is
      // the policy defending its own decode when called directly, which anyone may do.
      const { safe, erc20ApprovePolicy, token } = await loadFixture(fixture)

      await expect(
        erc20ApprovePolicy.checkTransaction(
          safe,
          token,
          0n,
          token.interface.encodeFunctionData('transfer', [randomAddress(), 1n]),
          SafeOperation.Call,
          ZeroAddress,
          '0x',
          0n
        )
      ).to.be.revertedWithCustomError(erc20ApprovePolicy, 'InvalidApproval')
    })
  })

  describe('isSpenderAllowed', function () {
    it('Should report whether a spender is allowed for a Safe and token', async function () {
      // State is namespaced by `msg.sender`, which the getter takes explicitly, so configuring
      // directly makes the deployer the namespace to query.
      const { owner, safe, erc20ApprovePolicy, token } = await loadFixture(fixture)
      const accessSelector = await (await ethers.getContractFactory('TestAccessSelector')).deploy()
      const access = await accessSelector.create(
        token,
        token.interface.getFunction('approve').selector,
        SafeOperation.Call
      )
      const spender = randomAddress()

      expect(await erc20ApprovePolicy.isSpenderAllowed(owner, safe, token, spender)).to.equal(false)

      await erc20ApprovePolicy.connect(owner).configure(safe, access, encodeAllowlistConfig([spender]))
      expect(await erc20ApprovePolicy.isSpenderAllowed(owner, safe, token, spender)).to.equal(true)

      // The same call can revoke, which is why `configure` takes a flag per entry.
      await erc20ApprovePolicy.connect(owner).configure(safe, access, encodeAllowlistConfig([spender], false))
      expect(await erc20ApprovePolicy.isSpenderAllowed(owner, safe, token, spender)).to.equal(false)
    })
  })
})
