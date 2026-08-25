import { loadFixture } from '@nomicfoundation/hardhat-network-helpers'
import { expect } from 'chai'
import { ZeroAddress } from 'ethers'
import { ethers } from 'hardhat'

import {
  createConfiguration,
  createSafe,
  enableGuard,
  encodeAllowlistConfig,
  execTransaction,
  randomAddress,
  SafeOperation
} from '../src/utils'
import { deploySafeContracts, deploySafePolicyGuard, deployERC20TransferPolicy, deployTestERC20Token } from './deploy'

describe('ERC20TransferPolicy', function () {
  async function fixture() {
    const [deployer, owner, recipient, other] = await ethers.getSigners()

    // Deploy the SafePolicyGuard contract
    const { safePolicyGuard } = await deploySafePolicyGuard()

    // Deploy the Safe contracts
    const { safeProxyFactory, safe: safeSingleton } = await deploySafeContracts()
    const safe = await createSafe({
      owner,
      guard: ZeroAddress, // No guard at this point
      saltNonce: BigInt(0x4),
      safeProxyFactory,
      singleton: safeSingleton
    })

    // Deploy ERC20TransferPolicy contract
    const { erc20TransferPolicy } = await deployERC20TransferPolicy()

    // Deploy Test ERC20 Token contract
    const { token } = await deployTestERC20Token()

    // Mint some tokens to the Safe
    await token.mint(await safe.getAddress(), ethers.parseEther('1000'))

    // Create an access selector instance
    const TestAccessSelectorFactory = await ethers.getContractFactory('TestAccessSelector')
    const accessSelector = await TestAccessSelectorFactory.deploy()

    return {
      deployer,
      owner,
      recipient,
      other,
      safe,
      safePolicyGuard,
      erc20TransferPolicy,
      token,
      accessSelector
    }
  }

  describe('Integration with SafePolicyGuard', function () {
    it('Should allow transfer to configured recipient', async function () {
      const { owner, recipient, safePolicyGuard, safe, erc20TransferPolicy, token } = await loadFixture(fixture)

      const amount = ethers.parseEther('100')

      // Configure the ERC20 transfer policy
      const configurations = [
        createConfiguration({
          target: await token.getAddress(),
          selector: token.interface.getFunction('transfer').selector,
          policy: await erc20TransferPolicy.getAddress(),
          data: encodeAllowlistConfig([await recipient.getAddress()])
        })
      ]

      // Configure the policy, then enable the guard
      await enableGuard({ owner, safe, safePolicyGuard, configurations })

      // Execute the transfer transaction
      await execTransaction({
        owners: [owner],
        safe,
        to: await token.getAddress(),
        data: token.interface.encodeFunctionData('transfer', [await recipient.getAddress(), amount])
      })

      // Verify the transfer was successful
      expect(await token.balanceOf(await recipient.getAddress())).to.equal(amount)
    })

    it('Should not allow transfer to unconfigured recipient', async function () {
      const { owner, other, safePolicyGuard, safe, erc20TransferPolicy, token } = await loadFixture(fixture)

      const amount = ethers.parseEther('100')

      // Configure the ERC20 transfer policy with no recipients
      const configurations = [
        createConfiguration({
          target: await token.getAddress(),
          selector: token.interface.getFunction('transfer').selector,
          policy: await erc20TransferPolicy.getAddress(),
          data: encodeAllowlistConfig([])
        })
      ]

      // Configure the policy, then enable the guard
      await enableGuard({ owner, safe, safePolicyGuard, configurations })

      // Try to execute a transfer transaction to unconfigured recipient
      await expect(
        execTransaction({
          owners: [owner],
          safe,
          to: await token.getAddress(),
          data: token.interface.encodeFunctionData('transfer', [await other.getAddress(), amount])
        })
      )
        .to.be.revertedWithCustomError(safePolicyGuard, 'PolicyReverted')
        .withArgs(
          await erc20TransferPolicy.getAddress(),
          erc20TransferPolicy.interface.encodeErrorResult('Unauthorized', [])
        )
    })

    it('Should not allow non-transfer transactions', async function () {
      const { owner, recipient, safePolicyGuard, safe, erc20TransferPolicy, token } = await loadFixture(fixture)

      const amount = ethers.parseEther('100')

      // Configure the ERC20 transfer policy
      const configurations = [
        createConfiguration({
          target: await token.getAddress(),
          selector: token.interface.getFunction('transfer').selector,
          policy: await erc20TransferPolicy.getAddress(),
          data: encodeAllowlistConfig([await recipient.getAddress()])
        })
      ]

      // Configure the policy, then enable the guard
      await enableGuard({ owner, safe, safePolicyGuard, configurations })

      // Try to execute an approve transaction (non-transfer)
      await expect(
        execTransaction({
          owners: [owner],
          safe,
          to: await token.getAddress(),
          data: token.interface.encodeFunctionData('approve', [await recipient.getAddress(), amount])
        })
      ).to.be.revertedWithCustomError(safePolicyGuard, 'AccessDenied')
    })

    it('Should allow transferFrom to configured recipient', async function () {
      const { owner, recipient, safePolicyGuard, safe, erc20TransferPolicy, token } = await loadFixture(fixture)

      const amount = ethers.parseEther('100')

      // Mint tokens to the owner
      await token.mint(await owner.getAddress(), amount)

      // Configure the ERC20 transfer policy
      const configurations = [
        createConfiguration({
          target: await token.getAddress(),
          selector: token.interface.getFunction('transferFrom').selector,
          policy: await erc20TransferPolicy.getAddress(),
          data: encodeAllowlistConfig([await recipient.getAddress()])
        })
      ]

      // Configure the policy, then enable the guard
      await enableGuard({ owner, safe, safePolicyGuard, configurations })

      // Approve the Safe to spend tokens (using owner's signer)
      await token.connect(owner).approve(await safe.getAddress(), amount)

      // Execute the transferFrom transaction
      await execTransaction({
        owners: [owner],
        safe,
        to: await token.getAddress(),
        data: token.interface.encodeFunctionData('transferFrom', [
          await owner.getAddress(),
          await recipient.getAddress(),
          amount
        ])
      })

      // Verify the transfer was successful
      expect(await token.balanceOf(await recipient.getAddress())).to.equal(amount)
    })
  })

  describe('Policy Configuration', function () {
    it('Should only be able to configure ERC20 transfer transactions', async function () {
      const { owner, safePolicyGuard, safe, erc20TransferPolicy, token } = await loadFixture(fixture)

      // Trying to configure a non-transfer transaction
      const configurations = [
        createConfiguration({
          target: await token.getAddress(),
          selector: token.interface.getFunction('approve').selector, // Non-transfer function
          policy: await erc20TransferPolicy.getAddress(),
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
      ).to.be.revertedWithCustomError(erc20TransferPolicy, 'InvalidSelector')
    })

    it('Should only allow CALL operations', async function () {
      const { owner, safePolicyGuard, safe, erc20TransferPolicy, token } = await loadFixture(fixture)

      // Trying to configure with DELEGATECALL operation
      const configurations = [
        createConfiguration({
          target: await token.getAddress(),
          selector: token.interface.getFunction('transfer').selector,
          operation: SafeOperation.DelegateCall,
          policy: await erc20TransferPolicy.getAddress(),
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
      ).to.be.revertedWithCustomError(erc20TransferPolicy, 'InvalidOperation')
    })
  })

  describe('Recipient Configuration Edge Cases', function () {
    it('Should handle empty recipient list configuration', async function () {
      const { erc20TransferPolicy, token, accessSelector } = await loadFixture(fixture)

      const access = await accessSelector.create(
        await token.getAddress(),
        token.interface.getFunction('transfer').selector,
        SafeOperation.Call
      )

      // Configure with empty recipient list
      await expect(erc20TransferPolicy.configure(ZeroAddress, access, encodeAllowlistConfig([]))).to.not.be.reverted
    })

    it('Should handle recipient permission toggle', async function () {
      const { deployer, erc20TransferPolicy, token, recipient, accessSelector } = await loadFixture(fixture)

      const recipientAddress = await recipient.getAddress()
      const tokenAddress = await token.getAddress()

      const access = await accessSelector.create(
        tokenAddress,
        token.interface.getFunction('transfer').selector,
        SafeOperation.Call
      )

      // First, allow the recipient
      await erc20TransferPolicy.configure(ZeroAddress, access, encodeAllowlistConfig([recipientAddress]))
      expect(await erc20TransferPolicy.isRecipientAllowed(deployer, ZeroAddress, tokenAddress, recipientAddress)).to.be
        .true

      // Then, disallow the same recipient
      await expect(erc20TransferPolicy.configure(ZeroAddress, access, encodeAllowlistConfig([recipientAddress], false)))
        .to.not.be.reverted
      expect(await erc20TransferPolicy.isRecipientAllowed(deployer, ZeroAddress, tokenAddress, recipientAddress)).to.be
        .false
    })

    it('Should reject calldata that is neither transfer nor transferFrom', async function () {
      // `configure` pins the selector to one of the two, so the engine can only route those here.
      // This is the policy defending its own decode when called directly, which anyone may do.
      const { safe, erc20TransferPolicy, token } = await loadFixture(fixture)

      await expect(
        erc20TransferPolicy.checkTransaction(
          safe,
          token,
          0n,
          token.interface.encodeFunctionData('approve', [randomAddress(), 1n]),
          SafeOperation.Call,
          ZeroAddress,
          '0x',
          0n
        )
      ).to.be.revertedWithCustomError(erc20TransferPolicy, 'InvalidTransfer')
    })
  })
})
