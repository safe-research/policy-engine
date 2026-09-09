import { loadFixture } from '@nomicfoundation/hardhat-network-helpers'
import { expect } from 'chai'
import { ZeroAddress } from 'ethers'
import { ethers } from 'hardhat'

import {
  createConfiguration,
  createSafe,
  enableGuard,
  encodeAllowlistConfig,
  encodeAllowlistEntries,
  Permission,
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
      owners: [owner],
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
      await enableGuard({ owners: [owner], safe, safePolicyGuard, configurations })

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
      await enableGuard({ owners: [owner], safe, safePolicyGuard, configurations })

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
      await enableGuard({ owners: [owner], safe, safePolicyGuard, configurations })

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
      await enableGuard({ owners: [owner], safe, safePolicyGuard, configurations })

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
      expect(
        await erc20TransferPolicy.getRecipientPermission(deployer, ZeroAddress, tokenAddress, recipientAddress)
      ).to.equal(Permission.Always)

      // Then, disallow the same recipient
      await expect(
        erc20TransferPolicy.configure(ZeroAddress, access, encodeAllowlistConfig([recipientAddress], Permission.None))
      ).to.not.be.reverted
      expect(
        await erc20TransferPolicy.getRecipientPermission(deployer, ZeroAddress, tokenAddress, recipientAddress)
      ).to.equal(Permission.None)
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

  describe('One-Time Grants', function () {
    it('Should spend a one-time recipient grant on the first transfer', async function () {
      const { owner, recipient, safePolicyGuard, safe, erc20TransferPolicy, token } = await loadFixture(fixture)

      const amount = ethers.parseEther('100')
      const recipientAddress = await recipient.getAddress()

      await enableGuard({
        owners: [owner],
        safe,
        safePolicyGuard,
        configurations: [
          createConfiguration({
            target: await token.getAddress(),
            selector: token.interface.getFunction('transfer').selector,
            policy: await erc20TransferPolicy.getAddress(),
            data: encodeAllowlistConfig([recipientAddress], Permission.Once)
          })
        ]
      })

      const transfer = token.interface.encodeFunctionData('transfer', [recipientAddress, amount])

      await execTransaction({ owners: [owner], safe, to: await token.getAddress(), data: transfer })
      expect(await token.balanceOf(recipientAddress)).to.equal(amount)
      expect(await erc20TransferPolicy.getRecipientPermission(safePolicyGuard, safe, token, recipientAddress)).to.equal(
        Permission.None
      )

      // The grant is spent, so an identical transfer is now unauthorised.
      await expect(
        execTransaction({ owners: [owner], safe, to: await token.getAddress(), data: transfer })
      ).to.be.revertedWithCustomError(safePolicyGuard, 'PolicyReverted')

      expect(await token.balanceOf(recipientAddress)).to.equal(amount)
    })

    it('Should leave an open-ended grant in place across transfers', async function () {
      const { owner, recipient, safePolicyGuard, safe, erc20TransferPolicy, token } = await loadFixture(fixture)

      const amount = ethers.parseEther('100')
      const recipientAddress = await recipient.getAddress()

      await enableGuard({
        owners: [owner],
        safe,
        safePolicyGuard,
        configurations: [
          createConfiguration({
            target: await token.getAddress(),
            selector: token.interface.getFunction('transfer').selector,
            policy: await erc20TransferPolicy.getAddress(),
            data: encodeAllowlistConfig([recipientAddress], Permission.Always)
          })
        ]
      })

      const transfer = token.interface.encodeFunctionData('transfer', [recipientAddress, amount])
      await execTransaction({ owners: [owner], safe, to: await token.getAddress(), data: transfer })
      await execTransaction({ owners: [owner], safe, to: await token.getAddress(), data: transfer })

      expect(await token.balanceOf(recipientAddress)).to.equal(amount * 2n)
      expect(await erc20TransferPolicy.getRecipientPermission(safePolicyGuard, safe, token, recipientAddress)).to.equal(
        Permission.Always
      )
    })
  })

  describe('Events', function () {
    it('Should emit when a transfer spends a one-time grant', async function () {
      const { owner, recipient, safePolicyGuard, safe, erc20TransferPolicy, token } = await loadFixture(fixture)

      const recipientAddress = await recipient.getAddress()

      await enableGuard({
        owners: [owner],
        safe,
        safePolicyGuard,
        configurations: [
          createConfiguration({
            target: await token.getAddress(),
            selector: token.interface.getFunction('transfer').selector,
            policy: await erc20TransferPolicy.getAddress(),
            data: encodeAllowlistConfig([recipientAddress], Permission.Once)
          })
        ]
      })

      // Spending the grant removes the recipient from the allowlist, which an indexer only learns
      // about from this event -- the guard emits nothing for a transaction it permits.
      await expect(
        execTransaction({
          owners: [owner],
          safe,
          to: await token.getAddress(),
          data: token.interface.encodeFunctionData('transfer', [recipientAddress, ethers.parseEther('100')])
        })
      )
        .to.emit(erc20TransferPolicy, 'RecipientPermissionUsed')
        .withArgs(safePolicyGuard, safe, token, recipientAddress)
    })

    it('Should not emit when a transfer leaves the allowlist unchanged', async function () {
      const { owner, recipient, safePolicyGuard, safe, erc20TransferPolicy, token } = await loadFixture(fixture)

      const recipientAddress = await recipient.getAddress()

      await enableGuard({
        owners: [owner],
        safe,
        safePolicyGuard,
        configurations: [
          createConfiguration({
            target: await token.getAddress(),
            selector: token.interface.getFunction('transfer').selector,
            policy: await erc20TransferPolicy.getAddress(),
            data: encodeAllowlistConfig([recipientAddress], Permission.Always)
          })
        ]
      })

      // An open-ended grant is not spent, so there is no state change to report.
      await expect(
        execTransaction({
          owners: [owner],
          safe,
          to: await token.getAddress(),
          data: token.interface.encodeFunctionData('transfer', [recipientAddress, ethers.parseEther('100')])
        })
      ).to.not.emit(erc20TransferPolicy, 'RecipientPermissionUsed')
    })
  })

  describe('Calldata Decoding', function () {
    // The policy reads the recipient and amount straight out of the transaction's calldata, so what
    // it accepts is exactly what the ABI decoder accepts: a word that is too short, or an address
    // word with dirty high bits, reverts inside the decoder rather than reaching a policy verdict.
    it('Should decode transfer calldata exactly, rejecting short or non-canonical words', async function () {
      const { deployer, safe, erc20TransferPolicy, token, recipient, accessSelector } = await loadFixture(fixture)

      const tokenAddress = await token.getAddress()
      const transfer = token.interface.getFunction('transfer').selector
      const transferFrom = token.interface.getFunction('transferFrom').selector
      const access = await accessSelector.create(tokenAddress, transfer, SafeOperation.Call)
      const safeAddress = await safe.getAddress()
      await erc20TransferPolicy
        .connect(deployer)
        .configure(safeAddress, access, encodeAllowlistConfig([recipient.address]))

      const check = (data: string) =>
        erc20TransferPolicy
          .connect(deployer)
          .checkTransaction.staticCall(
            safeAddress,
            tokenAddress,
            0n,
            data,
            SafeOperation.Call,
            ZeroAddress,
            '0x',
            access
          )
      const magicValue = erc20TransferPolicy.interface.getFunction('checkTransaction').selector
      const word = (value: string) => ethers.zeroPadValue(value, 32)
      const amount = ethers.zeroPadValue('0x01', 32)

      // Too short to hold a selector at all: read as `bytes4(0)`, which is not a transfer.
      await expect(check('0x')).to.be.revertedWithCustomError(erc20TransferPolicy, 'InvalidTransfer')
      await expect(check(transfer.slice(0, 8))).to.be.revertedWithCustomError(erc20TransferPolicy, 'InvalidTransfer')

      // The selector is right but the arguments are not all there.
      await expect(check(transfer)).to.be.revertedWithoutReason()
      await expect(check(ethers.concat([transfer, word(recipient.address)]))).to.be.revertedWithoutReason()

      expect(await check(ethers.concat([transfer, word(recipient.address), amount]))).to.equal(magicValue)
      // Trailing words past the declared arguments are ignored, as the decoder ignores them.
      expect(await check(ethers.concat([transfer, word(recipient.address), amount, amount]))).to.equal(magicValue)

      // An address word whose high bits are not clear is not a valid `address`.
      const dirty = ethers.concat(['0xffffffffffffffffffffffff', recipient.address])
      await expect(check(ethers.concat([transfer, dirty, amount]))).to.be.revertedWithoutReason()

      // `transferFrom` carries three arguments and its recipient is the second of them.
      await expect(check(ethers.concat([transferFrom, word(recipient.address), amount]))).to.be.revertedWithoutReason()
      expect(await check(ethers.concat([transferFrom, word(safeAddress), word(recipient.address), amount]))).to.equal(
        magicValue
      )
      await expect(
        check(ethers.concat([transferFrom, word(recipient.address), word(safeAddress), amount]))
      ).to.be.revertedWithCustomError(erc20TransferPolicy, 'Unauthorized')
    })
  })

  describe('Multi-Entry Configuration', function () {
    it('Should write every entry of a recipient list, with its own permission', async function () {
      const { deployer, safe, erc20TransferPolicy, token, accessSelector } = await loadFixture(fixture)

      const tokenAddress = await token.getAddress()
      const access = await accessSelector.create(
        tokenAddress,
        token.interface.getFunction('transfer').selector,
        SafeOperation.Call
      )
      const safeAddress = await safe.getAddress()
      const account = (i: number) => ethers.getAddress(`0x${i.toString(16).padStart(2, '0').repeat(20)}`)
      const permissions = [Permission.Always, Permission.Once, Permission.None]
      const entries = (count: number) =>
        Array.from({ length: count }, (_, i) => ({ account: account(i + 1), permission: permissions[i % 3] }))
      const untouched = account(0xee)

      // Lists long enough that a loop stopping early, or reusing one entry's permission for the
      // rest, would show up.
      for (const count of [2, 3, 4, 5, 20]) {
        const list = entries(count)
        const data = encodeAllowlistEntries(list)
        expect(await erc20TransferPolicy.connect(deployer).configure.staticCall(safeAddress, access, data)).to.equal(
          true
        )
        await erc20TransferPolicy.connect(deployer).configure(safeAddress, access, data)

        for (const { account: recipient, permission } of list) {
          expect(
            await erc20TransferPolicy.getRecipientPermission(deployer, safeAddress, tokenAddress, recipient)
          ).to.equal(permission)
        }
        // Configuring is additive: a recipient the list never names keeps whatever it had.
        expect(
          await erc20TransferPolicy.getRecipientPermission(deployer, safeAddress, tokenAddress, untouched)
        ).to.equal(Permission.None)
      }

      // A repeated account is written twice, so the last entry is the one that stands.
      const repeated = account(0x77)
      await erc20TransferPolicy.connect(deployer).configure(
        safeAddress,
        access,
        encodeAllowlistEntries([
          { account: repeated, permission: Permission.Once },
          { account: account(0x88), permission: Permission.Once },
          { account: repeated, permission: Permission.Always }
        ])
      )
      expect(await erc20TransferPolicy.getRecipientPermission(deployer, safeAddress, tokenAddress, repeated)).to.equal(
        Permission.Always
      )
    })
  })
})
