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
import { deploySafeContracts, deploySafePolicyGuard, deployERC20ApprovePolicy, deployTestERC20Token } from './deploy'

describe('ERC20ApprovePolicy', function () {
  async function fixture() {
    const [, owner, spender, other] = await ethers.getSigners()

    // Deploy the SafePolicyGuard contract
    const { safePolicyGuard } = await deploySafePolicyGuard()

    // Deploy the Safe contracts
    const { safeProxyFactory, safe: safeSingleton } = await deploySafeContracts()
    const safe = await createSafe({
      owners: [owner],
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

      // Configure the policy, then enable the guard
      await enableGuard({ owners: [owner], safe, safePolicyGuard, configurations })

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

      // Configure the policy, then enable the guard
      await enableGuard({ owners: [owner], safe, safePolicyGuard, configurations })

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

      // Configure the policy, then enable the guard
      await enableGuard({ owners: [owner], safe, safePolicyGuard, configurations })

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

      // Configure the policy, then enable the guard
      await enableGuard({ owners: [owner], safe, safePolicyGuard, configurations })

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

  describe('getSpenderPermission', function () {
    it('Should report the permission recorded for a spender', async function () {
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

      expect(await erc20ApprovePolicy.getSpenderPermission(owner, safe, token, spender)).to.equal(Permission.None)

      await erc20ApprovePolicy.connect(owner).configure(safe, access, encodeAllowlistConfig([spender]))
      expect(await erc20ApprovePolicy.getSpenderPermission(owner, safe, token, spender)).to.equal(Permission.Always)

      // A one-time grant is recorded distinctly from an open-ended one.
      await erc20ApprovePolicy.connect(owner).configure(safe, access, encodeAllowlistConfig([spender], Permission.Once))
      expect(await erc20ApprovePolicy.getSpenderPermission(owner, safe, token, spender)).to.equal(Permission.Once)

      // The same call can revoke, which is why `configure` takes a permission per entry.
      await erc20ApprovePolicy.connect(owner).configure(safe, access, encodeAllowlistConfig([spender], Permission.None))
      expect(await erc20ApprovePolicy.getSpenderPermission(owner, safe, token, spender)).to.equal(Permission.None)
    })
  })

  describe('One-Time Grants', function () {
    it('Should spend a one-time spender grant on the first approval', async function () {
      const { owner, safePolicyGuard, safe, erc20ApprovePolicy, token } = await loadFixture(fixture)

      const spender = randomAddress()
      const amount = ethers.parseEther('100')

      await enableGuard({
        owners: [owner],
        safe,
        safePolicyGuard,
        configurations: [
          createConfiguration({
            target: await token.getAddress(),
            selector: token.interface.getFunction('approve').selector,
            policy: await erc20ApprovePolicy.getAddress(),
            data: encodeAllowlistConfig([spender], Permission.Once)
          })
        ]
      })

      const approve = token.interface.encodeFunctionData('approve', [spender, amount])

      await execTransaction({ owners: [owner], safe, to: await token.getAddress(), data: approve })
      expect(await token.allowance(safe, spender)).to.equal(amount)
      expect(await erc20ApprovePolicy.getSpenderPermission(safePolicyGuard, safe, token, spender)).to.equal(
        Permission.None
      )

      await expect(
        execTransaction({ owners: [owner], safe, to: await token.getAddress(), data: approve })
      ).to.be.revertedWithCustomError(safePolicyGuard, 'PolicyReverted')
    })

    it('Should not spend a one-time grant on a zero-amount approval', async function () {
      const { owner, safePolicyGuard, safe, erc20ApprovePolicy, token } = await loadFixture(fixture)

      const spender = randomAddress()

      await enableGuard({
        owners: [owner],
        safe,
        safePolicyGuard,
        configurations: [
          createConfiguration({
            target: await token.getAddress(),
            selector: token.interface.getFunction('approve').selector,
            policy: await erc20ApprovePolicy.getAddress(),
            data: encodeAllowlistConfig([spender], Permission.Once)
          })
        ]
      })

      // Revoking an allowance bypasses the allowlist entirely, so it must not burn the grant.
      await execTransaction({
        owners: [owner],
        safe,
        to: await token.getAddress(),
        data: token.interface.encodeFunctionData('approve', [spender, 0])
      })

      expect(await erc20ApprovePolicy.getSpenderPermission(safePolicyGuard, safe, token, spender)).to.equal(
        Permission.Once
      )
    })
  })

  describe('Events', function () {
    it('Should emit when an approval spends a one-time grant', async function () {
      const { owner, safePolicyGuard, safe, erc20ApprovePolicy, token } = await loadFixture(fixture)

      const spender = randomAddress()

      await enableGuard({
        owners: [owner],
        safe,
        safePolicyGuard,
        configurations: [
          createConfiguration({
            target: await token.getAddress(),
            selector: token.interface.getFunction('approve').selector,
            policy: await erc20ApprovePolicy.getAddress(),
            data: encodeAllowlistConfig([spender], Permission.Once)
          })
        ]
      })

      // Spending the grant removes the spender from the allowlist, which an indexer only learns
      // about from this event -- the guard emits nothing for a transaction it permits.
      await expect(
        execTransaction({
          owners: [owner],
          safe,
          to: await token.getAddress(),
          data: token.interface.encodeFunctionData('approve', [spender, ethers.parseEther('100')])
        })
      )
        .to.emit(erc20ApprovePolicy, 'SpenderPermissionUsed')
        .withArgs(safePolicyGuard, safe, token, spender)
    })

    it('Should not emit when an approval leaves the allowlist unchanged', async function () {
      const { owner, safePolicyGuard, safe, erc20ApprovePolicy, token } = await loadFixture(fixture)

      const spender = randomAddress()

      await enableGuard({
        owners: [owner],
        safe,
        safePolicyGuard,
        configurations: [
          createConfiguration({
            target: await token.getAddress(),
            selector: token.interface.getFunction('approve').selector,
            policy: await erc20ApprovePolicy.getAddress(),
            data: encodeAllowlistConfig([spender], Permission.Always)
          })
        ]
      })

      // An open-ended grant is not spent, so there is no state change to report.
      await expect(
        execTransaction({
          owners: [owner],
          safe,
          to: await token.getAddress(),
          data: token.interface.encodeFunctionData('approve', [spender, ethers.parseEther('100')])
        })
      ).to.not.emit(erc20ApprovePolicy, 'SpenderPermissionUsed')
    })

    it('Should not emit when a zero-amount approval bypasses the allowlist', async function () {
      const { owner, safePolicyGuard, safe, erc20ApprovePolicy, token } = await loadFixture(fixture)

      const spender = randomAddress()

      await enableGuard({
        owners: [owner],
        safe,
        safePolicyGuard,
        configurations: [
          createConfiguration({
            target: await token.getAddress(),
            selector: token.interface.getFunction('approve').selector,
            policy: await erc20ApprovePolicy.getAddress(),
            data: encodeAllowlistConfig([spender], Permission.Once)
          })
        ]
      })

      // Revoking an allowance never touches the grant, so the indexed state stays put.
      await expect(
        execTransaction({
          owners: [owner],
          safe,
          to: await token.getAddress(),
          data: token.interface.encodeFunctionData('approve', [spender, 0])
        })
      ).to.not.emit(erc20ApprovePolicy, 'SpenderPermissionUsed')
    })
  })

  describe('Calldata Decoding', function () {
    // The policy reads the spender and amount straight out of the transaction's calldata, so what
    // it accepts is exactly what the ABI decoder accepts -- including for a zero-amount approval,
    // which bypasses the allowlist but is still decoded first.
    it('Should decode approve calldata exactly, rejecting short or non-canonical words', async function () {
      const { safe, erc20ApprovePolicy, token } = await loadFixture(fixture)

      const [deployer] = await ethers.getSigners()
      const accessSelector = await (await ethers.getContractFactory('TestAccessSelector')).deploy()
      const approve = token.interface.getFunction('approve').selector
      const tokenAddress = await token.getAddress()
      const access = await accessSelector.create(tokenAddress, approve, SafeOperation.Call)
      const spender = randomAddress()

      const check = (data: string) =>
        erc20ApprovePolicy
          .connect(deployer)
          .checkTransaction.staticCall(safe, tokenAddress, 0n, data, SafeOperation.Call, ZeroAddress, '0x', access)
      const magicValue = erc20ApprovePolicy.interface.getFunction('checkTransaction').selector
      const word = (value: string) => ethers.zeroPadValue(value, 32)
      const zero = ethers.ZeroHash

      // Nothing is configured here, so the zero-amount approval is the one that clears.
      expect(await check(ethers.concat([approve, word(spender), zero]))).to.equal(magicValue)
      await expect(
        check(ethers.concat([approve, word(spender), ethers.zeroPadValue('0x01', 32)]))
      ).to.be.revertedWithCustomError(erc20ApprovePolicy, 'Unauthorized')

      // A spender word whose high bits are not clear is rejected by the decoder, before the
      // zero-amount branch can wave it through.
      const dirty = ethers.concat(['0xffffffffffffffffffffffff', spender])
      await expect(check(ethers.concat([approve, dirty, zero]))).to.be.revertedWithoutReason()

      // The selector is right but the arguments are not there.
      await expect(check(approve)).to.be.revertedWithoutReason()
    })
  })

  describe('Multi-Entry Configuration', function () {
    it('Should write every entry of a spender list, with its own permission', async function () {
      const { safe, erc20ApprovePolicy, token } = await loadFixture(fixture)

      const [deployer] = await ethers.getSigners()
      const accessSelector = await (await ethers.getContractFactory('TestAccessSelector')).deploy()
      const tokenAddress = await token.getAddress()
      const access = await accessSelector.create(
        tokenAddress,
        token.interface.getFunction('approve').selector,
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
        expect(await erc20ApprovePolicy.connect(deployer).configure.staticCall(safeAddress, access, data)).to.equal(
          true
        )
        await erc20ApprovePolicy.connect(deployer).configure(safeAddress, access, data)

        for (const { account: spender, permission } of list) {
          expect(await erc20ApprovePolicy.getSpenderPermission(deployer, safeAddress, tokenAddress, spender)).to.equal(
            permission
          )
        }
        // Configuring is additive: a spender the list never names keeps whatever it had.
        expect(await erc20ApprovePolicy.getSpenderPermission(deployer, safeAddress, tokenAddress, untouched)).to.equal(
          Permission.None
        )
      }

      // A repeated account is written twice, so the last entry is the one that stands.
      const repeated = account(0x77)
      await erc20ApprovePolicy.connect(deployer).configure(
        safeAddress,
        access,
        encodeAllowlistEntries([
          { account: repeated, permission: Permission.Once },
          { account: account(0x88), permission: Permission.Once },
          { account: repeated, permission: Permission.Always }
        ])
      )
      expect(await erc20ApprovePolicy.getSpenderPermission(deployer, safeAddress, tokenAddress, repeated)).to.equal(
        Permission.Always
      )
    })
  })
})
