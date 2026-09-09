import { loadFixture } from '@nomicfoundation/hardhat-network-helpers'
import { expect } from 'chai'
import { ethers } from 'hardhat'

import {
  createConfiguration,
  enableGuard,
  encodeAllowlistConfig,
  encodeOneTimeGrantConfig,
  execTransaction,
  Permission,
  randomAddress,
  SafeOperation
} from '../src/utils'
import { deployERC20TransferPolicy, deployOneTimeAllowPolicy, deployTestERC20Token } from './deploy'
import { safePolicyGuardFixture as fixture } from './fixtures'

// Mirrors ReentrantMockPolicy.Mode.
enum ReentrantMockPolicyMode {
  None,
  ReenterGuardEntry,
  ReenterEngine,
  WriteState
}

describe('SafePolicyGuard -- execution outcome', function () {
  describe('Execution outcome', function () {
    // Checks run pre-execution only, so a policy's writes commit with the transaction. These pin
    // that a failed execution still rolls them back on both authorization paths.
    async function statefulFixture() {
      const base = await loadFixture(fixture)
      const { owner, safe, safePolicyGuard } = base

      const statefulPolicy = await (await ethers.getContractFactory('ReentrantMockPolicy')).deploy()
      await statefulPolicy.setMode(ReentrantMockPolicyMode.WriteState)

      const testModule = await (await ethers.getContractFactory('TestModule')).deploy()

      await enableGuard({
        owners: [owner],
        safe,
        safePolicyGuard,
        configurations: [createConfiguration({ policy: await statefulPolicy.getAddress() })],
        module: await testModule.getAddress(),
        moduleGuard: true
      })

      // A contract with neither `receive` nor a matching function reverts on a 0-value empty call.
      const revertingTarget = await statefulPolicy.getAddress()

      return { ...base, statefulPolicy, testModule, revertingTarget }
    }

    it('Should revert a module transaction whose execution failed', async function () {
      // Control, on the same Safe before any guard is installed: `execTransactionFromModule` has no
      // `safeTxGas` counterpart, so it reports a failed inner call by return value rather than
      // reverting. That asymmetry is why the module-path hook, and not the Safe, is what can keep a
      // policy's write from committing against an action that never happened.
      const { owner, safe, accessSelector } = await loadFixture(fixture)
      const safeAddress = await safe.getAddress()
      const target = await accessSelector.getAddress()
      const unguardedModule = await (await ethers.getContractFactory('TestModule')).deploy()
      await execTransaction({
        owners: [owner],
        safe,
        to: safeAddress,
        data: safe.interface.encodeFunctionData('enableModule', [await unguardedModule.getAddress()])
      })

      const succeeded = await unguardedModule.executeTx.staticCall(safeAddress, target, 0, '0x', SafeOperation.Call)
      expect(succeeded).to.equal(false)
      await expect(unguardedModule.executeTx(safeAddress, target, 0, '0x', SafeOperation.Call)).to.not.be.reverted

      // With the guard installed, a call that fails the same way reverts the module transaction
      // instead, and the policy's write goes back with it.
      const { safePolicyGuard, statefulPolicy, testModule, revertingTarget } = await statefulFixture()

      expect(await statefulPolicy.writes()).to.equal(0n)

      await expect(
        testModule.executeTx(safeAddress, revertingTarget, 0, '0x', SafeOperation.Call)
      ).to.be.revertedWithCustomError(safePolicyGuard, 'ModuleExecutionFailed')

      expect(await statefulPolicy.writes()).to.equal(0n)
    })

    it('Should keep a successful module transaction working', async function () {
      const { safe, statefulPolicy, testModule } = await statefulFixture()

      await testModule.executeTx(await safe.getAddress(), randomAddress(), 0, '0x', SafeOperation.Call)

      expect(await statefulPolicy.writes()).to.equal(1n)
    })

    it('Should revert a transaction whose execution failed', async function () {
      const { owner, safe, statefulPolicy, revertingTarget } = await statefulFixture()

      // The Safe already reverts this itself given `safeTxGas == 0` and `gasPrice == 0`; asserted
      // here as the transaction-path counterpart of the module case above.
      expect(await statefulPolicy.writes()).to.equal(0n)
      await expect(execTransaction({ owners: [owner], safe, to: revertingTarget })).to.be.reverted
      expect(await statefulPolicy.writes()).to.equal(0n)
    })

    it('Should reject the after-execution hooks reporting failure', async function () {
      const { safePolicyGuard } = await loadFixture(fixture)

      await expect(safePolicyGuard.checkAfterExecution(ethers.ZeroHash, false)).to.be.revertedWithCustomError(
        safePolicyGuard,
        'ExecutionFailed'
      )
      await expect(safePolicyGuard.checkAfterModuleExecution(ethers.ZeroHash, false)).to.be.revertedWithCustomError(
        safePolicyGuard,
        'ModuleExecutionFailed'
      )

      // Success is a no-op, so the hooks stay callable without any bookkeeping.
      await expect(safePolicyGuard.checkAfterExecution(ethers.ZeroHash, true)).to.not.be.reverted
      await expect(safePolicyGuard.checkAfterModuleExecution(ethers.ZeroHash, true)).to.not.be.reverted
    })
  })

  describe('Spend lifetime', function () {
    // A policy that spends an allowance spends it in the pre-execution check, before the Safe has
    // executed anything at all. The after-execution hooks are what keeps such a spend from
    // outliving an action that never took effect, so these run the real allowance-spending
    // policies over both authorization paths.
    async function spendFixture() {
      const base = await loadFixture(fixture)
      const { owner, safe, safePolicyGuard, accessSelector } = base
      const [, , , recipient] = await ethers.getSigners()

      const { oneTimeAllowPolicy } = await deployOneTimeAllowPolicy()
      const { erc20TransferPolicy } = await deployERC20TransferPolicy()
      const { token } = await deployTestERC20Token()
      const testModule = await (await ethers.getContractFactory('TestModule')).deploy()

      const safeAddress = await safe.getAddress()
      const tokenAddress = await token.getAddress()
      // A contract with neither `receive` nor a matching function reverts on a 0-value empty call.
      const revertingTarget = await accessSelector.getAddress()
      // An EOA, against which the very same call succeeds.
      const succeedingTarget = randomAddress()

      await token.mint(safeAddress, ethers.parseEther('100'))

      await enableGuard({
        owners: [owner],
        safe,
        safePolicyGuard,
        configurations: [
          createConfiguration({
            target: revertingTarget,
            policy: await oneTimeAllowPolicy.getAddress(),
            data: encodeOneTimeGrantConfig()
          }),
          createConfiguration({
            target: succeedingTarget,
            policy: await oneTimeAllowPolicy.getAddress(),
            data: encodeOneTimeGrantConfig()
          }),
          createConfiguration({
            target: tokenAddress,
            selector: token.interface.getFunction('transfer').selector,
            policy: await erc20TransferPolicy.getAddress(),
            data: encodeAllowlistConfig([recipient.address], Permission.Once)
          })
        ],
        module: await testModule.getAddress(),
        moduleGuard: true
      })

      /** Whether the one-time grant for `target` is still unspent. */
      const granted = async (target: string) =>
        oneTimeAllowPolicy.isGranted(
          safePolicyGuard,
          safe,
          await accessSelector.create(target, '0x00000000', SafeOperation.Call)
        )
      /** How often the recipient may still receive tokens. */
      const permission = () =>
        erc20TransferPolicy.getRecipientPermission(safePolicyGuard, safe, tokenAddress, recipient.address)
      // More tokens than the Safe holds, so the token contract reverts the inner call.
      const overdraft = token.interface.encodeFunctionData('transfer', [recipient.address, ethers.parseEther('1000')])

      return {
        ...base,
        safeAddress,
        testModule,
        tokenAddress,
        revertingTarget,
        succeedingTarget,
        granted,
        permission,
        overdraft
      }
    }

    it('Should restore a one-time grant when the transaction execution fails', async function () {
      const { owner, safe, revertingTarget, granted } = await spendFixture()

      expect(await granted(revertingTarget)).to.equal(true)
      await expect(execTransaction({ owners: [owner], safe, to: revertingTarget })).to.be.reverted
      // The check spent the grant; the failed execution takes the spend back with it.
      expect(await granted(revertingTarget)).to.equal(true)
    })

    it('Should restore a one-time grant when the module execution fails', async function () {
      const { safeAddress, safePolicyGuard, testModule, revertingTarget, succeedingTarget, granted } =
        await spendFixture()

      expect(await granted(revertingTarget)).to.equal(true)
      await expect(
        testModule.executeTx(safeAddress, revertingTarget, 0, '0x', SafeOperation.Call)
      ).to.be.revertedWithCustomError(safePolicyGuard, 'ModuleExecutionFailed')
      expect(await granted(revertingTarget)).to.equal(true)

      // Control on the same path and fixture: a grant whose inner call succeeds really is spent,
      // so the survival above is the rollback rather than a check that never ran.
      expect(await granted(succeedingTarget)).to.equal(true)
      await testModule.executeTx(safeAddress, succeedingTarget, 0, '0x', SafeOperation.Call)
      expect(await granted(succeedingTarget)).to.equal(false)
    })

    it('Should restore a one-time token allowance when the module transfer fails', async function () {
      const { safeAddress, safePolicyGuard, testModule, tokenAddress, permission, overdraft } = await spendFixture()

      expect(await permission()).to.equal(Permission.Once)
      await expect(
        testModule.executeTx(safeAddress, tokenAddress, 0, overdraft, SafeOperation.Call)
      ).to.be.revertedWithCustomError(safePolicyGuard, 'ModuleExecutionFailed')
      expect(await permission()).to.equal(Permission.Once)
    })

    it('Should not change a spend when the after-execution hooks are called directly', async function () {
      // Neither hook keeps bookkeeping of its own, so rejecting `success == false` is the whole of
      // the defence: a bare call reporting success moves nothing a later check reads back, and
      // there is no state for it to repair either.
      const { safePolicyGuard, revertingTarget, granted, permission } = await spendFixture()
      const arbitrary = ethers.id('a transaction hash the guard never saw')

      expect(await granted(revertingTarget)).to.equal(true)
      expect(await permission()).to.equal(Permission.Once)

      await expect(safePolicyGuard.checkAfterExecution(arbitrary, true)).to.not.be.reverted
      await expect(safePolicyGuard.checkAfterModuleExecution(arbitrary, true)).to.not.be.reverted

      expect(await granted(revertingTarget)).to.equal(true)
      expect(await permission()).to.equal(Permission.Once)
    })
  })
})
