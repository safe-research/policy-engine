import { loadFixture } from '@nomicfoundation/hardhat-network-helpers'
import { expect } from 'chai'
import { ethers } from 'hardhat'

import { createConfiguration, enableGuard, execTransaction, randomAddress, SafeOperation } from '../src/utils'
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
        owner,
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
      const { safe, safePolicyGuard, statefulPolicy, testModule, revertingTarget } = await statefulFixture()

      expect(await statefulPolicy.writes()).to.equal(0n)

      // `execTransactionFromModule` returns `false` rather than reverting, so without the
      // after-execution check the policy's write would commit against an action that never happened.
      await expect(
        testModule.executeTx(await safe.getAddress(), revertingTarget, 0, '0x', SafeOperation.Call)
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
})
