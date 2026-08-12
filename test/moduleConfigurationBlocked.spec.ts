import { loadFixture, time } from '@nomicfoundation/hardhat-network-helpers'
import { expect } from 'chai'
import { ZeroAddress } from 'ethers'
import { ethers } from 'hardhat'

import {
  buildContractCall,
  buildMultiSendSafeTx,
  createConfiguration,
  createSafe,
  execTransaction,
  getConfigurationRoot,
  SafeOperation
} from '../src/utils'
import { deployAllowPolicy, deployMultiSendPolicy, deploySafeContracts, deploySafePolicyGuard } from './deploy'

/**
 * A module must not be able to change policies.
 */
describe('Module policy-change blocking', function () {
  async function fixture() {
    const [, owner, attacker] = await ethers.getSigners()

    const { safePolicyGuard } = await deploySafePolicyGuard()
    const { safeProxyFactory, safe: safeSingleton, multiSend } = await deploySafeContracts()
    const safe = await createSafe({
      owner,
      guard: ZeroAddress,
      saltNonce: BigInt(0x73),
      safeProxyFactory,
      singleton: safeSingleton
    })
    const { allowPolicy } = await deployAllowPolicy()
    const { multiSendPolicy } = await deployMultiSendPolicy()

    const testModule = await (await ethers.getContractFactory('TestModule')).deploy()
    const guardAddress = await safePolicyGuard.getAddress()
    const safeAddress = await safe.getAddress()
    const moduleAddress = await testModule.getAddress()

    await execTransaction({
      owners: [owner],
      safe,
      to: safeAddress,
      data: safe.interface.encodeFunctionData('enableModule', [moduleAddress])
    })

    /** Installs `cfgs`, then enables both guard slots (module guard first — see below). */
    async function configurePolicies(cfgs: unknown[] = []) {
      await execTransaction({
        owners: [owner],
        safe,
        to: guardAddress,
        data: safePolicyGuard.interface.encodeFunctionData('configureImmediately', [cfgs])
      })
      // Module guard first: once the transaction guard is live, `setModuleGuard` is itself a guarded
      // self-call needing a configured policy, which this fixture does not install.
      await execTransaction({
        owners: [owner],
        safe,
        to: safeAddress,
        data: safe.interface.encodeFunctionData('setModuleGuard', [guardAddress])
      })
      await execTransaction({
        owners: [owner],
        safe,
        to: safeAddress,
        data: safe.interface.encodeFunctionData('setGuard', [guardAddress])
      })
    }

    /** A root the owners have requested and matured, ready to apply. */
    async function maturedRoot() {
      const cfgs = [createConfiguration({ policy: await allowPolicy.getAddress() })]
      const root = getConfigurationRoot(cfgs)
      await execTransaction({
        owners: [owner],
        safe,
        to: guardAddress,
        data: safePolicyGuard.interface.encodeFunctionData('requestConfiguration', [root])
      })
      await time.increase(7n * 24n * 60n * 60n + 1n)
      return { cfgs, root }
    }

    const viaModule = (to: string, data: string, operation: number = SafeOperation.Call) =>
      testModule.executeTx(safeAddress, to, 0n, data, operation)

    return {
      owner,
      attacker,
      safe,
      safePolicyGuard,
      allowPolicy,
      multiSendPolicy,
      multiSend,
      testModule,
      guardAddress,
      safeAddress,
      configurePolicies,
      maturedRoot,
      viaModule
    }
  }

  it('Should block a module from requesting a configuration', async function () {
    const { safePolicyGuard, allowPolicy, guardAddress, safeAddress, configurePolicies, viaModule } =
      await loadFixture(fixture)
    await configurePolicies()

    const root = getConfigurationRoot([createConfiguration({ policy: await allowPolicy.getAddress() })])

    await expect(
      viaModule(guardAddress, safePolicyGuard.interface.encodeFunctionData('requestConfiguration', [root]))
    ).to.be.revertedWithCustomError(safePolicyGuard, 'ModuleConfigurationDenied')

    expect(await safePolicyGuard.rootConfigured(safeAddress, root)).to.equal(0n)
  })

  it('Should block a module from applying a configuration the owners matured', async function () {
    const { safePolicyGuard, allowPolicy, guardAddress, safeAddress, configurePolicies, maturedRoot, viaModule } =
      await loadFixture(fixture)
    await configurePolicies()
    const { cfgs, root } = await maturedRoot()

    await expect(
      viaModule(guardAddress, safePolicyGuard.interface.encodeFunctionData('applyConfiguration', [cfgs]))
    ).to.be.revertedWithCustomError(safePolicyGuard, 'ModuleConfigurationDenied')

    // The policy set is untouched and the root is still pending for the owners to apply.
    const [, policy] = await safePolicyGuard.getPolicy(safeAddress, safeAddress, '0x', SafeOperation.Call)
    expect(policy).to.not.equal(await allowPolicy.getAddress())
    expect(await safePolicyGuard.rootConfigured(safeAddress, root)).to.be.gt(0n)
  })

  it('Should block a module from invalidating a root the owners requested', async function () {
    const { safePolicyGuard, guardAddress, safeAddress, configurePolicies, maturedRoot, viaModule } =
      await loadFixture(fixture)
    await configurePolicies()
    const { root } = await maturedRoot()
    const deadline = await safePolicyGuard.rootConfigured(safeAddress, root)

    await expect(
      viaModule(guardAddress, safePolicyGuard.interface.encodeFunctionData('invalidateRoot', [root]))
    ).to.be.revertedWithCustomError(safePolicyGuard, 'ModuleConfigurationDenied')

    expect(await safePolicyGuard.rootConfigured(safeAddress, root)).to.equal(deadline)
  })

  it('Should block a module even when a policy authorises the configuration call', async function () {
    const { owner, safe, safePolicyGuard, allowPolicy, guardAddress, safeAddress, configurePolicies, viaModule } =
      await loadFixture(fixture)

    // Deliberately grant the configuration entry point an allow-all policy. The revert must win over
    // the policy, otherwise a Safe could opt back into module-driven configuration.
    const requestSelector = safePolicyGuard.interface.getFunction('requestConfiguration')!.selector
    await configurePolicies([
      createConfiguration({
        target: guardAddress,
        selector: requestSelector,
        operation: SafeOperation.Call,
        policy: await allowPolicy.getAddress()
      })
    ])

    const root = getConfigurationRoot([createConfiguration({ policy: await allowPolicy.getAddress() })])
    const data = safePolicyGuard.interface.encodeFunctionData('requestConfiguration', [root])

    // Confirm the policy really does resolve for this exact call.
    const [, resolved] = await safePolicyGuard.getPolicy(safeAddress, guardAddress, data, SafeOperation.Call)
    expect(resolved).to.equal(await allowPolicy.getAddress())

    await expect(viaModule(guardAddress, data)).to.be.revertedWithCustomError(
      safePolicyGuard,
      'ModuleConfigurationDenied'
    )

    // …while the owners are unaffected by that same configuration.
    await execTransaction({ owners: [owner], safe, to: guardAddress, data })
    expect(await safePolicyGuard.rootConfigured(safeAddress, root)).to.be.gt(0n)
  })

  it('Should block a module from configurating policy through a MultiSend batch', async function () {
    const { safePolicyGuard, allowPolicy, multiSendPolicy, multiSend, safeAddress, configurePolicies, viaModule } =
      await loadFixture(fixture)

    // Batching is permitted, so the outer delegatecall passes. The sub-transaction check still runs
    // on the module path — `$checkingModule` is engine state, not something the batch can clear.
    await configurePolicies([
      createConfiguration({
        target: await multiSend.getAddress(),
        selector: multiSend.interface.getFunction('multiSend')!.selector,
        operation: SafeOperation.DelegateCall,
        policy: await multiSendPolicy.getAddress()
      })
    ])

    const root = getConfigurationRoot([createConfiguration({ policy: await allowPolicy.getAddress() })])
    const batch = await buildMultiSendSafeTx(
      multiSend,
      [await buildContractCall(safePolicyGuard, 'requestConfiguration', [root], 0)],
      0
    )

    await expect(
      viaModule(await multiSend.getAddress(), batch.data as string, SafeOperation.DelegateCall)
    ).to.be.revertedWithCustomError(safePolicyGuard, 'PolicyReverted')

    expect(await safePolicyGuard.rootConfigured(safeAddress, root)).to.equal(0n)
  })

  it('Should leave the owner escape hatch intact with no policy configured', async function () {
    const { owner, safe, safePolicyGuard, allowPolicy, guardAddress, safeAddress, configurePolicies } =
      await loadFixture(fixture)
    // Nothing configured at all, so the owners depend entirely on the escape hatch.
    await configurePolicies()

    const cfgs = [createConfiguration({ policy: await allowPolicy.getAddress() })]
    const root = getConfigurationRoot(cfgs)

    await execTransaction({
      owners: [owner],
      safe,
      to: guardAddress,
      data: safePolicyGuard.interface.encodeFunctionData('requestConfiguration', [root])
    })
    expect(await safePolicyGuard.rootConfigured(safeAddress, root)).to.be.gt(0n)

    await execTransaction({
      owners: [owner],
      safe,
      to: guardAddress,
      data: safePolicyGuard.interface.encodeFunctionData('invalidateRoot', [root])
    })
    expect(await safePolicyGuard.rootConfigured(safeAddress, root)).to.equal(0n)

    await execTransaction({
      owners: [owner],
      safe,
      to: guardAddress,
      data: safePolicyGuard.interface.encodeFunctionData('requestConfiguration', [root])
    })
    await time.increase(7n * 24n * 60n * 60n + 1n)
    await execTransaction({
      owners: [owner],
      safe,
      to: guardAddress,
      data: safePolicyGuard.interface.encodeFunctionData('applyConfiguration', [cfgs])
    })

    const [, policy] = await safePolicyGuard.getPolicy(safeAddress, safeAddress, '0x', SafeOperation.Call)
    expect(policy).to.equal(await allowPolicy.getAddress())
  })
})
