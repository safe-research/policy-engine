import { loadFixture, time } from '@nomicfoundation/hardhat-network-helpers'
import { expect } from 'chai'
import { ZeroAddress, id } from 'ethers'
import { ethers } from 'hardhat'

import {
  SafeOperation,
  createConfiguration,
  createSafe,
  execTransaction,
  getConfigurationRoot,
  getSafeTransactionHash,
  preApprovedSignature,
  randomAddress
} from '../src/utils'
import { deployAllowPolicy, deploySafeContracts, deploySafePolicyGuard } from './deploy'

// Mirrors ReentrantMockPolicy.Mode.
enum Mode {
  None,
  ReenterGuardEntry,
  ReenterEngine,
  WriteState,
  ReenterModuleGuardEntry
}

describe('Non-view check path — reentrancy & Safe confinement', function () {
  async function deployReentrantPolicy() {
    return await (await ethers.getContractFactory('ReentrantMockPolicy')).deploy()
  }

  async function fixture() {
    const [, ownerA, ownerB] = await ethers.getSigners()

    const { safePolicyGuard } = await deploySafePolicyGuard()
    const { safeProxyFactory, safe: safeSingleton } = await deploySafeContracts()
    const safeA = await createSafe({
      owner: ownerA,
      guard: ZeroAddress,
      saltNonce: BigInt(0xa1),
      safeProxyFactory,
      singleton: safeSingleton
    })
    const safeB = await createSafe({
      owner: ownerB,
      guard: ZeroAddress,
      saltNonce: BigInt(0xb2),
      safeProxyFactory,
      singleton: safeSingleton
    })

    return { ownerA, ownerB, safePolicyGuard, safeA, safeB }
  }

  // Configures `policy` for `owner`'s Safe (via configureImmediately) using the given
  // configuration overrides, then enables the guard on that Safe.
  async function configureAndEnableGuard(owner: any, safe: any, safePolicyGuard: any, configurations: any[]) {
    await execTransaction({
      owners: [owner],
      safe,
      to: await safePolicyGuard.getAddress(),
      data: safePolicyGuard.interface.encodeFunctionData('configureImmediately', [configurations])
    })
    await execTransaction({
      owners: [owner],
      safe,
      to: await safe.getAddress(),
      data: safe.interface.encodeFunctionData('setGuard', [await safePolicyGuard.getAddress()])
    })
  }

  it('Should block a policy re-entering the guard during a check (Reentrancy)', async function () {
    const { ownerA, safePolicyGuard, safeA } = await loadFixture(fixture)

    const x = await deployReentrantPolicy()
    await x.setMode(Mode.ReenterGuardEntry)
    await configureAndEnableGuard(ownerA, safeA, safePolicyGuard, [
      createConfiguration({ policy: await x.getAddress() })
    ])

    // Outer tx succeeds: the policy catches the (blocked) reentry and returns the magic value.
    await execTransaction({ owners: [ownerA], safe: safeA, to: randomAddress() })

    expect((await x.lastReentryError()).slice(0, 10)).to.equal(id('Reentrancy()').slice(0, 10))
  })

  it("Should NOT let a malicious policy on Safe A consume another Safe B's policy state (CrossSafeCheck)", async function () {
    const { ownerA, ownerB, safePolicyGuard, safeA, safeB } = await loadFixture(fixture)

    // Safe B has a real stateful policy Y (its fallback) that counts every check it receives.
    const policyY = await deployReentrantPolicy()
    await policyY.setMode(Mode.WriteState)
    await execTransaction({
      owners: [ownerB],
      safe: safeB,
      to: await safePolicyGuard.getAddress(),
      data: safePolicyGuard.interface.encodeFunctionData('configureImmediately', [
        [createConfiguration({ policy: await policyY.getAddress() })]
      ])
    })

    // Safe A has a malicious policy X that re-enters the engine hardcoding safe = Safe B,
    // attempting to drive (and consume) Safe B's policy Y.
    const policyX = await deployReentrantPolicy()
    await policyX.setMode(Mode.ReenterEngine)
    await policyX.setReenter(await safeB.getAddress(), randomAddress())
    await configureAndEnableGuard(ownerA, safeA, safePolicyGuard, [
      createConfiguration({ policy: await policyX.getAddress() })
    ])

    // Safe A executes; X tries to drive a check for Safe B mid-check.
    await execTransaction({ owners: [ownerA], safe: safeA, to: randomAddress() })

    // The cross-Safe re-entry was rejected by CrossSafeCheck ...
    expect((await policyX.lastReentryError()).slice(0, 10)).to.equal(id('CrossSafeCheck()').slice(0, 10))
    expect(await policyX.reenterSucceeded()).to.equal(false)
    // ... and Safe B's policy state was never touched.
    expect(await policyY.writes()).to.equal(0n)
  })

  it('Should allow same-Safe re-invocation by design (the MultiSendPolicy mechanism)', async function () {
    const { ownerA, safePolicyGuard, safeA } = await loadFixture(fixture)

    const targetX = randomAddress() // outer target -> policy X
    const targetZ = randomAddress() // re-entry target -> policy Z

    // Z: a benign stateful policy on Safe A for `targetZ`.
    const policyZ = await deployReentrantPolicy()
    await policyZ.setMode(Mode.WriteState)

    // X: re-enters the engine for the SAME Safe A, targeting `targetZ` (-> policy Z).
    const policyX = await deployReentrantPolicy()
    await policyX.setMode(Mode.ReenterEngine)
    await policyX.setReenter(await safeA.getAddress(), targetZ)

    await configureAndEnableGuard(ownerA, safeA, safePolicyGuard, [
      createConfiguration({ target: targetX, policy: await policyX.getAddress() }),
      createConfiguration({ target: targetZ, policy: await policyZ.getAddress() })
    ])

    // Safe A executes a tx to targetX -> X -> re-enters the engine for A/targetZ -> Z.
    await execTransaction({ owners: [ownerA], safe: safeA, to: targetX })

    // Same-Safe re-invocation is permitted and reaches A's other policy, confined to Safe A.
    expect(await policyX.reenterSucceeded()).to.equal(true)
    expect(await policyZ.writes()).to.equal(1n)
  })

  it('Should commit state a policy writes during a successful check', async function () {
    const { ownerA, safePolicyGuard, safeA } = await loadFixture(fixture)

    const policy = await deployReentrantPolicy()
    await policy.setMode(Mode.WriteState)
    await configureAndEnableGuard(ownerA, safeA, safePolicyGuard, [
      createConfiguration({ policy: await policy.getAddress() })
    ])

    expect(await policy.writes()).to.equal(0n)
    await execTransaction({ owners: [ownerA], safe: safeA, to: randomAddress() })
    expect(await policy.writes()).to.equal(1n)
  })

  it('Should block a policy re-entering the module-guard entry (Reentrancy)', async function () {
    const { ownerA, safePolicyGuard, safeA } = await loadFixture(fixture)

    // The counterpart of the transaction-guard case above: both entry points call `_enterCheck`.
    const policy = await deployReentrantPolicy()
    await policy.setMode(Mode.ReenterModuleGuardEntry)
    await configureAndEnableGuard(ownerA, safeA, safePolicyGuard, [
      createConfiguration({ policy: await policy.getAddress() })
    ])

    await execTransaction({ owners: [ownerA], safe: safeA, to: randomAddress() })

    expect((await policy.lastReentryError()).slice(0, 10)).to.equal(id('Reentrancy()').slice(0, 10))
  })

  it('Should reject re-entering applyConfiguration from a policy configure hook', async function () {
    const { ownerA, safePolicyGuard, safeA } = await loadFixture(fixture)

    const policy = await (await ethers.getContractFactory('ReentrantConfigurePolicy')).deploy()
    const configurations = [createConfiguration({ target: randomAddress(), policy: await policy.getAddress() })]
    const applyCalldata = safePolicyGuard.interface.encodeFunctionData('applyConfiguration', [configurations])
    await policy.setReentrantCalldata(applyCalldata)

    await execTransaction({
      owners: [ownerA],
      safe: safeA,
      to: await safePolicyGuard.getAddress(),
      data: safePolicyGuard.interface.encodeFunctionData('requestConfiguration', [getConfigurationRoot(configurations)])
    })
    await time.increase(await safePolicyGuard.DELAY())

    // `applyConfiguration` deletes the pending root before calling any policy, so the policy's
    // re-entry finds nothing to apply and cannot replay the configuration.
    await execTransaction({
      owners: [ownerA],
      safe: safeA,
      to: await safePolicyGuard.getAddress(),
      data: applyCalldata
    })

    expect(await policy.reenterSucceeded()).to.equal(false)
    expect((await policy.lastReentryError()).slice(0, 10)).to.equal(id('RootNotConfigured(bytes32)').slice(0, 10))
  })

  it('Should allow a guarded Safe to execute a transaction on another guarded Safe', async function () {
    // The gate must not over-block: `_exitCheck` runs before execution begins, so a nested guarded
    // execution is a fresh top-level check rather than a reentrant one.
    const { ownerA, ownerB, safePolicyGuard, safeA, safeB } = await loadFixture(fixture)
    const { allowPolicy } = await deployAllowPolicy()

    const innerTarget = randomAddress()
    await configureAndEnableGuard(ownerB, safeB, safePolicyGuard, [
      createConfiguration({ target: innerTarget, policy: await allowPolicy.getAddress() })
    ])
    await configureAndEnableGuard(ownerA, safeA, safePolicyGuard, [
      createConfiguration({
        target: await safeB.getAddress(),
        selector: safeB.interface.getFunction('execTransaction')?.selector,
        policy: await allowPolicy.getAddress()
      })
    ])

    // Safe B's owner pre-approves the inner hash so that Safe A can be the executor.
    const innerHash = await getSafeTransactionHash({ safe: safeB, to: innerTarget })
    await safeB.connect(ownerB).approveHash(innerHash)
    const preApproved = await preApprovedSignature(ownerB)

    await expect(
      execTransaction({
        owners: [ownerA],
        safe: safeA,
        to: await safeB.getAddress(),
        data: safeB.interface.encodeFunctionData('execTransaction', [
          innerTarget,
          0n,
          '0x',
          SafeOperation.Call,
          0n,
          0n,
          0n,
          ZeroAddress,
          ZeroAddress,
          preApproved
        ])
      })
    ).to.not.be.reverted
  })
})
