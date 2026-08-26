import { loadFixture } from '@nomicfoundation/hardhat-network-helpers'
import { expect } from 'chai'
import { ZeroAddress } from 'ethers'
import { ethers } from 'hardhat'

import {
  buildMultiSendSafeTx,
  buildSafeTransaction,
  createConfiguration,
  createSafe,
  enableGuard,
  encodeOneTimeGrantConfig,
  execTransaction,
  randomAddress,
  SafeOperation
} from '../src/utils'
import { deploySafePolicyGuard, deploySafeContracts, deployMultiSendPolicy, deployOneTimeAllowPolicy } from './deploy'

describe('OneTimeAllowPolicy', function () {
  async function fixture() {
    const [deployer, owner, other] = await ethers.getSigners()

    // Deploy the SafePolicyGuard contract
    const { safePolicyGuard } = await deploySafePolicyGuard()

    // Deploy the Safe contracts
    const { safeProxyFactory, safe: safeSingleton, multiSend } = await deploySafeContracts()
    const safe = await createSafe({
      owners: [owner],
      guard: ZeroAddress, // No guard at this point
      saltNonce: BigInt(0xc),
      safeProxyFactory,
      singleton: safeSingleton
    })

    // Deploy OneTimeAllowPolicy contract
    const { oneTimeAllowPolicy } = await deployOneTimeAllowPolicy()

    // Deploy MultiSendPolicy contract
    const { multiSendPolicy } = await deployMultiSendPolicy()

    // Deploy Test Access Selector
    const accessSelector = await (await ethers.getContractFactory('TestAccessSelector')).deploy()

    // Fund the Safe
    await owner.sendTransaction({ to: await safe.getAddress(), value: ethers.parseEther('10') })

    return {
      deployer,
      owner,
      other,
      safePolicyGuard,
      safe,
      oneTimeAllowPolicy,
      multiSend,
      multiSendPolicy,
      accessSelector
    }
  }

  describe('Integration with SafePolicyGuard', function () {
    it('Should allow the configured transaction exactly once', async function () {
      const { owner, safePolicyGuard, safe, oneTimeAllowPolicy } = await loadFixture(fixture)

      const target = randomAddress()
      const value = ethers.parseEther('1')

      await enableGuard({
        owners: [owner],
        safe,
        safePolicyGuard,
        configurations: [
          createConfiguration({
            target,
            policy: await oneTimeAllowPolicy.getAddress(),
            data: encodeOneTimeGrantConfig()
          })
        ]
      })

      await execTransaction({ owners: [owner], safe, to: target, value })
      expect(await ethers.provider.getBalance(target)).to.equal(value)

      // The grant is spent, so the very same transaction is now denied.
      await expect(execTransaction({ owners: [owner], safe, to: target, value })).to.be.revertedWithCustomError(
        safePolicyGuard,
        'PolicyReverted'
      )

      expect(await ethers.provider.getBalance(target)).to.equal(value)
    })

    it('Should spend a fallback grant on a single arbitrary transaction', async function () {
      const { owner, safePolicyGuard, safe, oneTimeAllowPolicy } = await loadFixture(fixture)

      const granted = randomAddress()
      const other = randomAddress()

      await enableGuard({
        owners: [owner],
        safe,
        safePolicyGuard,
        configurations: [
          createConfiguration({
            target: granted,
            policy: await oneTimeAllowPolicy.getAddress(),
            data: encodeOneTimeGrantConfig()
          }),
          // A fallback pointing at the policy with no grant recorded against the fallback key.
          createConfiguration({ policy: await oneTimeAllowPolicy.getAddress(), data: encodeOneTimeGrantConfig() })
        ]
      })

      // The fallback grant above is itself one-time; spend it so the next call has nothing left.
      await execTransaction({ owners: [owner], safe, to: other, value: ethers.parseEther('1') })

      await expect(
        execTransaction({ owners: [owner], safe, to: randomAddress(), value: ethers.parseEther('1') })
      ).to.be.revertedWithCustomError(safePolicyGuard, 'PolicyReverted')
    })

    it('Should not let a batch replay the single grant', async function () {
      const { owner, safePolicyGuard, safe, oneTimeAllowPolicy, multiSend, multiSendPolicy } =
        await loadFixture(fixture)

      const target = randomAddress()
      const value = ethers.parseEther('1')
      const multiSendSelector = multiSend.interface.getFunction('multiSend')?.selector

      await enableGuard({
        owners: [owner],
        safe,
        safePolicyGuard,
        configurations: [
          createConfiguration({
            target,
            policy: await oneTimeAllowPolicy.getAddress(),
            data: encodeOneTimeGrantConfig()
          }),
          createConfiguration({
            target: await multiSend.getAddress(),
            selector: multiSendSelector,
            operation: SafeOperation.DelegateCall,
            policy: await multiSendPolicy.getAddress()
          })
        ]
      })

      const nonce = await safe.nonce()
      const transfer = buildSafeTransaction({ to: target, value, data: '0x', nonce })
      const multiSendTx = await buildMultiSendSafeTx(multiSend, [transfer, transfer], nonce)

      await expect(
        execTransaction({
          owners: [owner],
          safe,
          to: await multiSend.getAddress(),
          data: multiSendTx.data,
          operation: SafeOperation.DelegateCall
        })
      ).to.be.revertedWithCustomError(safePolicyGuard, 'PolicyReverted')

      expect(await ethers.provider.getBalance(target)).to.equal(0n)
    })
  })

  describe('Policy Configuration', function () {
    it('Should record the grant against the configuring policy guard', async function () {
      const { owner, safePolicyGuard, safe, oneTimeAllowPolicy, accessSelector } = await loadFixture(fixture)

      const target = randomAddress()
      const access = await accessSelector.create(target, '0x00000000', SafeOperation.Call)

      expect(await oneTimeAllowPolicy.isGranted(safePolicyGuard, safe, access)).to.equal(false)

      await enableGuard({
        owners: [owner],
        safe,
        safePolicyGuard,
        configurations: [
          createConfiguration({
            target,
            policy: await oneTimeAllowPolicy.getAddress(),
            data: encodeOneTimeGrantConfig()
          })
        ]
      })

      expect(await oneTimeAllowPolicy.isGranted(safePolicyGuard, safe, access)).to.equal(true)
    })

    it('Should grant and revoke through configure', async function () {
      const { deployer, safe, oneTimeAllowPolicy, accessSelector } = await loadFixture(fixture)

      // `configure` is reachable by anyone for its own namespace, so the grant lifecycle can be
      // exercised directly against the policy -- here `deployer` is the namespacing `msg.sender`.
      const access = await accessSelector.create(randomAddress(), '0x00000000', SafeOperation.Call)

      await oneTimeAllowPolicy.connect(deployer).configure(safe, access, encodeOneTimeGrantConfig())
      expect(await oneTimeAllowPolicy.isGranted(deployer, safe, access)).to.equal(true)

      await oneTimeAllowPolicy.connect(deployer).configure(safe, access, encodeOneTimeGrantConfig(false))
      expect(await oneTimeAllowPolicy.isGranted(deployer, safe, access)).to.equal(false)
    })

    it('Should reject a configuration carrying no flag', async function () {
      const { deployer, safe, oneTimeAllowPolicy, accessSelector } = await loadFixture(fixture)

      const access = await accessSelector.create(randomAddress(), '0x00000000', SafeOperation.Call)
      await expect(oneTimeAllowPolicy.connect(deployer).configure(safe, access, '0x')).to.be.reverted
    })
  })

  describe('Events', function () {
    it('Should emit when a transaction spends the allowance', async function () {
      const { owner, safePolicyGuard, safe, oneTimeAllowPolicy, accessSelector } = await loadFixture(fixture)

      const target = randomAddress()
      const access = await accessSelector.create(target, '0x00000000', SafeOperation.Call)

      await enableGuard({
        owners: [owner],
        safe,
        safePolicyGuard,
        configurations: [
          createConfiguration({
            target,
            policy: await oneTimeAllowPolicy.getAddress(),
            data: encodeOneTimeGrantConfig()
          })
        ]
      })

      // Spending the grant revokes it, which an indexer only learns about from this event -- the
      // guard emits nothing for a transaction it permits.
      await expect(
        execTransaction({
          owners: [owner],
          safe,
          to: target,
          value: ethers.parseEther('1')
        })
      )
        .to.emit(oneTimeAllowPolicy, 'OneTimeAllowanceUsed')
        .withArgs(safePolicyGuard, safe, access)
    })
  })
})
