import { loadFixture, time } from '@nomicfoundation/hardhat-network-helpers'
import { expect } from 'chai'
import { ZeroAddress } from 'ethers'
import { ethers } from 'hardhat'

import {
  buildMultiSendSafeTx,
  buildSafeTransaction,
  createConfiguration,
  enableGuard,
  execTransaction,
  getConfigurationRoot,
  getGuard,
  randomAddress,
  SafeOperation
} from '../src/utils'
import { deployAllowPolicy, deploySafeContracts } from './deploy'
import { safePolicyGuardFixture as fixture } from './fixtures'

describe('SafePolicyGuard -- interface surface and guard entries', function () {
  describe('constructor', function () {
    it('Should set the delay', async function () {
      const { safePolicyGuard, delay } = await loadFixture(fixture)
      expect(await safePolicyGuard.DELAY()).to.equal(delay)
    })
  })

  describe('supportsInterface', function () {
    // Pinned as literals rather than recomputed from the ABI: these IDs are part of the deployed
    // surface, and deriving them here would let a signature change go unnoticed.
    const INTERFACE_IDS = {
      PolicyEngine: '0x04a9e3cd',
      SafeModuleGuard: '0x58401ed8',
      SafeTransactionGuard: '0xe6d7a83a',
      ERC165: '0x01ffc9a7'
    }

    it('Should support the declared interfaces', async function () {
      const { safePolicyGuard } = await loadFixture(fixture)

      for (const [name, id] of Object.entries(INTERFACE_IDS)) {
        expect(await safePolicyGuard.supportsInterface(id), name).to.equal(true)
      }
    })

    it('Should not claim support for an unknown interface', async function () {
      // Without this, the assertions above would pass just as well against a `supportsInterface`
      // that returned true unconditionally. `0xffffffff` is the ID ERC-165 requires to be false.
      const { safePolicyGuard } = await loadFixture(fixture)

      expect(await safePolicyGuard.supportsInterface('0xffffffff')).to.equal(false)
    })
  })

  describe('checkTransaction', function () {
    it('Should be able to block normal transactions when guard is enabled', async function () {
      const { owner, safePolicyGuard, safe } = await loadFixture(fixture)

      // Enable the guard on safe
      await enableGuard({ owners: [owner], safe, safePolicyGuard })

      // Try to execute a transaction that is not configured
      await expect(
        execTransaction({
          owners: [owner],
          safe,
          to: randomAddress()
        })
      )
        .to.be.revertedWithCustomError(safePolicyGuard, 'AccessDenied')
        .withArgs(ZeroAddress)
    })

    it('Should revert when safeTxGas is non-zero', async function () {
      const { safePolicyGuard } = await loadFixture(fixture)

      // A non-zero `safeTxGas` must be rejected before any policy lookup. Call the transaction
      // guard entry point directly so the revert originates in the guard (not routed through a
      // full Safe execution).
      const checkTransaction = safePolicyGuard.getFunction(
        'checkTransaction(address,uint256,bytes,uint8,uint256,uint256,uint256,address,address,bytes,address)'
      )
      await expect(
        checkTransaction(
          randomAddress(),
          0n,
          '0x',
          SafeOperation.Call,
          1n,
          0n,
          0n,
          ZeroAddress,
          ZeroAddress,
          '0x',
          ZeroAddress
        )
      ).to.be.revertedWithCustomError(safePolicyGuard, 'NonZeroSafeTxGas')
    })

    it('Should revert when safeTxGas is non-zero through a Safe execution', async function () {
      // The unit test above asserts the ordering (rejected before policy lookup, since no policy is
      // configured there); this one asserts the Safe actually forwards `safeTxGas` to the guard.
      const { owner, safePolicyGuard, safe, mockPolicy } = await loadFixture(fixture)
      const target = randomAddress()
      await enableGuard({
        owners: [owner],
        safe,
        safePolicyGuard,
        configurations: [createConfiguration({ target, policy: await mockPolicy.getAddress() })]
      })

      await expect(
        execTransaction({ owners: [owner], safe, to: target, safeTxGas: 100_000n })
      ).to.be.revertedWithCustomError(safePolicyGuard, 'NonZeroSafeTxGas')
    })

    it('Should revert when gasPrice is non-zero', async function () {
      const { owner, safePolicyGuard, safe, mockPolicy } = await loadFixture(fixture)
      const target = randomAddress()
      await enableGuard({
        owners: [owner],
        safe,
        safePolicyGuard,
        configurations: [createConfiguration({ target, policy: await mockPolicy.getAddress() })]
      })

      await expect(execTransaction({ owners: [owner], safe, to: target, gasPrice: 1n })).to.be.revertedWithCustomError(
        safePolicyGuard,
        'NonZeroGasPrice'
      )
    })

    it('Should revert a direct engine checkTransaction outside a top-level check (NotChecking)', async function () {
      const { safePolicyGuard, safe } = await loadFixture(fixture)

      // The engine `checkTransaction` (6-arg) is only reachable while a top-level guard check is
      // in progress. Calling it directly (no `_enterCheck`) must revert.
      const engineCheck = safePolicyGuard.getFunction('checkTransaction(address,address,uint256,bytes,uint8,bytes)')
      await expect(
        engineCheck(await safe.getAddress(), randomAddress(), 0n, '0x', SafeOperation.Call, '0x')
      ).to.be.revertedWithCustomError(safePolicyGuard, 'NotChecking')
    })
  })

  describe('checkModuleTransaction', function () {
    it('Should be able to block module transactions when guard is enabled', async function () {
      const { owner, safePolicyGuard, safe } = await loadFixture(fixture)

      // Deploy Test Module
      const TestModuleFactory = await ethers.getContractFactory('TestModule')
      const testModule = await TestModuleFactory.deploy()

      // Enable the module on safe
      await execTransaction({
        owners: [owner],
        safe,
        to: await safe.getAddress(),
        data: safe.interface.encodeFunctionData('enableModule', [await testModule.getAddress()])
      })

      // Enable the guard on safe as ModuleGuard (Using Safe v1.5.0)
      await execTransaction({
        owners: [owner],
        safe,
        to: await safe.getAddress(),
        data: safe.interface.encodeFunctionData('setModuleGuard', [await safePolicyGuard.getAddress()])
      })

      // Try to execute a transaction that is not configured through the module
      await expect(testModule.executeTx(await safe.getAddress(), randomAddress(), 0, '0x', SafeOperation.Call))
        .to.be.revertedWithCustomError(safePolicyGuard, 'AccessDenied')
        .withArgs(ZeroAddress)
    })
  })

  describe('Guard removal', function () {
    it('Should remove the guard after the delay via a single batch', async function () {
      // The documented flow: request an AllowPolicy for `setGuard`, wait out the delay, then apply
      // it and remove the guard in one MultiSend.
      const { owner, safePolicyGuard, safe, delay } = await loadFixture(fixture)
      const { allowPolicy } = await deployAllowPolicy()
      const { multiSend } = await deploySafeContracts()

      await enableGuard({
        owners: [owner],
        safe,
        safePolicyGuard,
        configurations: [
          createConfiguration({
            target: await multiSend.getAddress(),
            selector: multiSend.interface.getFunction('multiSend')?.selector,
            operation: SafeOperation.DelegateCall,
            policy: await allowPolicy.getAddress()
          })
        ]
      })

      const configurations = [
        createConfiguration({
          target: await safe.getAddress(),
          selector: safe.interface.getFunction('setGuard')?.selector,
          policy: await allowPolicy.getAddress()
        })
      ]

      await execTransaction({
        owners: [owner],
        safe,
        to: await safePolicyGuard.getAddress(),
        data: safePolicyGuard.interface.encodeFunctionData('requestConfiguration', [
          getConfigurationRoot(configurations)
        ])
      })
      await time.increase(delay)

      const batch = await buildMultiSendSafeTx(
        multiSend,
        [
          buildSafeTransaction({
            to: await safePolicyGuard.getAddress(),
            data: safePolicyGuard.interface.encodeFunctionData('applyConfiguration', [configurations]),
            nonce: 0
          }),
          buildSafeTransaction({
            to: await safe.getAddress(),
            data: safe.interface.encodeFunctionData('setGuard', [ZeroAddress]),
            nonce: 1
          })
        ],
        await safe.nonce()
      )

      await execTransaction({
        owners: [owner],
        safe,
        to: await multiSend.getAddress(),
        data: batch.data,
        operation: SafeOperation.DelegateCall
      })

      expect(await getGuard(safe)).to.equal(ZeroAddress)
    })
  })
})
