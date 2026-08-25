import { loadFixture } from '@nomicfoundation/hardhat-network-helpers'
import { expect } from 'chai'
import { Signer, ZeroAddress } from 'ethers'
import { ethers } from 'hardhat'

import {
  SafeOperation,
  appendSignatureExtension,
  buildSafeTransaction,
  createConfiguration,
  createSafe,
  enableGuard,
  encodeModuleConfig,
  encodeMultiSend,
  execTransaction,
  randomAddress,
  safeSignTypedData
} from '../src/utils'
import { Safe, SafePolicyGuard } from '../typechain-types'
import { deployAllowedModulePolicy, deployMultiSendPolicy, deploySafeContracts, deploySafePolicyGuard } from './deploy'

/**
 * The module authorizing a transaction reaches policies as its own engine-supplied argument, not
 * through the caller-chosen `context`. These tests pin that boundary: a forged context must not be
 * mistaken for a module, while genuine module transactions (including MultiSend batches, which are
 * checked recursively) must still see the real module.
 */
describe('Authenticated module parameter', function () {
  async function fixture() {
    const [deployer, owner, other] = await ethers.getSigners()

    const { safePolicyGuard } = await deploySafePolicyGuard()
    const { allowedModulePolicy } = await deployAllowedModulePolicy()
    const { multiSendPolicy } = await deployMultiSendPolicy()
    const { safeProxyFactory, safe: safeSingleton, multiSend } = await deploySafeContracts()

    const safe = await createSafe({
      owner,
      guard: ZeroAddress,
      saltNonce: BigInt(0x4d),
      safeProxyFactory,
      singleton: safeSingleton
    })

    const testModule = await (await ethers.getContractFactory('TestModule')).deploy()
    const moduleAddress = await testModule.getAddress()

    return {
      deployer,
      owner,
      other,
      safe,
      safePolicyGuard,
      allowedModulePolicy,
      multiSendPolicy,
      multiSend,
      testModule,
      moduleAddress
    }
  }

  /**
   * Builds the `AllowedModulePolicy` CALL-fallback configuration -- the part `enableGuard` does not
   * cover -- so the policy is reached by owner transactions as well as module ones, then hands the
   * module and both guards to `enableGuard`.
   */
  async function hardenWithModuleFallback(
    owner: Signer,
    safe: Safe,
    safePolicyGuard: SafePolicyGuard,
    policyAddress: string,
    moduleAddress: string
  ) {
    await enableGuard({
      owner,
      safe,
      safePolicyGuard,
      configurations: [createConfiguration({ policy: policyAddress, data: encodeModuleConfig(moduleAddress) })],
      module: moduleAddress,
      moduleGuard: true
    })
  }

  describe('Forged module identity', function () {
    it('Should deny an owner transaction that appends a module address as context', async function () {
      const { owner, other, safe, safePolicyGuard, allowedModulePolicy, moduleAddress } = await loadFixture(fixture)
      await hardenWithModuleFallback(
        owner,
        safe,
        safePolicyGuard,
        await allowedModulePolicy.getAddress(),
        moduleAddress
      )

      const to = randomAddress()
      const safeTx = buildSafeTransaction({ to, nonce: await safe.nonce() })

      // The owner signs the transaction. The signed hash does not cover the `signatures` bytes, so
      // it is identical whether or not a context is appended -- which is what makes the context
      // freely choosable by whoever submits the transaction.
      const { data: signature } = await safeSignTypedData(owner, await safe.getAddress(), safeTx)

      // `other` is not an owner and signed nothing; it appends a well-formed context envelope
      // carrying a forged "module". The envelope is valid, so the guard does decode and pass it to
      // the policy -- the denial must come from the policy reading `module`, not from the decode.
      const forgedContext = ethers.AbiCoder.defaultAbiCoder().encode(['address'], [moduleAddress])
      const signatures = appendSignatureExtension(signature, forgedContext)

      await expect(
        safe
          .connect(other)
          .execTransaction(to, 0n, '0x', SafeOperation.Call, 0n, 0n, 0n, ZeroAddress, ZeroAddress, signatures)
      )
        .to.be.revertedWithCustomError(safePolicyGuard, 'PolicyReverted')
        .withArgs(
          await allowedModulePolicy.getAddress(),
          allowedModulePolicy.interface.encodeErrorResult('InvalidModule', [])
        )
    })

    it('Should deny an owner transaction with no context', async function () {
      const { owner, safe, safePolicyGuard, allowedModulePolicy, moduleAddress } = await loadFixture(fixture)
      await hardenWithModuleFallback(
        owner,
        safe,
        safePolicyGuard,
        await allowedModulePolicy.getAddress(),
        moduleAddress
      )

      // `module` is `address(0)` for an owner transaction, so the policy rejects it. The revert
      // reason is the policy's own `InvalidModule`, forwarded by the engine in `PolicyReverted`.
      await expect(execTransaction({ owners: [owner], safe, to: randomAddress() }))
        .to.be.revertedWithCustomError(safePolicyGuard, 'PolicyReverted')
        .withArgs(
          await allowedModulePolicy.getAddress(),
          allowedModulePolicy.interface.encodeErrorResult('InvalidModule', [])
        )
    })
  })

  describe('Genuine module transactions', function () {
    it('Should allow a transaction from the configured module', async function () {
      const { owner, safe, safePolicyGuard, allowedModulePolicy, testModule, moduleAddress } =
        await loadFixture(fixture)
      await hardenWithModuleFallback(
        owner,
        safe,
        safePolicyGuard,
        await allowedModulePolicy.getAddress(),
        moduleAddress
      )

      expect(
        await testModule.executeTx.staticCall(await safe.getAddress(), randomAddress(), 0, '0x', SafeOperation.Call)
      ).to.equal(true)
    })

    it('Should not leak the module into a later owner transaction', async function () {
      const { owner, safe, safePolicyGuard, allowedModulePolicy, testModule, moduleAddress } =
        await loadFixture(fixture)
      await hardenWithModuleFallback(
        owner,
        safe,
        safePolicyGuard,
        await allowedModulePolicy.getAddress(),
        moduleAddress
      )

      // A successful module transaction sets `$checkingModule`; `_exitCheck` must clear it, or the
      // next owner transaction would be checked as though the module had authorized it.
      await testModule.executeTx(await safe.getAddress(), randomAddress(), 0, '0x', SafeOperation.Call)

      await expect(execTransaction({ owners: [owner], safe, to: randomAddress() }))
        .to.be.revertedWithCustomError(safePolicyGuard, 'PolicyReverted')
        .withArgs(
          await allowedModulePolicy.getAddress(),
          allowedModulePolicy.interface.encodeErrorResult('InvalidModule', [])
        )
    })

    it('Should propagate the module to MultiSend sub-transaction checks', async function () {
      const {
        owner,
        safe,
        safePolicyGuard,
        allowedModulePolicy,
        multiSendPolicy,
        multiSend,
        testModule,
        moduleAddress
      } = await loadFixture(fixture)

      const guardAddress = await safePolicyGuard.getAddress()
      const safeAddress = await safe.getAddress()
      const multiSendAddress = await multiSend.getAddress()
      const subTarget = randomAddress()

      // MultiSendPolicy for the batch itself, AllowedModulePolicy for the sub-transaction target.
      // The sub-checks are driven by MultiSendPolicy recursing into the engine, so they only pass
      // if the module recorded at the guard entry is still what the engine supplies.
      await execTransaction({
        owners: [owner],
        safe,
        to: guardAddress,
        data: safePolicyGuard.interface.encodeFunctionData('configureImmediately', [
          [
            createConfiguration({
              target: multiSendAddress,
              selector: multiSend.interface.getFunction('multiSend')!.selector,
              operation: SafeOperation.DelegateCall,
              policy: await multiSendPolicy.getAddress()
            }),
            createConfiguration({
              target: subTarget,
              policy: await allowedModulePolicy.getAddress(),
              data: encodeModuleConfig(moduleAddress)
            })
          ]
        ])
      })
      await execTransaction({
        owners: [owner],
        safe,
        to: safeAddress,
        data: safe.interface.encodeFunctionData('enableModule', [moduleAddress])
      })
      await execTransaction({
        owners: [owner],
        safe,
        to: safeAddress,
        data: safe.interface.encodeFunctionData('setModuleGuard', [guardAddress])
      })

      const batch = multiSend.interface.encodeFunctionData('multiSend', [
        encodeMultiSend([{ to: subTarget, value: 0, data: '0x', operation: SafeOperation.Call }])
      ])

      expect(
        await testModule.executeTx.staticCall(safeAddress, multiSendAddress, 0, batch, SafeOperation.DelegateCall)
      ).to.equal(true)
    })
  })

  describe('Configuration', function () {
    it('Should reject configuring the zero address as an allowed module', async function () {
      const { owner, safe, safePolicyGuard, allowedModulePolicy } = await loadFixture(fixture)

      // A zero entry would be matched by every owner transaction, for which the engine supplies
      // `module == address(0)`, turning the policy into an allow-all.
      await expect(
        execTransaction({
          owners: [owner],
          safe,
          to: await safePolicyGuard.getAddress(),
          data: safePolicyGuard.interface.encodeFunctionData('configureImmediately', [
            [
              createConfiguration({
                policy: await allowedModulePolicy.getAddress(),
                data: encodeModuleConfig(ZeroAddress)
              })
            ]
          ])
        })
      ).to.be.revertedWithCustomError(allowedModulePolicy, 'InvalidModule')
    })
  })
})
