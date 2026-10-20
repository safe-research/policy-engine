import { loadFixture } from '@nomicfoundation/hardhat-network-helpers'
import SignMessageLibArtifact from '@safe-global/safe-smart-account/build/artifacts/contracts/libraries/SignMessageLib.sol/SignMessageLib.json'
import { expect } from 'chai'
import { Signer, ZeroAddress } from 'ethers'
import { ethers } from 'hardhat'

import {
  EIP712_MODULE_TRANSACTION_APPROVAL_TYPE,
  ModuleTransaction,
  SafeOperation,
  buildSafeTransaction,
  calculateSafeMessageHash,
  createConfiguration,
  createSafe,
  enableGuard,
  encodeCoSignerConfig,
  encodeMultiSend,
  execTransaction,
  hashModuleTransaction,
  signModuleTransactionApproval
} from '../src/utils'
import { TestModule } from '../typechain-types'
import {
  deployAllowPolicy,
  deployCoSignerPolicy,
  deployMultiSendPolicy,
  deploySafeContracts,
  deploySafePolicyGuard
} from './deploy'

const EIP1271_MAGIC_VALUE = '0x1626ba7e'

/**
 * `CoSignerPolicy` on the module path.
 *
 * `execTransactionFromModule` carries no signatures and never advances the Safe nonce, so neither
 * the owner-path context nor the Safe transaction hash can serve there. The policy instead spends
 * a use the co-signer granted ahead of time for the exact module transaction -- identified by a
 * nonce-free hash the check re-derives, so uses are unordered -- with relayed signatures carrying
 * their own one-time nonce.
 *
 * The first block is the regression for ACK3 L3: before this, the module path rebuilt the
 * owner-path hash with `nonce() - 1`, which a Safe co-signer's stale `signMessage` pre-approval
 * satisfied through ERC-1271 with an empty signature.
 */
describe('CoSignerPolicy on the module path', function () {
  async function fixture() {
    const [, owner, cosignerOwner, cosigner, recipient, other] = await ethers.getSigners()

    const { safePolicyGuard } = await deploySafePolicyGuard()
    const { coSignerPolicy } = await deployCoSignerPolicy()
    const { allowPolicy } = await deployAllowPolicy()
    const { multiSendPolicy } = await deployMultiSendPolicy()
    const {
      safeProxyFactory,
      safe: safeSingleton,
      compatibilityFallbackHandler,
      multiSend
    } = await deploySafeContracts()
    const signMessageLib = await (
      await ethers.getContractFactory(SignMessageLibArtifact.abi, SignMessageLibArtifact.bytecode)
    ).deploy()

    const safe = await createSafe({
      owners: [owner],
      guard: ZeroAddress,
      saltNonce: BigInt(0x7a),
      safeProxyFactory,
      singleton: safeSingleton
    })
    await owner.sendTransaction({ to: await safe.getAddress(), value: ethers.parseEther('10') })

    // A co-signer that is itself a Safe. The CompatibilityFallbackHandler makes it answer
    // ERC-1271, including the empty-signature "pre-approved hash" path backed by `signedMessages`.
    const cosignerSafe = await createSafe({
      owners: [cosignerOwner],
      guard: ZeroAddress,
      saltNonce: BigInt(0x7b),
      fallbackHandler: await compatibilityFallbackHandler.getAddress(),
      safeProxyFactory,
      singleton: safeSingleton
    })

    const testModuleFactory = await ethers.getContractFactory('TestModule')
    const testModule = (await testModuleFactory.deploy()) as unknown as TestModule
    const otherModule = (await testModuleFactory.deploy()) as unknown as TestModule

    return {
      owner,
      cosignerOwner,
      cosigner,
      recipient,
      other,
      safe,
      cosignerSafe,
      safePolicyGuard,
      coSignerPolicy,
      allowPolicy,
      multiSendPolicy,
      multiSend,
      signMessageLib,
      testModule,
      otherModule
    }
  }
  type Fixture = Awaited<ReturnType<typeof fixture>>

  /**
   * Gates plain transfers to `recipient` behind `cosigner`, leaves transfers to `other` freely
   * allowed (so the Safe can run an unrelated owner transaction at any nonce), lets `MultiSend`
   * batches through to the per-sub-transaction checks, enables both modules and installs the guard
   * on both paths.
   */
  async function harden(f: Fixture, cosigner: string) {
    const safeAddress = await f.safe.getAddress()
    // No guard yet, so enabling the second module needs no policy.
    await execTransaction({
      owners: [f.owner],
      safe: f.safe,
      to: safeAddress,
      data: f.safe.interface.encodeFunctionData('enableModule', [await f.otherModule.getAddress()])
    })
    await enableGuard({
      owners: [f.owner],
      safe: f.safe,
      safePolicyGuard: f.safePolicyGuard,
      configurations: [
        createConfiguration({
          target: await f.recipient.getAddress(),
          policy: await f.coSignerPolicy.getAddress(),
          data: encodeCoSignerConfig(cosigner)
        }),
        createConfiguration({ target: await f.other.getAddress(), policy: await f.allowPolicy.getAddress() }),
        createConfiguration({
          target: await f.multiSend.getAddress(),
          selector: f.multiSend.interface.getFunction('multiSend')!.selector,
          operation: SafeOperation.DelegateCall,
          policy: await f.multiSendPolicy.getAddress()
        })
      ],
      module: await f.testModule.getAddress(),
      moduleGuard: true
    })
  }

  /** A 1 ETH transfer to `recipient` driven by `testModule`. */
  async function moduleTransfer(f: Fixture, overrides: Partial<ModuleTransaction> = {}): Promise<ModuleTransaction> {
    return {
      policyGuard: await f.safePolicyGuard.getAddress(),
      safe: await f.safe.getAddress(),
      module: await f.testModule.getAddress(),
      to: await f.recipient.getAddress(),
      value: ethers.parseEther('1'),
      data: '0x',
      operation: SafeOperation.Call,
      ...overrides
    }
  }

  async function moduleTransactionHash(f: Fixture, tx: ModuleTransaction): Promise<string> {
    return f.coSignerPolicy.getModuleTransactionHash(
      tx.policyGuard,
      tx.safe,
      tx.module,
      tx.to,
      tx.value,
      tx.data,
      tx.operation
    )
  }

  function randomNonce(): bigint {
    return ethers.toBigInt(ethers.randomBytes(32))
  }

  /** The co-signer signs off-chain; `other`, who holds no role at all, relays the signature. */
  async function approveBySignature(
    f: Fixture,
    signer: Signer,
    tx: ModuleTransaction,
    uses = 1n,
    nonce = randomNonce()
  ) {
    const moduleTxHash = await moduleTransactionHash(f, tx)
    const { data: signature } = await signModuleTransactionApproval(signer, await f.coSignerPolicy.getAddress(), {
      moduleTxHash,
      uses,
      nonce
    })
    return f.coSignerPolicy
      .connect(f.other)
      .approveModuleTransactionWithSignature(
        tx.policyGuard,
        tx.safe,
        await signer.getAddress(),
        moduleTxHash,
        uses,
        nonce,
        signature
      )
  }

  function executeFromModule(f: Fixture, tx: ModuleTransaction, module: TestModule = f.testModule) {
    return module.connect(f.other).executeTx(tx.safe, tx.to, tx.value, tx.data, tx.operation)
  }

  async function remainingUses(f: Fixture, cosigner: string, tx: ModuleTransaction): Promise<bigint> {
    return f.coSignerPolicy.getModuleTransactionApprovals(
      tx.policyGuard,
      tx.safe,
      cosigner,
      await moduleTransactionHash(f, tx)
    )
  }

  async function expectUnauthorized(f: Fixture, call: Promise<unknown>) {
    await expect(call)
      .to.be.revertedWithCustomError(f.safePolicyGuard, 'PolicyReverted')
      .withArgs(await f.coSignerPolicy.getAddress(), f.coSignerPolicy.interface.encodeErrorResult('Unauthorized', []))
  }

  describe('ACK3 L3 regression', function () {
    it('Should not let a module reuse a stale owner-path pre-approval of a Safe co-signer', async function () {
      const f = await loadFixture(fixture)
      const cosignerSafeAddress = await f.cosignerSafe.getAddress()
      const recipientAddress = await f.recipient.getAddress()
      const amount = ethers.parseEther('1')
      const { chainId } = await ethers.provider.getNetwork()

      await harden(f, cosignerSafeAddress)

      // The co-signer Safe pre-approves owner transaction T for the Safe's current nonce `n`, the
      // way a Safe signs anything: `SignMessageLib.signMessage` via DELEGATECALL.
      const nonce = await f.safe.nonce()
      const transfer = buildSafeTransaction({ to: recipientAddress, value: amount, data: '0x', nonce })
      const safeTxHash = await f.safe.getTransactionHash(
        transfer.to!,
        transfer.value!,
        transfer.data!,
        transfer.operation!,
        transfer.safeTxGas!,
        transfer.baseGas!,
        transfer.gasPrice!,
        transfer.gasToken!,
        transfer.refundReceiver!,
        nonce
      )
      const message = ethers.AbiCoder.defaultAbiCoder().encode(['bytes32'], [safeTxHash])
      await execTransaction({
        owners: [f.cosignerOwner],
        safe: f.cosignerSafe,
        to: await f.signMessageLib.getAddress(),
        data: f.signMessageLib.interface.encodeFunctionData('signMessage', [message]),
        operation: SafeOperation.DelegateCall
      })
      expect(
        await f.cosignerSafe.signedMessages(
          await calculateSafeMessageHash(cosignerSafeAddress, message, Number(chainId))
        )
      ).to.equal(1n)
      const erc1271 = new ethers.Contract(
        cosignerSafeAddress,
        ['function isValidSignature(bytes32, bytes) view returns (bytes4)'],
        ethers.provider
      )
      expect(await erc1271.isValidSignature(safeTxHash, '0x')).to.equal(EIP1271_MAGIC_VALUE)

      // The Safe executes a *different* owner transaction at nonce `n`: T's pre-approval is now
      // stale on the owner path and unspent in the policy -- exactly `nonce() - 1` from here on.
      await execTransaction({ owners: [f.owner], safe: f.safe, to: await f.other.getAddress(), value: 0n })
      expect(await f.safe.nonce()).to.equal(nonce + 1n)
      expect(await f.coSignerPolicy.isCoSignatureSpent(f.safePolicyGuard, f.safe, safeTxHash)).to.equal(false)

      // The module path no longer derives the owner-path hash, so the stale pre-approval is inert.
      const before = await ethers.provider.getBalance(recipientAddress)
      await expectUnauthorized(f, executeFromModule(f, await moduleTransfer(f)))
      expect(await ethers.provider.getBalance(recipientAddress)).to.equal(before)
      expect(await f.coSignerPolicy.isCoSignatureSpent(f.safePolicyGuard, f.safe, safeTxHash)).to.equal(false)
    })

    it('Should fail closed with no approval registered', async function () {
      const f = await loadFixture(fixture)
      await harden(f, await f.cosigner.getAddress())

      await expectUnauthorized(f, executeFromModule(f, await moduleTransfer(f)))
    })
  })

  describe('Approval by signature', function () {
    it('Should derive the hashes as EIP-712 typed data', async function () {
      const f = await loadFixture(fixture)
      const policyAddress = await f.coSignerPolicy.getAddress()
      const { chainId } = await ethers.provider.getNetwork()

      // The module transaction hash is the struct hash alone, nonce-free, as the check re-derives it.
      const tx = await moduleTransfer(f, { data: '0xdeadbeef' })
      const moduleTxHash = await moduleTransactionHash(f, tx)
      expect(moduleTxHash).to.equal(hashModuleTransaction(tx))

      // What the co-signer signs is the approval, under the policy's domain.
      const approval = { moduleTxHash, uses: 3n, nonce: 7n }
      expect(
        await f.coSignerPolicy.getModuleTransactionApprovalHash(moduleTxHash, approval.uses, approval.nonce)
      ).to.equal(
        ethers.TypedDataEncoder.hash(
          { chainId, verifyingContract: policyAddress },
          EIP712_MODULE_TRANSACTION_APPROVAL_TYPE,
          approval
        )
      )
    })

    it('Should allow an approved module transaction exactly once per use', async function () {
      const f = await loadFixture(fixture)
      const cosignerAddress = await f.cosigner.getAddress()
      const recipientAddress = await f.recipient.getAddress()
      await harden(f, cosignerAddress)

      const tx = await moduleTransfer(f)
      const hash = await moduleTransactionHash(f, tx)

      await expect(approveBySignature(f, f.cosigner, tx))
        .to.emit(f.coSignerPolicy, 'ModuleTransactionApproved')
        .withArgs(tx.policyGuard, tx.safe, cosignerAddress, hash, 1n)
      expect(await remainingUses(f, cosignerAddress, tx)).to.equal(1n)

      const before = await ethers.provider.getBalance(recipientAddress)
      await expect(executeFromModule(f, tx))
        .to.emit(f.coSignerPolicy, 'ModuleCoSignatureUsed')
        .withArgs(tx.policyGuard, tx.safe, tx.module, hash, 0n)
      expect((await ethers.provider.getBalance(recipientAddress)) - before).to.equal(tx.value)

      // Spent: no use is left, so the same call is denied.
      expect(await remainingUses(f, cosignerAddress, tx)).to.equal(0n)
      await expectUnauthorized(f, executeFromModule(f, tx))
    })

    it('Should reject a signature from anyone but the named co-signer', async function () {
      const f = await loadFixture(fixture)
      await harden(f, await f.cosigner.getAddress())

      const tx = await moduleTransfer(f)
      const moduleTxHash = await moduleTransactionHash(f, tx)
      const approval = { moduleTxHash, uses: 1n, nonce: randomNonce() }
      const { data: signature } = await signModuleTransactionApproval(
        f.other,
        await f.coSignerPolicy.getAddress(),
        approval
      )
      await expect(
        f.coSignerPolicy.approveModuleTransactionWithSignature(
          tx.policyGuard,
          tx.safe,
          await f.cosigner.getAddress(),
          moduleTxHash,
          approval.uses,
          approval.nonce,
          signature
        )
      ).to.be.revertedWithCustomError(f.coSignerPolicy, 'InvalidCoSignature')
    })

    it('Should relay a signature once: the approval nonce is burnt', async function () {
      const f = await loadFixture(fixture)
      const cosignerAddress = await f.cosigner.getAddress()
      await harden(f, cosignerAddress)

      const tx = await moduleTransfer(f)
      const nonce = randomNonce()
      await approveBySignature(f, f.cosigner, tx, 1n, nonce)
      expect(await f.coSignerPolicy.isApprovalNonceUsed(tx.policyGuard, tx.safe, cosignerAddress, nonce)).to.equal(true)

      // Same signature again would double the uses; a fresh nonce is a fresh approval.
      await expect(approveBySignature(f, f.cosigner, tx, 1n, nonce)).to.be.revertedWithCustomError(
        f.coSignerPolicy,
        'ApprovalNonceUsed'
      )
      expect(await remainingUses(f, cosignerAddress, tx)).to.equal(1n)
      await approveBySignature(f, f.cosigner, tx, 1n, randomNonce())
      expect(await remainingUses(f, cosignerAddress, tx)).to.equal(2n)
    })

    it('Should let the co-signer invalidate a nonce before its signature is relayed', async function () {
      const f = await loadFixture(fixture)
      const cosignerAddress = await f.cosigner.getAddress()
      await harden(f, cosignerAddress)

      const tx = await moduleTransfer(f)
      const nonce = randomNonce()
      await expect(f.coSignerPolicy.connect(f.cosigner).invalidateApprovalNonce(tx.policyGuard, tx.safe, nonce))
        .to.emit(f.coSignerPolicy, 'ApprovalNonceInvalidated')
        .withArgs(tx.policyGuard, tx.safe, cosignerAddress, nonce)

      await expect(approveBySignature(f, f.cosigner, tx, 1n, nonce)).to.be.revertedWithCustomError(
        f.coSignerPolicy,
        'ApprovalNonceUsed'
      )
      await expectUnauthorized(f, executeFromModule(f, tx))
    })

    it('Should bind the approval to the authorizing module', async function () {
      const f = await loadFixture(fixture)
      await harden(f, await f.cosigner.getAddress())

      const tx = await moduleTransfer(f)
      await approveBySignature(f, f.cosigner, tx)

      // Same Safe, same action -- but driven by the other enabled module.
      await expectUnauthorized(f, executeFromModule(f, tx, f.otherModule))
      // The use is intact for the module it names.
      await expect(executeFromModule(f, tx)).to.emit(f.coSignerPolicy, 'ModuleCoSignatureUsed')
    })

    it('Should spend uses of the exact action, in any order', async function () {
      const f = await loadFixture(fixture)
      const cosignerAddress = await f.cosigner.getAddress()
      await harden(f, cosignerAddress)

      const oneEth = await moduleTransfer(f)
      const twoEth = await moduleTransfer(f, { value: ethers.parseEther('2') })
      await approveBySignature(f, f.cosigner, oneEth, 2n)
      await approveBySignature(f, f.cosigner, twoEth, 1n)

      // Not approved at all: denied, whatever else is pending.
      await expectUnauthorized(f, executeFromModule(f, await moduleTransfer(f, { value: ethers.parseEther('3') })))

      // The later approval runs first; the earlier one's two uses follow and then run out.
      await executeFromModule(f, twoEth).then((tx) => tx.wait())
      await executeFromModule(f, oneEth).then((tx) => tx.wait())
      await executeFromModule(f, oneEth).then((tx) => tx.wait())
      expect(await remainingUses(f, cosignerAddress, oneEth)).to.equal(0n)
      expect(await remainingUses(f, cosignerAddress, twoEth)).to.equal(0n)
      await expectUnauthorized(f, executeFromModule(f, oneEth))
      await expectUnauthorized(f, executeFromModule(f, twoEth))
    })
  })

  describe('Approval by the co-signer itself', function () {
    it('Should let a Safe co-signer approve with a Safe transaction, no ERC-1271 involved', async function () {
      const f = await loadFixture(fixture)
      const cosignerSafeAddress = await f.cosignerSafe.getAddress()
      await harden(f, cosignerSafeAddress)

      const tx = await moduleTransfer(f)
      const hash = await moduleTransactionHash(f, tx)
      await execTransaction({
        owners: [f.cosignerOwner],
        safe: f.cosignerSafe,
        to: await f.coSignerPolicy.getAddress(),
        data: f.coSignerPolicy.interface.encodeFunctionData('approveModuleTransaction', [
          tx.policyGuard,
          tx.safe,
          hash,
          1n
        ])
      })
      expect(await remainingUses(f, cosignerSafeAddress, tx)).to.equal(1n)

      await expect(executeFromModule(f, tx)).to.emit(f.coSignerPolicy, 'ModuleCoSignatureUsed')
    })

    it('Should accept a Safe co-signer pre-signed message for the approval digest', async function () {
      // The very mechanism ACK3 L3 exploited -- ERC-1271 with an empty signature over a
      // `signMessage`d hash -- is sound once the digest lives in the policy's own domain: a
      // co-signer pre-approving a module transaction means exactly that, and nothing else collides.
      const f = await loadFixture(fixture)
      const cosignerSafeAddress = await f.cosignerSafe.getAddress()
      await harden(f, cosignerSafeAddress)

      const tx = await moduleTransfer(f)
      const moduleTxHash = await moduleTransactionHash(f, tx)
      const nonce = randomNonce()
      const approvalHash = await f.coSignerPolicy.getModuleTransactionApprovalHash(moduleTxHash, 1n, nonce)
      await execTransaction({
        owners: [f.cosignerOwner],
        safe: f.cosignerSafe,
        to: await f.signMessageLib.getAddress(),
        data: f.signMessageLib.interface.encodeFunctionData('signMessage', [
          ethers.AbiCoder.defaultAbiCoder().encode(['bytes32'], [approvalHash])
        ]),
        operation: SafeOperation.DelegateCall
      })

      await f.coSignerPolicy
        .connect(f.other)
        .approveModuleTransactionWithSignature(
          tx.policyGuard,
          tx.safe,
          cosignerSafeAddress,
          moduleTxHash,
          1n,
          nonce,
          '0x'
        )
      await expect(executeFromModule(f, tx)).to.emit(f.coSignerPolicy, 'ModuleCoSignatureUsed')
    })

    it('Should reject an approval granting no use', async function () {
      const f = await loadFixture(fixture)
      const tx = await moduleTransfer(f)
      await expect(
        f.coSignerPolicy
          .connect(f.cosigner)
          .approveModuleTransaction(tx.policyGuard, tx.safe, await moduleTransactionHash(f, tx), 0n)
      ).to.be.revertedWithCustomError(f.coSignerPolicy, 'ZeroUses')
      await expect(approveBySignature(f, f.cosigner, tx, 0n)).to.be.revertedWithCustomError(
        f.coSignerPolicy,
        'ZeroUses'
      )
    })

    it('Should let only the approver revoke unspent uses', async function () {
      const f = await loadFixture(fixture)
      const cosignerAddress = await f.cosigner.getAddress()
      await harden(f, cosignerAddress)

      const tx = await moduleTransfer(f)
      const hash = await moduleTransactionHash(f, tx)
      await approveBySignature(f, f.cosigner, tx, 3n)

      // A stranger's revocation touches only its own (empty) namespace.
      await f.coSignerPolicy.connect(f.other).revokeModuleTransaction(tx.policyGuard, tx.safe, hash)
      expect(await remainingUses(f, cosignerAddress, tx)).to.equal(3n)

      await expect(f.coSignerPolicy.connect(f.cosigner).revokeModuleTransaction(tx.policyGuard, tx.safe, hash))
        .to.emit(f.coSignerPolicy, 'ModuleTransactionRevoked')
        .withArgs(tx.policyGuard, tx.safe, cosignerAddress, hash, 3n)
      expect(await remainingUses(f, cosignerAddress, tx)).to.equal(0n)
      await expectUnauthorized(f, executeFromModule(f, tx))
    })
  })

  describe('Batches', function () {
    it('Should spend one use per sub-transaction', async function () {
      const f = await loadFixture(fixture)
      const cosignerAddress = await f.cosigner.getAddress()
      const recipientAddress = await f.recipient.getAddress()
      const multiSendAddress = await f.multiSend.getAddress()
      await harden(f, cosignerAddress)

      // The batch repeats one transfer. On the owner path a single co-signature could never cover
      // both occurrences (same hash); here each occurrence spends a use of the same module
      // transaction, so the approval has to carry two.
      const transfer = {
        to: recipientAddress,
        value: ethers.parseEther('1'),
        data: '0x',
        operation: SafeOperation.Call
      }
      const batch = f.multiSend.interface.encodeFunctionData('multiSend', [encodeMultiSend([transfer, transfer])])
      const batchTx = await moduleTransfer(f, {
        to: multiSendAddress,
        value: 0n,
        data: batch,
        operation: SafeOperation.DelegateCall
      })
      const oneEth = await moduleTransfer(f)

      // With a single use the second sub-check denies. The engine wraps a sub-policy's revert in
      // the batch policy's own `PolicyReverted`.
      await approveBySignature(f, f.cosigner, oneEth, 1n)
      await expect(executeFromModule(f, batchTx))
        .to.be.revertedWithCustomError(f.safePolicyGuard, 'PolicyReverted')
        .withArgs(
          await f.multiSendPolicy.getAddress(),
          f.safePolicyGuard.interface.encodeErrorResult('PolicyReverted', [
            await f.coSignerPolicy.getAddress(),
            f.coSignerPolicy.interface.encodeErrorResult('Unauthorized', [])
          ])
        )
      // A failed batch spends nothing.
      expect(await remainingUses(f, cosignerAddress, oneEth)).to.equal(1n)

      await approveBySignature(f, f.cosigner, oneEth, 1n)
      const before = await ethers.provider.getBalance(recipientAddress)
      await executeFromModule(f, batchTx).then((tx) => tx.wait())
      expect((await ethers.provider.getBalance(recipientAddress)) - before).to.equal(ethers.parseEther('2'))
      expect(await remainingUses(f, cosignerAddress, oneEth)).to.equal(0n)
    })
  })
})
