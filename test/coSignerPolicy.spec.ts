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
  encodeCoSignerConfig,
  execTransaction,
  safeSignTypedData,
  SafeOperation,
  TransactionParametersWithNonce
} from '../src/utils'
import { deploySafeContracts, deploySafePolicyGuard, deployCoSignerPolicy, deployMultiSendPolicy } from './deploy'

describe('CoSignerPolicy', function () {
  async function fixture() {
    const [deployer, owner, cosigner, recipient, other] = await ethers.getSigners()

    // Deploy the SafePolicyGuard contract
    const { safePolicyGuard } = await deploySafePolicyGuard()

    // Deploy the Safe contracts
    const { safeProxyFactory, safe: safeSingleton, multiSend } = await deploySafeContracts()
    const safe = await createSafe({
      owners: [owner],
      guard: ZeroAddress, // No guard at this point
      saltNonce: BigInt(0x6),
      safeProxyFactory,
      singleton: safeSingleton
    })

    // Deploy CoSignerPolicy contract
    const { coSignerPolicy } = await deployCoSignerPolicy()

    // Deploy MultiSendPolicy contract
    const { multiSendPolicy } = await deployMultiSendPolicy()

    // Fund the Safe with some ETH
    await owner.sendTransaction({
      to: await safe.getAddress(),
      value: ethers.parseEther('10')
    })

    return {
      deployer,
      owner,
      cosigner,
      recipient,
      other,
      safe,
      safePolicyGuard,
      coSignerPolicy,
      multiSend,
      multiSendPolicy
    }
  }

  describe('Integration with SafePolicyGuard', function () {
    it('Should allow transaction when co-signed by configured co-signer', async function () {
      const { owner, cosigner, recipient, safePolicyGuard, safe, coSignerPolicy } = await loadFixture(fixture)

      const amount = ethers.parseEther('1')

      // Configure the co-signer policy
      const configurations = [
        createConfiguration({
          target: await recipient.getAddress(),
          policy: await coSignerPolicy.getAddress(),
          data: encodeCoSignerConfig(await cosigner.getAddress())
        })
      ]

      // Configure the policy, then enable the guard
      await enableGuard({ owners: [owner], safe, safePolicyGuard, configurations })

      // Get initial balances
      const initialRecipientBalance = await ethers.provider.getBalance(await recipient.getAddress())
      const initialSafeBalance = await ethers.provider.getBalance(await safe.getAddress())

      // Create the transaction data
      const txData: TransactionParametersWithNonce = {
        to: await recipient.getAddress(),
        value: amount,
        data: '0x',
        operation: 0, // CALL
        safeTxGas: 0,
        baseGas: 0,
        gasPrice: 0,
        gasToken: ZeroAddress,
        refundReceiver: ZeroAddress,
        nonce: await safe.nonce()
      }

      // Sign the transaction hash with the co-signer
      const cosignerSignature = await safeSignTypedData(cosigner, await safe.getAddress(), txData)

      // Execute the transaction with co-signer signature
      await execTransaction({
        owners: [owner],
        safe,
        to: await recipient.getAddress(),
        value: amount,
        additionalData: cosignerSignature.data
      })

      // Verify the transfer was successful
      const finalRecipientBalance = await ethers.provider.getBalance(await recipient.getAddress())
      const finalSafeBalance = await ethers.provider.getBalance(await safe.getAddress())

      expect(finalRecipientBalance - initialRecipientBalance).to.equal(amount)
      expect(initialSafeBalance - finalSafeBalance).to.equal(amount)
    })

    it('Should not allow transaction without co-signer signature', async function () {
      const { owner, cosigner, recipient, safePolicyGuard, safe, coSignerPolicy } = await loadFixture(fixture)

      const amount = ethers.parseEther('1')

      // Configure the co-signer policy
      const configurations = [
        createConfiguration({
          target: await recipient.getAddress(),
          selector: '0x00000000',
          policy: await coSignerPolicy.getAddress(),
          data: encodeCoSignerConfig(await cosigner.getAddress())
        })
      ]

      // Configure the policy, then enable the guard
      await enableGuard({ owners: [owner], safe, safePolicyGuard, configurations })

      // Try to execute the transaction without co-signer signature
      await expect(
        execTransaction({
          owners: [owner],
          safe,
          to: await recipient.getAddress(),
          value: amount,
          data: '0x'
        })
      )
        .to.be.revertedWithCustomError(safePolicyGuard, 'PolicyReverted')
        .withArgs(await coSignerPolicy.getAddress(), coSignerPolicy.interface.encodeErrorResult('Unauthorized', []))
    })

    it('Should not allow transaction with wrong co-signer signature', async function () {
      const { owner, cosigner, recipient, other, safePolicyGuard, safe, coSignerPolicy } = await loadFixture(fixture)

      const amount = ethers.parseEther('1')

      // Configure the co-signer policy
      const configurations = [
        createConfiguration({
          target: await recipient.getAddress(),
          selector: '0x00000000',
          policy: await coSignerPolicy.getAddress(),
          data: encodeCoSignerConfig(await cosigner.getAddress())
        })
      ]

      // Configure the policy, then enable the guard
      await enableGuard({ owners: [owner], safe, safePolicyGuard, configurations })

      // Create the transaction data
      const txData: TransactionParametersWithNonce = {
        to: await recipient.getAddress(),
        value: amount,
        data: '0x',
        operation: 0, // CALL
        safeTxGas: 0,
        baseGas: 0,
        gasPrice: 0,
        gasToken: ZeroAddress,
        refundReceiver: ZeroAddress,
        nonce: await safe.nonce()
      }

      // Sign the transaction hash with the wrong co-signer
      const cosignerSignature = await safeSignTypedData(other, await safe.getAddress(), txData)

      // Try to execute the transaction with wrong co-signer signature
      await expect(
        execTransaction({
          owners: [owner],
          safe,
          to: await recipient.getAddress(),
          value: amount,
          additionalData: cosignerSignature.data
        })
      )
        .to.be.revertedWithCustomError(safePolicyGuard, 'PolicyReverted')
        .withArgs(await coSignerPolicy.getAddress(), coSignerPolicy.interface.encodeErrorResult('Unauthorized', []))
    })

    it('Should allow transaction with different co-signers for different targets', async function () {
      const { owner, cosigner, recipient, other, safePolicyGuard, safe, coSignerPolicy } = await loadFixture(fixture)

      const amount = ethers.parseEther('1')

      // Configure the co-signer policy with different co-signers for different targets
      const configurations = [
        createConfiguration({
          target: await recipient.getAddress(),
          policy: await coSignerPolicy.getAddress(),
          data: encodeCoSignerConfig(await cosigner.getAddress())
        }),
        createConfiguration({
          target: await other.getAddress(),
          policy: await coSignerPolicy.getAddress(),
          data: encodeCoSignerConfig(await other.getAddress())
        })
      ]

      // Configure the policy, then enable the guard
      await enableGuard({ owners: [owner], safe, safePolicyGuard, configurations })

      // Get initial balances
      const initialRecipientBalance = await ethers.provider.getBalance(await recipient.getAddress())
      const initialOtherBalance = await ethers.provider.getBalance(await other.getAddress())
      const initialSafeBalance = await ethers.provider.getBalance(await safe.getAddress())

      // Create and sign transaction for recipient
      const recipientTxData = {
        to: await recipient.getAddress(),
        value: amount,
        data: '0x',
        operation: 0,
        safeTxGas: 0,
        baseGas: 0,
        gasPrice: 0,
        gasToken: ZeroAddress,
        refundReceiver: ZeroAddress,
        nonce: await safe.nonce()
      }

      const recipientSignature = await safeSignTypedData(cosigner, await safe.getAddress(), recipientTxData)

      // Execute transaction to recipient
      await execTransaction({
        owners: [owner],
        safe,
        to: await recipient.getAddress(),
        value: amount,
        additionalData: recipientSignature.data
      })

      // Create and sign transaction for other
      const otherTxData = {
        to: await other.getAddress(),
        value: amount,
        data: '0x',
        operation: 0,
        safeTxGas: 0,
        baseGas: 0,
        gasPrice: 0,
        gasToken: ZeroAddress,
        refundReceiver: ZeroAddress,
        nonce: await safe.nonce()
      }

      const otherSignature = await safeSignTypedData(other, await safe.getAddress(), otherTxData)

      // Execute transaction to other
      await execTransaction({
        owners: [owner],
        safe,
        to: await other.getAddress(),
        value: amount,
        additionalData: otherSignature.data
      })

      // Get final balances
      const finalRecipientBalance = await ethers.provider.getBalance(await recipient.getAddress())
      const finalOtherBalance = await ethers.provider.getBalance(await other.getAddress())
      const finalSafeBalance = await ethers.provider.getBalance(await safe.getAddress())

      // Verify the transfers were successful
      expect(finalRecipientBalance - initialRecipientBalance).to.equal(amount)
      expect(finalOtherBalance - initialOtherBalance).to.equal(amount)
      expect(initialSafeBalance - finalSafeBalance).to.equal(amount * 2n)
    })

    it('Should reject a transaction when the configured co-signer is the zero address', async function () {
      // `configure` takes whatever address it is handed, so a Safe can configure the policy with no
      // co-signer at all. That has to fail closed at check time rather than accept any signature.
      const { owner, recipient, safePolicyGuard, safe, coSignerPolicy } = await loadFixture(fixture)

      await enableGuard({
        owners: [owner],
        safe,
        safePolicyGuard,
        configurations: [
          createConfiguration({
            target: await recipient.getAddress(),
            policy: await coSignerPolicy.getAddress(),
            data: encodeCoSignerConfig(ZeroAddress)
          })
        ]
      })

      await expect(
        execTransaction({ owners: [owner], safe, to: await recipient.getAddress(), value: ethers.parseEther('1') })
      )
        .to.be.revertedWithCustomError(safePolicyGuard, 'PolicyReverted')
        .withArgs(
          await coSignerPolicy.getAddress(),
          coSignerPolicy.interface.encodeErrorResult('NoCosignerConfigured', [])
        )
    })
  })

  describe('getCoSigner', function () {
    it('Should report the co-signer configured for an access selector', async function () {
      // State is namespaced by `msg.sender`, and `getCoSigner` reads that same namespace, so
      // configuring directly is what makes the getter observable.
      const { deployer, cosigner, recipient, safe, coSignerPolicy } = await loadFixture(fixture)
      const accessSelector = await (await ethers.getContractFactory('TestAccessSelector')).deploy()
      const access = await accessSelector.create(await recipient.getAddress(), '0x00000000', SafeOperation.Call)

      expect(await coSignerPolicy.connect(deployer).getCoSigner(safe, access)).to.equal(ZeroAddress)

      await coSignerPolicy.connect(deployer).configure(safe, access, encodeCoSignerConfig(await cosigner.getAddress()))

      expect(await coSignerPolicy.connect(deployer).getCoSigner(safe, access)).to.equal(await cosigner.getAddress())
    })
  })
  describe('Co-Signature Replay', function () {
    it('Should not let a batch spend the same co-signature more than once', async function () {
      const { owner, cosigner, recipient, safePolicyGuard, safe, coSignerPolicy, multiSend, multiSendPolicy } =
        await loadFixture(fixture)

      const amount = ethers.parseEther('1')
      const multiSendSelector = multiSend.interface.getFunction('multiSend')?.selector

      const configurations = [
        createConfiguration({
          target: await recipient.getAddress(),
          policy: await coSignerPolicy.getAddress(),
          data: encodeCoSignerConfig(await cosigner.getAddress())
        }),
        createConfiguration({
          target: await multiSend.getAddress(),
          selector: multiSendSelector,
          operation: SafeOperation.DelegateCall,
          policy: await multiSendPolicy.getAddress()
        })
      ]
      await enableGuard({ owners: [owner], safe, safePolicyGuard, configurations })

      const nonce = await safe.nonce()

      // The co-signer authorises exactly one transfer of `amount`.
      const transfer: TransactionParametersWithNonce = buildSafeTransaction({
        to: await recipient.getAddress(),
        value: amount,
        data: '0x',
        nonce
      })
      const coSignature = await safeSignTypedData(cosigner, await safe.getAddress(), transfer)

      // The batch presents that same transfer three times, replaying the one co-signature. Every
      // occurrence derives the same hash, so each check would see a valid signature.
      const txs = [transfer, transfer, transfer]
      const multiSendTx = await buildMultiSendSafeTx(multiSend, txs, nonce)
      const combinedContext = ethers.solidityPacked(
        ['uint256', 'bytes', 'uint256', 'bytes', 'uint256', 'bytes'],
        [
          ethers.dataLength(coSignature.data),
          coSignature.data,
          ethers.dataLength(coSignature.data),
          coSignature.data,
          ethers.dataLength(coSignature.data),
          coSignature.data
        ]
      )

      const initialSafeBalance = await ethers.provider.getBalance(await safe.getAddress())

      await expect(
        execTransaction({
          owners: [owner],
          safe,
          to: await multiSend.getAddress(),
          data: multiSendTx.data,
          operation: SafeOperation.DelegateCall,
          additionalData: combinedContext
        })
      ).to.be.revertedWithCustomError(safePolicyGuard, 'PolicyReverted')

      expect(await ethers.provider.getBalance(await safe.getAddress())).to.equal(initialSafeBalance)
    })

    it('Should record a co-signature as spent once used', async function () {
      const { owner, cosigner, recipient, safePolicyGuard, safe, coSignerPolicy } = await loadFixture(fixture)

      const amount = ethers.parseEther('1')
      const configurations = [
        createConfiguration({
          target: await recipient.getAddress(),
          policy: await coSignerPolicy.getAddress(),
          data: encodeCoSignerConfig(await cosigner.getAddress())
        })
      ]
      await enableGuard({ owners: [owner], safe, safePolicyGuard, configurations })

      const nonce = await safe.nonce()
      const transfer: TransactionParametersWithNonce = buildSafeTransaction({
        to: await recipient.getAddress(),
        value: amount,
        data: '0x',
        nonce
      })
      const safeTxHash = await safe.getTransactionHash(
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
      const coSignature = await safeSignTypedData(cosigner, await safe.getAddress(), transfer)

      expect(await coSignerPolicy.isCoSignatureSpent(safePolicyGuard, safe, safeTxHash)).to.equal(false)

      await execTransaction({
        owners: [owner],
        safe,
        to: await recipient.getAddress(),
        value: amount,
        additionalData: coSignature.data
      })

      expect(await coSignerPolicy.isCoSignatureSpent(safePolicyGuard, safe, safeTxHash)).to.equal(true)
    })
  })
})
