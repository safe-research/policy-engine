import { loadFixture } from '@nomicfoundation/hardhat-network-helpers'
import { expect } from 'chai'
import { ZeroAddress } from 'ethers'
import { ethers } from 'hardhat'

import {
  createConfiguration,
  createSafe,
  execTransaction,
  safeSignTypedData,
  randomAddress,
  randomSelector,
  SafeOperation,
  TransactionParametersWithNonce,
  buildSafeTransaction,
  buildContractCall,
  buildMultiSendSafeTx,
  getConfigurationRoot
} from '../src/utils'
import {
  deploySafeContracts,
  deploySafePolicyGuard,
  deployMultiSendPolicy,
  deployTestERC20Token,
  deployCoSignerPolicy,
  deployAllowPolicy
} from './deploy'

describe('MultiSendPolicy', function () {
  async function fixture() {
    const [, owner, cosigner, recipient, other] = await ethers.getSigners()

    // Deploy the SafePolicyGuard contract
    const { safePolicyGuard } = await deploySafePolicyGuard()

    // Deploy the Safe contracts
    const { safeProxyFactory, safe: safeSingleton, multiSend } = await deploySafeContracts()
    const safe = await createSafe({
      owner,
      guard: ZeroAddress, // No guard at this point
      saltNonce: BigInt(0x7),
      safeProxyFactory,
      singleton: safeSingleton
    })

    // Deploy MultiSendPolicy contract
    const { multiSendPolicy } = await deployMultiSendPolicy()

    // Deploy CoSignerPolicy contract
    const { coSignerPolicy } = await deployCoSignerPolicy()

    // Deploy AllowPolicy contract
    const { allowPolicy } = await deployAllowPolicy()

    // Deploy Test ERC20 Token contract
    const { token } = await deployTestERC20Token()

    // Mint some tokens to the Safe
    await token.mint(await safe.getAddress(), ethers.parseEther('1000'))

    // Fund the Safe with some ETH
    await owner.sendTransaction({
      to: await safe.getAddress(),
      value: ethers.parseEther('10')
    })

    return {
      owner,
      cosigner,
      recipient,
      other,
      safe,
      safePolicyGuard,
      multiSendPolicy,
      multiSend,
      coSignerPolicy,
      allowPolicy,
      token
    }
  }

  describe('Policy Configuration', function () {
    it('Should only be able to configure with MultiSend selector', async function () {
      const { owner, safePolicyGuard, safe, multiSendPolicy, multiSend } = await loadFixture(fixture)

      // Get MultiSend selector
      const multiSendSelector = multiSend.interface.getFunction('multiSend')?.selector

      // Trying to configure with non-MultiSend selector
      const configurations = [
        createConfiguration({
          selector: randomSelector(), // Non-MultiSend selector
          operation: SafeOperation.DelegateCall,
          policy: await multiSendPolicy.getAddress()
        })
      ]

      // Configure the policy - should fail
      await expect(
        execTransaction({
          owners: [owner],
          safe,
          to: await safePolicyGuard.getAddress(),
          data: safePolicyGuard.interface.encodeFunctionData('configureImmediately', [configurations])
        })
      ).to.be.revertedWithCustomError(safePolicyGuard, 'PolicyConfigurationFailed')

      // Configure with correct MultiSend selector
      const validConfigurations = [
        createConfiguration({
          selector: multiSendSelector,
          operation: SafeOperation.DelegateCall,
          policy: await multiSendPolicy.getAddress()
        })
      ]

      // Configure the policy - should succeed
      await expect(
        execTransaction({
          owners: [owner],
          safe,
          to: await safePolicyGuard.getAddress(),
          data: safePolicyGuard.interface.encodeFunctionData('configureImmediately', [validConfigurations])
        })
      ).to.not.be.reverted
    })

    it('Should only allow DELEGATECALL operations', async function () {
      const { owner, safePolicyGuard, safe, multiSendPolicy, multiSend } = await loadFixture(fixture)

      // Get MultiSend selector
      const multiSendSelector = multiSend.interface.getFunction('multiSend')?.selector

      // Trying to configure with CALL operation
      const configurations = [
        createConfiguration({
          selector: multiSendSelector,
          operation: SafeOperation.Call, // Default is CALL, explicitly setting it to CALL for clarity
          policy: await multiSendPolicy.getAddress()
        })
      ]

      // Configure the policy - should fail
      await expect(
        execTransaction({
          owners: [owner],
          safe,
          to: await safePolicyGuard.getAddress(),
          data: safePolicyGuard.interface.encodeFunctionData('configureImmediately', [configurations])
        })
      ).to.be.revertedWithCustomError(safePolicyGuard, 'PolicyConfigurationFailed')

      // Configure with correct DELEGATECALL operation
      const validConfigurations = [
        createConfiguration({
          selector: multiSendSelector,
          operation: SafeOperation.DelegateCall,
          policy: await multiSendPolicy.getAddress()
        })
      ]

      // Configure the policy - should succeed
      await expect(
        execTransaction({
          owners: [owner],
          safe,
          to: await safePolicyGuard.getAddress(),
          data: safePolicyGuard.interface.encodeFunctionData('configureImmediately', [validConfigurations])
        })
      ).to.not.be.reverted
    })
  })

  describe('Transaction Validation', function () {
    it('Should validate each transaction within MultiSend', async function () {
      const { owner, safePolicyGuard, safe, multiSendPolicy, multiSend, allowPolicy, token, recipient } =
        await loadFixture(fixture)

      const amount = ethers.parseEther('1')
      const tokenAmount = ethers.parseEther('100')

      // Fund the Safe with ETH
      await owner.sendTransaction({
        to: await safe.getAddress(),
        value: amount * 2n
      })

      // Create transactions array
      const txs = [
        buildSafeTransaction({ to: recipient.address, value: amount, data: '0x', nonce: 0 }),
        await buildContractCall(token, 'transfer', [recipient.address, tokenAmount], 0)
      ]

      // Get function selectors
      const transferSelector = token.interface.getFunction('transfer')?.selector
      const multiSendSelector = multiSend.interface.getFunction('multiSend')?.selector

      // Configure the policies for individual transactions first
      const configurations = [
        // Configure policy for native transfer with empty data
        createConfiguration({
          target: recipient.address,
          policy: await allowPolicy.getAddress()
        }),
        // Configure policy for ERC20 transfer
        createConfiguration({
          target: await token.getAddress(),
          selector: transferSelector,
          policy: await allowPolicy.getAddress()
        }),
        // Configure policy for MultiSend
        createConfiguration({
          target: await multiSend.getAddress(),
          selector: multiSendSelector,
          operation: SafeOperation.DelegateCall,
          policy: await multiSendPolicy.getAddress()
        })
      ]

      // Configure the policies for all transactions
      await execTransaction({
        owners: [owner],
        safe,
        to: await safePolicyGuard.getAddress(),
        data: safePolicyGuard.interface.encodeFunctionData('configureImmediately', [configurations])
      })

      // Enable the guard on safe
      await execTransaction({
        owners: [owner],
        safe,
        to: await safe.getAddress(),
        data: safe.interface.encodeFunctionData('setGuard', [await safePolicyGuard.getAddress()])
      })

      // Build MultiSend transaction
      const safeTx = await buildMultiSendSafeTx(multiSend, txs, await safe.nonce())

      // Get previous balances
      const initialRecipientBalance = await ethers.provider.getBalance(recipient.address)
      const initialTokenBalance = await token.balanceOf(recipient.address)

      // Execute the MultiSend transaction through the Safe
      await execTransaction({
        owners: [owner],
        safe,
        to: await multiSend.getAddress(),
        data: safeTx.data,
        operation: SafeOperation.DelegateCall
        // ...safeTx
      })

      // Get the new balances
      const newRecipientBalance = await ethers.provider.getBalance(recipient.address)
      const newTokenBalance = await token.balanceOf(recipient.address)

      // Verify the transactions were executed
      expect(newRecipientBalance).to.equal(initialRecipientBalance + amount)
      expect(newTokenBalance).to.equal(initialTokenBalance + tokenAmount)
    })

    it('Should revert if any transaction in MultiSend is not configured', async function () {
      const { owner, safePolicyGuard, safe, multiSendPolicy, multiSend, allowPolicy, recipient } =
        await loadFixture(fixture)

      const amount = ethers.parseEther('1')

      // Fund the Safe with ETH
      await owner.sendTransaction({
        to: await safe.getAddress(),
        value: amount * 2n
      })

      // Get function selectors
      const multiSendSelector = multiSend.interface.getFunction('multiSend')?.selector

      // Configure the policies for individual transactions first
      const configurations = [
        // Configure policy for native transfer with empty data
        createConfiguration({
          target: recipient.address,
          policy: await allowPolicy.getAddress()
        }),
        // Configure policy for MultiSend
        createConfiguration({
          target: await multiSend.getAddress(),
          selector: multiSendSelector,
          operation: SafeOperation.DelegateCall,
          policy: await multiSendPolicy.getAddress()
        })
      ]

      // Configure the policies for all transactions
      await execTransaction({
        owners: [owner],
        safe,
        to: await safePolicyGuard.getAddress(),
        data: safePolicyGuard.interface.encodeFunctionData('configureImmediately', [configurations])
      })

      // Enable the guard on safe
      await execTransaction({
        owners: [owner],
        safe,
        to: await safe.getAddress(),
        data: safe.interface.encodeFunctionData('setGuard', [await safePolicyGuard.getAddress()])
      })

      // Build MultiSend transaction with an unconfigured transaction
      const txs = [
        buildSafeTransaction({ to: recipient.address, value: amount, data: '0x', nonce: 0 }),
        buildSafeTransaction({ to: randomAddress() as string, value: amount, data: '0x', nonce: 1 })
      ]
      const safeTx = await buildMultiSendSafeTx(multiSend, txs, await safe.nonce())

      // Attempt to execute the MultiSend transaction through the Safe
      await expect(
        execTransaction({
          owners: [owner],
          safe,
          to: await multiSend.getAddress(),
          data: safeTx.data,
          operation: SafeOperation.DelegateCall
        })
      )
        .to.be.revertedWithCustomError(safePolicyGuard, 'AccessDenied')
        .withArgs(await multiSendPolicy.getAddress())
    })

    it('Should pass with multiple guard transactions to configure without any configured policy', async function () {
      const { owner, safePolicyGuard, safe, multiSendPolicy, multiSend, allowPolicy, coSignerPolicy } =
        await loadFixture(fixture)

      // Get function selectors
      const multiSendSelector = multiSend.interface.getFunction('multiSend')?.selector

      const multiSendConfiguration = [
        // Configure policy for MultiSend
        createConfiguration({
          target: await multiSend.getAddress(),
          selector: multiSendSelector,
          operation: SafeOperation.DelegateCall,
          policy: await multiSendPolicy.getAddress()
        })
      ]

      // Configure the multiSend policy
      await execTransaction({
        owners: [owner],
        safe,
        to: await safePolicyGuard.getAddress(),
        data: safePolicyGuard.interface.encodeFunctionData('configureImmediately', [multiSendConfiguration])
      })

      // Enable the guard on safe
      await execTransaction({
        owners: [owner],
        safe,
        to: await safe.getAddress(),
        data: safe.interface.encodeFunctionData('setGuard', [await safePolicyGuard.getAddress()])
      })

      const configurationCall = [
        createConfiguration({
          operation: SafeOperation.Call,
          policy: await allowPolicy.getAddress()
        })
      ]

      const configurationDelegateCall = [
        createConfiguration({
          operation: SafeOperation.DelegateCall,
          policy: await coSignerPolicy.getAddress()
        })
      ]

      // Create transactions array
      const txs = [
        await buildContractCall(safePolicyGuard, 'requestConfiguration', [getConfigurationRoot(configurationCall)], 0),
        await buildContractCall(
          safePolicyGuard,
          'requestConfiguration',
          [getConfigurationRoot(configurationDelegateCall)],
          0
        )
      ]

      // Build MultiSend transaction
      const safeTx = await buildMultiSendSafeTx(multiSend, txs, await safe.nonce())

      // Both roots should be unconfigured at this point
      expect(
        await safePolicyGuard.rootConfigured(await safe.getAddress(), getConfigurationRoot(configurationCall))
      ).to.be.eq(0n)
      expect(
        await safePolicyGuard.rootConfigured(await safe.getAddress(), getConfigurationRoot(configurationDelegateCall))
      ).to.be.eq(0n)

      // Execute the MultiSend transaction through the Safe
      await execTransaction({
        owners: [owner],
        safe,
        to: await multiSend.getAddress(),
        data: safeTx.data,
        operation: SafeOperation.DelegateCall
      })

      // Both roots should be configured at this point
      expect(
        await safePolicyGuard.rootConfigured(await safe.getAddress(), getConfigurationRoot(configurationCall))
      ).to.be.gt(0n)
      expect(
        await safePolicyGuard.rootConfigured(await safe.getAddress(), getConfigurationRoot(configurationDelegateCall))
      ).to.be.gt(0n)
    })
  })

  describe('Context Decoding', function () {
    it('Should correctly decode context in MultiSend with co-signer signatures', async function () {
      const {
        owner,
        cosigner,
        recipient,
        other,
        safePolicyGuard,
        safe,
        multiSendPolicy,
        coSignerPolicy,
        multiSend,
        token
      } = await loadFixture(fixture)

      const ethAmount = ethers.parseEther('1')
      const tokenAmount = ethers.parseEther('100')

      // Get function selectors
      const transferSelector = token.interface.getFunction('transfer')?.selector
      const multiSendSelector = multiSend.interface.getFunction('multiSend')?.selector

      // Configure the policies:
      // 1. For ETH transfers to recipient, require cosigner signature
      // 2. For ETH transfers to other, require other's signature
      // 3. For token transfers, require cosigner signature
      // 4. For MultiSend operation, use MultiSendPolicy
      const configurations = [
        // Configure policy for ETH transfer to recipient with cosigner
        createConfiguration({
          target: await recipient.getAddress(),
          policy: await coSignerPolicy.getAddress(),
          data: ethers.AbiCoder.defaultAbiCoder().encode(['address'], [await cosigner.getAddress()])
        }),
        // Configure policy for ETH transfer to other with other as cosigner
        createConfiguration({
          target: await other.getAddress(),
          policy: await coSignerPolicy.getAddress(),
          data: ethers.AbiCoder.defaultAbiCoder().encode(['address'], [await other.getAddress()])
        }),
        // Configure policy for ERC20 transfer with cosigner
        createConfiguration({
          target: await token.getAddress(),
          selector: transferSelector,
          policy: await coSignerPolicy.getAddress(),
          data: ethers.AbiCoder.defaultAbiCoder().encode(['address'], [await cosigner.getAddress()])
        }),
        // Configure policy for MultiSend
        createConfiguration({
          target: await multiSend.getAddress(),
          selector: multiSendSelector,
          operation: SafeOperation.DelegateCall,
          policy: await multiSendPolicy.getAddress()
        })
      ]

      // Configure the policies for all transactions
      await execTransaction({
        owners: [owner],
        safe,
        to: await safePolicyGuard.getAddress(),
        data: safePolicyGuard.interface.encodeFunctionData('configureImmediately', [configurations])
      })

      // Enable the guard on safe
      await execTransaction({
        owners: [owner],
        safe,
        to: await safe.getAddress(),
        data: safe.interface.encodeFunctionData('setGuard', [await safePolicyGuard.getAddress()])
      })

      // Get initial balances
      const initialRecipientBalance = await ethers.provider.getBalance(await recipient.getAddress())
      const initialOtherBalance = await ethers.provider.getBalance(await other.getAddress())
      const initialRecipientTokenBalance = await token.balanceOf(recipient.address)
      const initialSafeBalance = await ethers.provider.getBalance(await safe.getAddress())

      const nonce = await safe.nonce()

      // Create transactions array
      const txs = [
        // ETH transfer to recipient
        buildSafeTransaction({ to: recipient.address, value: ethAmount, data: '0x', nonce }),
        // ETH transfer to other
        buildSafeTransaction({ to: other.address, value: ethAmount, data: '0x', nonce }),
        // Token transfer to recipient
        await buildContractCall(token, 'transfer', [recipient.address, tokenAmount], nonce, false)
      ]

      // Build MultiSend transaction
      const multiSendTx = await buildMultiSendSafeTx(multiSend, txs, nonce)

      // Sign individual transactions with appropriate cosigners
      // Transaction 1: ETH to recipient, signed by cosigner
      const tx1Data: TransactionParametersWithNonce = txs[0]
      const recipientSignature = await safeSignTypedData(cosigner, await safe.getAddress(), tx1Data)

      // Transaction 2: ETH to other, signed by other
      const tx2Data: TransactionParametersWithNonce = txs[1]
      const otherSignature = await safeSignTypedData(other, await safe.getAddress(), tx2Data)

      // Transaction 3: Token transfer, signed by cosigner
      const tx3Data: TransactionParametersWithNonce = txs[2]
      const tokenSignature = await safeSignTypedData(cosigner, await safe.getAddress(), tx3Data)

      // Combine signatures for all transactions in the multiSend
      // We need to encode the signatures in a way that the MultiSendPolicy can decode them
      // Each context (signature) should be prefixed with its length as a uint256
      const combinedContext = ethers.solidityPacked(
        ['uint256', 'bytes', 'uint256', 'bytes', 'uint256', 'bytes'],
        [
          ethers.dataLength(recipientSignature.data),
          recipientSignature.data,
          ethers.dataLength(otherSignature.data),
          otherSignature.data,
          ethers.dataLength(tokenSignature.data),
          tokenSignature.data
        ]
      )

      // Execute the MultiSend transaction through the Safe with the combined signatures
      await execTransaction({
        owners: [owner],
        safe,
        to: await multiSend.getAddress(),
        data: multiSendTx.data,
        operation: SafeOperation.DelegateCall,
        additionalData: combinedContext
      })

      // Get new balances
      const finalRecipientBalance = await ethers.provider.getBalance(await recipient.getAddress())
      const finalOtherBalance = await ethers.provider.getBalance(await other.getAddress())
      const finalRecipientTokenBalance = await token.balanceOf(recipient.address)
      const finalSafeBalance = await ethers.provider.getBalance(await safe.getAddress())

      // Verify the transactions were successful
      expect(finalRecipientBalance - initialRecipientBalance).to.equal(ethAmount)
      expect(finalOtherBalance - initialOtherBalance).to.equal(ethAmount)
      expect(finalRecipientTokenBalance - initialRecipientTokenBalance).to.equal(tokenAmount)
      expect(initialSafeBalance - finalSafeBalance).to.equal(ethAmount * 2n)
    })
  })
})
