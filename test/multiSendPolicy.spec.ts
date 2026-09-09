import { loadFixture } from '@nomicfoundation/hardhat-network-helpers'
import { expect } from 'chai'
import { BaseContract, ZeroAddress } from 'ethers'
import { ethers } from 'hardhat'

import {
  createConfiguration,
  createSafe,
  enableGuard,
  encodeCoSignerConfig,
  encodeMultiSend,
  execTransaction,
  MetaTransaction,
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
  deployAllowPolicy,
  deployDenyPolicy,
  deployMockPolicy
} from './deploy'

describe('MultiSendPolicy', function () {
  async function fixture() {
    const [, owner, cosigner, recipient, other] = await ethers.getSigners()

    // Deploy the SafePolicyGuard contract
    const { safePolicyGuard } = await deploySafePolicyGuard()

    // Deploy the Safe contracts
    const { safeProxyFactory, safe: safeSingleton, multiSend } = await deploySafeContracts()
    const safe = await createSafe({
      owners: [owner],
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

    // Deploy DenyPolicy contract
    const { denyPolicy } = await deployDenyPolicy()

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
      denyPolicy,
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

    it('Should reject calldata that is not a MultiSend batch', async function () {
      // `configure` pins the selector, so the engine can only route `multiSend` calldata here. This
      // is the policy defending its own decode when called directly, which anyone may do.
      const { safe, multiSendPolicy } = await loadFixture(fixture)

      await expect(
        multiSendPolicy.checkTransaction(
          safe,
          randomAddress(),
          0n,
          randomSelector(),
          SafeOperation.DelegateCall,
          ZeroAddress,
          '0x',
          0n
        )
      ).to.be.revertedWithCustomError(multiSendPolicy, 'InvalidMultiSend')
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
      await enableGuard({ owners: [owner], safe, safePolicyGuard, configurations: configurations })

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
      await enableGuard({ owners: [owner], safe, safePolicyGuard, configurations: configurations })

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
        // Attributed to MultiSendPolicy -- engine-supplied, so trustworthy -- with the
        // sub-transaction's own denial nested inside as opaque data.
        .to.be.revertedWithCustomError(safePolicyGuard, 'PolicyReverted')
        .withArgs(
          await multiSendPolicy.getAddress(),
          safePolicyGuard.interface.encodeErrorResult('AccessDenied', [ZeroAddress])
        )
    })

    it('Should nest a sub-transaction policy revert reason inside the batch attribution', async function () {
      const { owner, safePolicyGuard, safe, multiSendPolicy, multiSend, allowPolicy, recipient } =
        await loadFixture(fixture)

      const { mockPolicy } = await deployMockPolicy()
      const subTarget = randomAddress()
      const amount = ethers.parseEther('1')

      await enableGuard({
        owners: [owner],
        safe,
        safePolicyGuard,
        configurations: [
          createConfiguration({ target: recipient.address, policy: await allowPolicy.getAddress() }),
          createConfiguration({ target: subTarget, policy: await mockPolicy.getAddress() }),
          createConfiguration({
            target: await multiSend.getAddress(),
            selector: multiSend.interface.getFunction('multiSend')?.selector,
            operation: SafeOperation.DelegateCall,
            policy: await multiSendPolicy.getAddress()
          })
        ]
      })

      await mockPolicy.setRevertCheckWithReason(true)

      const txs = [
        buildSafeTransaction({ to: recipient.address, value: amount, data: '0x', nonce: 0 }),
        buildSafeTransaction({ to: subTarget as string, value: 0, data: '0x', nonce: 1 })
      ]
      const safeTx = await buildMultiSendSafeTx(multiSend, txs, await safe.nonce())

      await expect(
        execTransaction({
          owners: [owner],
          safe,
          to: await multiSend.getAddress(),
          data: safeTx.data,
          operation: SafeOperation.DelegateCall
        })
      )
        // Each layer's `policy` is engine-supplied, so the attribution cannot be forged by a
        // policy; the inner policy's own error is carried verbatim as the nested payload.
        .to.be.revertedWithCustomError(safePolicyGuard, 'PolicyReverted')
        .withArgs(
          await multiSendPolicy.getAddress(),
          safePolicyGuard.interface.encodeErrorResult('PolicyReverted', [
            await mockPolicy.getAddress(),
            mockPolicy.interface.encodeErrorResult('MockDenied', [42])
          ])
        )
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
      await enableGuard({ owners: [owner], safe, safePolicyGuard, configurations: multiSendConfiguration })

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
          data: encodeCoSignerConfig(await cosigner.getAddress())
        }),
        // Configure policy for ETH transfer to other with other as cosigner
        createConfiguration({
          target: await other.getAddress(),
          policy: await coSignerPolicy.getAddress(),
          data: encodeCoSignerConfig(await other.getAddress())
        }),
        // Configure policy for ERC20 transfer with cosigner
        createConfiguration({
          target: await token.getAddress(),
          selector: transferSelector,
          policy: await coSignerPolicy.getAddress(),
          data: encodeCoSignerConfig(await cosigner.getAddress())
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
      await enableGuard({ owners: [owner], safe, safePolicyGuard, configurations: configurations })

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
  describe('Zero Target Resolution', function () {
    // `MultiSend` replaces a zero `to` with `address(this)`, which is the Safe because the batch is
    // delegatecalled. The policy has to resolve it the same way, or the checked target and the
    // called one diverge.
    it('Should route a zero target to the Safe rather than to address(0)', async function () {
      const { owner, safePolicyGuard, safe, multiSendPolicy, multiSend, allowPolicy, other } =
        await loadFixture(fixture)

      const multiSendSelector = multiSend.interface.getFunction('multiSend')?.selector
      const addOwnerSelector = safe.interface.getFunction('addOwnerWithThreshold')?.selector

      // The Safe allows exactly one self-administration call, addressed to itself.
      const configurations = [
        createConfiguration({
          target: await safe.getAddress(),
          selector: addOwnerSelector,
          policy: await allowPolicy.getAddress()
        }),
        createConfiguration({
          target: await multiSend.getAddress(),
          selector: multiSendSelector,
          operation: SafeOperation.DelegateCall,
          policy: await multiSendPolicy.getAddress()
        })
      ]
      await enableGuard({ owners: [owner], safe, safePolicyGuard, configurations })

      const txs = [
        buildSafeTransaction({
          to: ZeroAddress,
          data: safe.interface.encodeFunctionData('addOwnerWithThreshold', [other.address, 1]),
          nonce: 0
        })
      ]
      const safeTx = await buildMultiSendSafeTx(multiSend, txs, await safe.nonce())

      await execTransaction({
        owners: [owner],
        safe,
        to: await multiSend.getAddress(),
        data: safeTx.data,
        operation: SafeOperation.DelegateCall
      })

      expect(await safe.isOwner(other.address)).to.equal(true)
    })

    it('Should not let a zero target bypass a policy configured for the Safe', async function () {
      const { owner, safePolicyGuard, safe, multiSendPolicy, multiSend, allowPolicy, denyPolicy, other } =
        await loadFixture(fixture)

      const multiSendSelector = multiSend.interface.getFunction('multiSend')?.selector
      const addOwnerSelector = safe.interface.getFunction('addOwnerWithThreshold')?.selector

      // Self-administration is explicitly denied, while everything else reachable by `CALL` is
      // permitted through the fallback. Without the zero-target resolution the sub-transaction is
      // looked up against `address(0)`, misses, and lands on that permissive fallback instead of
      // the deny -- executing a self-call to the Safe that the Safe forbade.
      const configurations = [
        createConfiguration({
          target: await safe.getAddress(),
          selector: addOwnerSelector,
          policy: await denyPolicy.getAddress()
        }),
        createConfiguration({
          policy: await allowPolicy.getAddress() // CALL fallback
        }),
        createConfiguration({
          target: await multiSend.getAddress(),
          selector: multiSendSelector,
          operation: SafeOperation.DelegateCall,
          policy: await multiSendPolicy.getAddress()
        })
      ]
      await enableGuard({ owners: [owner], safe, safePolicyGuard, configurations })

      const txs = [
        buildSafeTransaction({
          to: ZeroAddress,
          data: safe.interface.encodeFunctionData('addOwnerWithThreshold', [other.address, 1]),
          nonce: 0
        })
      ]
      const safeTx = await buildMultiSendSafeTx(multiSend, txs, await safe.nonce())

      await expect(
        execTransaction({
          owners: [owner],
          safe,
          to: await multiSend.getAddress(),
          data: safeTx.data,
          operation: SafeOperation.DelegateCall
        })
      ).to.be.revertedWithCustomError(safePolicyGuard, 'PolicyReverted')

      expect(await safe.isOwner(other.address)).to.equal(false)
    })
  })

  // A sub-transaction of a batch may itself be a `multiSend` delegatecall, and a batch may hold
  // more sub-transactions than any of the tests above use. Both shapes walk the same code, so what
  // these check is that the walk neither stops early nor loses track of which context belongs to
  // which position.
  const leaf = (to: string): MetaTransaction => ({ operation: SafeOperation.Call, to, value: 0n, data: '0x' })

  /** ABI-encodes a `multiSend` call over `txs`, as a sub-transaction's calldata. */
  const batch = (multiSend: BaseContract, txs: MetaTransaction[]) =>
    multiSend.interface.encodeFunctionData('multiSend', [encodeMultiSend(txs)])

  /** A sub-transaction that is itself a batch. */
  const nested = (multiSendAddress: string, data: string): MetaTransaction => ({
    operation: SafeOperation.DelegateCall,
    to: multiSendAddress,
    value: 0n,
    data
  })

  /**
   * Packs one context per batch position, `[uint256 length][bytes]` each. An entry may itself be a
   * whole packed blob, which is how a nested batch receives its own positional contexts.
   */
  const encodeContexts = (entries: string[]) =>
    ethers.concat(
      entries.map((entry) => ethers.solidityPacked(['uint256', 'bytes'], [ethers.dataLength(entry), entry]))
    )

  describe('Nested Batches', function () {
    async function nestedFixture() {
      const base = await loadFixture(fixture)
      const { multiSend, multiSendPolicy } = base

      const multiSendAddress = await multiSend.getAddress()
      const multiSendKey = createConfiguration({
        target: multiSendAddress,
        selector: multiSend.interface.getFunction('multiSend')?.selector,
        operation: SafeOperation.DelegateCall,
        policy: await multiSendPolicy.getAddress()
      })

      return { ...base, multiSendAddress, multiSendKey }
    }

    it('Should clear a depth-2 batch whose every leaf is allowed', async function () {
      const { owner, safe, safePolicyGuard, multiSend, multiSendAddress, multiSendKey, allowPolicy } =
        await nestedFixture()

      const [first, second, innerFirst, innerSecond] = [
        randomAddress(),
        randomAddress(),
        randomAddress(),
        randomAddress()
      ]
      const allow = await allowPolicy.getAddress()
      await enableGuard({
        owners: [owner],
        safe,
        safePolicyGuard,
        configurations: [
          multiSendKey,
          ...[first, second, innerFirst, innerSecond].map((target) => createConfiguration({ target, policy: allow }))
        ]
      })

      const inner = batch(multiSend, [leaf(innerFirst), leaf(innerSecond)])
      const outer = batch(multiSend, [leaf(first), nested(multiSendAddress, inner), leaf(second)])

      await expect(
        execTransaction({
          owners: [owner],
          safe,
          to: multiSendAddress,
          data: outer,
          operation: SafeOperation.DelegateCall
        })
      ).to.not.be.reverted
    })

    it('Should wrap the denial of a nested leaf once per batch layer', async function () {
      const {
        owner,
        safe,
        safePolicyGuard,
        multiSendPolicy,
        multiSend,
        multiSendAddress,
        multiSendKey,
        allowPolicy,
        denyPolicy
      } = await nestedFixture()

      const [first, innerAllowed, innerDenied] = [randomAddress(), randomAddress(), randomAddress()]
      const allow = await allowPolicy.getAddress()
      const deny = await denyPolicy.getAddress()
      await enableGuard({
        owners: [owner],
        safe,
        safePolicyGuard,
        configurations: [
          multiSendKey,
          createConfiguration({ target: first, policy: allow }),
          createConfiguration({ target: innerAllowed, policy: allow }),
          createConfiguration({ target: innerDenied, policy: deny })
        ]
      })

      const inner = batch(multiSend, [leaf(innerAllowed), leaf(innerDenied)])
      const outer = batch(multiSend, [leaf(first), nested(multiSendAddress, inner)])

      // Each layer's `try/catch` wraps the one below it: the leaf's `AccessDenied`, then the inner
      // batch's `PolicyReverted`, then the outer batch's.
      const policy = await multiSendPolicy.getAddress()
      const leafDenial = safePolicyGuard.interface.encodeErrorResult('AccessDenied', [deny])
      const innerDenial = safePolicyGuard.interface.encodeErrorResult('PolicyReverted', [policy, leafDenial])

      await expect(
        execTransaction({
          owners: [owner],
          safe,
          to: multiSendAddress,
          data: outer,
          operation: SafeOperation.DelegateCall
        })
      )
        .to.be.revertedWithCustomError(safePolicyGuard, 'PolicyReverted')
        .withArgs(policy, innerDenial)
    })

    it('Should pair contexts positionally at every level', async function () {
      const { owner, safe, safePolicyGuard, multiSend, multiSendAddress, multiSendKey } = await nestedFixture()

      const recorderFactory = await ethers.getContractFactory('ContextRecorderPolicy')
      const recorders = await Promise.all([1, 2, 3, 4].map(() => recorderFactory.deploy()))
      const targets = recorders.map(() => randomAddress())
      await enableGuard({
        owners: [owner],
        safe,
        safePolicyGuard,
        configurations: [
          multiSendKey,
          ...(await Promise.all(
            recorders.map(async (recorder, i) =>
              createConfiguration({ target: targets[i], policy: await recorder.getAddress() })
            )
          ))
        ]
      })

      const [first, innerFirst, innerSecond, second] = targets
      const contexts = ['0xaa11', '0xbb01', '0xbb02', '0xcc33']
      const inner = batch(multiSend, [leaf(innerFirst), leaf(innerSecond)])
      const outer = batch(multiSend, [leaf(first), nested(multiSendAddress, inner), leaf(second)])
      // The whole inner blob sits in the outer context's second slot, which is where the nested
      // batch reads its own two contexts from.
      const context = encodeContexts([contexts[0], encodeContexts([contexts[1], contexts[2]]), contexts[3]])

      await execTransaction({
        owners: [owner],
        safe,
        to: multiSendAddress,
        data: outer,
        operation: SafeOperation.DelegateCall,
        additionalData: context
      })

      for (const [i, recorder] of recorders.entries()) {
        expect(await recorder.lastContext()).to.equal(contexts[i])
      }
    })

    it('Should clear a depth-3 batch', async function () {
      const { owner, safe, safePolicyGuard, multiSend, multiSendAddress, multiSendKey, allowPolicy } =
        await nestedFixture()

      const targets = [randomAddress(), randomAddress()]
      const allow = await allowPolicy.getAddress()
      await enableGuard({
        owners: [owner],
        safe,
        safePolicyGuard,
        configurations: [multiSendKey, ...targets.map((target) => createConfiguration({ target, policy: allow }))]
      })

      const inner = batch(multiSend, targets.map(leaf))
      const middle = batch(multiSend, [nested(multiSendAddress, inner)])
      const outer = batch(multiSend, [nested(multiSendAddress, middle)])

      await expect(
        execTransaction({
          owners: [owner],
          safe,
          to: multiSendAddress,
          data: outer,
          operation: SafeOperation.DelegateCall
        })
      ).to.not.be.reverted
    })
  })

  describe('Long Batches', function () {
    /** One `ContextRecorderPolicy` per position, so "leaf i was checked with context i" is observed. */
    async function recorderLeaves(count: number) {
      const recorderFactory = await ethers.getContractFactory('ContextRecorderPolicy')
      const recorders = await Promise.all(Array.from({ length: count }, () => recorderFactory.deploy()))
      const targets = Array.from({ length: count }, () => randomAddress())
      // A distinct context per position, so a repeated, shifted or dropped one is visible.
      const contexts = Array.from({ length: count }, (_, i) => ethers.zeroPadValue(ethers.toBeHex(i + 1), 32))
      const configurations = await Promise.all(
        recorders.map(async (recorder, i) =>
          createConfiguration({ target: targets[i], policy: await recorder.getAddress() })
        )
      )
      return { recorders, targets, contexts, configurations }
    }

    it('Should check every leaf of a four-item batch with its own context', async function () {
      const { owner, safe, safePolicyGuard, multiSendPolicy, multiSend } = await loadFixture(fixture)

      const multiSendAddress = await multiSend.getAddress()
      const { recorders, targets, contexts, configurations } = await recorderLeaves(4)
      await enableGuard({
        owners: [owner],
        safe,
        safePolicyGuard,
        configurations: [
          createConfiguration({
            target: multiSendAddress,
            selector: multiSend.interface.getFunction('multiSend')?.selector,
            operation: SafeOperation.DelegateCall,
            policy: await multiSendPolicy.getAddress()
          }),
          ...configurations
        ]
      })

      await execTransaction({
        owners: [owner],
        safe,
        to: multiSendAddress,
        data: batch(multiSend, targets.map(leaf)),
        operation: SafeOperation.DelegateCall,
        additionalData: encodeContexts(contexts)
      })

      for (const [i, recorder] of recorders.entries()) {
        expect(await recorder.lastContext(), `leaf ${i}`).to.equal(contexts[i])
      }
    })

    it('Should deny a five-item batch on a leaf at its last position', async function () {
      const { owner, safe, safePolicyGuard, multiSendPolicy, multiSend, allowPolicy, denyPolicy } =
        await loadFixture(fixture)

      const multiSendAddress = await multiSend.getAddress()
      const allow = await allowPolicy.getAddress()
      const deny = await denyPolicy.getAddress()
      const allowed = Array.from({ length: 5 }, () => randomAddress())
      const denied = randomAddress()

      await enableGuard({
        owners: [owner],
        safe,
        safePolicyGuard,
        configurations: [
          createConfiguration({
            target: multiSendAddress,
            selector: multiSend.interface.getFunction('multiSend')?.selector,
            operation: SafeOperation.DelegateCall,
            policy: await multiSendPolicy.getAddress()
          }),
          ...allowed.map((target) => createConfiguration({ target, policy: allow })),
          createConfiguration({ target: denied, policy: deny })
        ]
      })

      // Control: five allowed leaves clear, so the denial below is the leaf and not the length.
      await execTransaction({
        owners: [owner],
        safe,
        to: multiSendAddress,
        data: batch(multiSend, allowed.map(leaf)),
        operation: SafeOperation.DelegateCall
      })

      // Reaching position 4 is the point: a walk that stopped earlier would clear this batch.
      await expect(
        execTransaction({
          owners: [owner],
          safe,
          to: multiSendAddress,
          data: batch(multiSend, [...allowed.slice(0, 4).map(leaf), leaf(denied)]),
          operation: SafeOperation.DelegateCall
        })
      )
        .to.be.revertedWithCustomError(safePolicyGuard, 'PolicyReverted')
        .withArgs(
          await multiSendPolicy.getAddress(),
          safePolicyGuard.interface.encodeErrorResult('AccessDenied', [deny])
        )
    })

    it('Should check every leaf of a twenty-item batch and still deny on the last', async function () {
      const { owner, safe, safePolicyGuard, multiSendPolicy, multiSend, denyPolicy } = await loadFixture(fixture)

      const multiSendAddress = await multiSend.getAddress()
      const deny = await denyPolicy.getAddress()
      const { recorders, targets, contexts, configurations } = await recorderLeaves(20)
      const denied = randomAddress()

      await enableGuard({
        owners: [owner],
        safe,
        safePolicyGuard,
        configurations: [
          createConfiguration({
            target: multiSendAddress,
            selector: multiSend.interface.getFunction('multiSend')?.selector,
            operation: SafeOperation.DelegateCall,
            policy: await multiSendPolicy.getAddress()
          }),
          ...configurations,
          createConfiguration({ target: denied, policy: deny })
        ]
      })

      const context = encodeContexts(contexts)
      expect(ethers.dataLength(context)).to.equal(20 * (32 + 32))

      await execTransaction({
        owners: [owner],
        safe,
        to: multiSendAddress,
        data: batch(multiSend, targets.map(leaf)),
        operation: SafeOperation.DelegateCall,
        additionalData: context
      })

      // No early break, no repeated context, no drift between position and context slot.
      for (const [i, recorder] of recorders.entries()) {
        expect(await recorder.lastContext(), `leaf ${i}`).to.equal(contexts[i])
      }

      // A denial at the very last position of a long batch still denies the whole batch.
      await expect(
        execTransaction({
          owners: [owner],
          safe,
          to: multiSendAddress,
          data: batch(multiSend, [...targets.map(leaf), leaf(denied)]),
          operation: SafeOperation.DelegateCall,
          additionalData: encodeContexts([...contexts, '0x'])
        })
      )
        .to.be.revertedWithCustomError(safePolicyGuard, 'PolicyReverted')
        .withArgs(
          await multiSendPolicy.getAddress(),
          safePolicyGuard.interface.encodeErrorResult('AccessDenied', [deny])
        )
    })
  })
})
