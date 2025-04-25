import { mine } from '@nomicfoundation/hardhat-network-helpers'
// Artifact imports
import hre, { ethers } from 'hardhat'

import IERC20Artifact from '../artifacts/contracts/interfaces/IERC20.sol/IERC20.json'
import {
  execTransaction,
  SafeOperation,
  getSafeTransactionHash,
  EIP712_SAFE_MESSAGE_TYPE,
  createSafe
} from '../src/utils'
import {
  deployCoSignerPolicy,
  deployERC20ApprovePolicy,
  deployERC20TransferPolicy,
  deployNativeTransferPolicy,
  deploySafeContracts,
  deploySafePolicyGuard,
  deployTestERC20Token
} from './deploy'
import { logSection, logGasUsage, logGasDiff } from './utils/gas'

describe('[@bench] Policies', () => {
  const DELAY = 0n

  const setupTests = hre.deployments.createFixture(async () => {
    const [deployer, alice, bob, charlie] = await ethers.getSigners()

    const { safeProxyFactory, safe: safeSingleton, compatibilityFallbackHandler } = await deploySafeContracts()

    const safeProxy = await createSafe({
      owner: alice,
      saltNonce: 0n,
      fallbackHandler: await compatibilityFallbackHandler.getAddress(),
      safeProxyFactory,
      singleton: safeSingleton
    })

    const safeProxyCosigner = await createSafe({
      owner: bob,
      saltNonce: 0n,
      fallbackHandler: await compatibilityFallbackHandler.getAddress(),
      safeProxyFactory,
      singleton: safeSingleton
    })

    // Enable the SafePolicyGuard as Guard
    const { safePolicyGuard } = await deploySafePolicyGuard({ delay: DELAY })

    // Deploy ERC20ApprovePolicy
    const { erc20ApprovePolicy } = await deployERC20ApprovePolicy()

    // Deploy NativeTransferPolicy
    const { nativeTransferPolicy } = await deployNativeTransferPolicy()

    // Deploy ERC20TransferPolicy
    const { erc20TransferPolicy } = await deployERC20TransferPolicy()

    // Deploy CoSignerPolicy
    const { coSignerPolicy } = await deployCoSignerPolicy()

    // Deploy TestERC20
    const { token: testERC20 } = await deployTestERC20Token()
    await testERC20.mint(await alice.getAddress(), 1000n)
    await testERC20.mint(await safeProxy.getAddress(), 1000n)

    return {
      deployer,
      alice,
      bob,
      charlie,
      owners: [alice],
      safe: safeProxy,
      safePolicyGuard,
      erc20ApprovePolicy,
      coSignerPolicy,
      safeCosigner: safeProxyCosigner,
      token: testERC20,
      erc20TransferPolicy,
      nativeTransferPolicy
    }
  })

  describe('CoSignerPolicy', () => {
    it('[CoSignerPolicy] Native token transfer with 1:1 Safe', async () => {
      logSection('[CoSignerPolicy] Native token transfer with 1:1 Safe')

      const { safe, safeCosigner, alice, bob, charlie, owners, safePolicyGuard, coSignerPolicy } = await setupTests()

      const to = await charlie.getAddress()
      const value = 1n
      const selector = '0x00000000'

      // Fund the safe
      await alice.sendTransaction({
        to: safe.target,
        value: ethers.parseEther('1')
      })

      // Warmup tx to increment nonce
      await execTransaction({ owners, safe })

      // First transaction without guard
      const txWithoutGuard = await execTransaction({ owners, safe, to, value })
      await logGasUsage(txWithoutGuard, 'Tx without guard')

      // Enable guard
      const guardData = safe.interface.encodeFunctionData('setGuard', [await safePolicyGuard.getAddress()])
      const txEnableGuard = await execTransaction({
        owners,
        safe,
        to: safe.target,
        data: guardData
      })
      await logGasUsage(txEnableGuard, 'Set guard')

      // Request configuration
      const cosignerData = ethers.AbiCoder.defaultAbiCoder().encode(['address'], [await safeCosigner.getAddress()])
      const configurations = [
        { target: to, selector, operation: SafeOperation.Call, policy: coSignerPolicy.target, data: cosignerData }
      ]
      const configureRoot = ethers.keccak256(
        ethers.AbiCoder.defaultAbiCoder().encode(
          ['tuple(address target, bytes4 selector, uint8 operation, address policy, bytes data)[]'],
          [configurations]
        )
      )
      const requestPolicyConfiguration = safePolicyGuard.interface.encodeFunctionData('requestConfiguration', [
        configureRoot
      ])
      const txRequest = await execTransaction({
        owners,
        safe,
        to: await safePolicyGuard.getAddress(),
        data: requestPolicyConfiguration
      })
      await logGasUsage(txRequest, 'Request configuration')

      await mine(13, { interval: DELAY * 60n })

      // Apply configuration
      const applyPolicyConfiguration = safePolicyGuard.interface.encodeFunctionData('applyConfiguration', [
        configurations
      ])
      const txApply = await execTransaction({
        owners,
        safe,
        to: await safePolicyGuard.getAddress(),
        data: applyPolicyConfiguration
      })
      await logGasUsage(txApply, 'Apply configuration')

      // Get cosigner signature
      const safeTransactionHash = await getSafeTransactionHash({
        safe,
        to,
        value
      })
      const chainId = (await ethers.provider.getNetwork()).chainId
      const bobSignature = await bob.signTypedData(
        { verifyingContract: safeCosigner.target, chainId: chainId },
        EIP712_SAFE_MESSAGE_TYPE,
        { message: safeTransactionHash }
      )

      // Execute transaction with guard enabled
      const txWithGuard = await execTransaction({
        owners,
        safe,
        to,
        value,
        additionalData: bobSignature
      })
      await logGasUsage(txWithGuard, 'Tx with guard')

      await logGasDiff(txWithoutGuard, txWithGuard)
    })

    it('[CoSignerPolicy] ERC20 token transfer with 1:1 Safe', async () => {
      logSection('[CoSignerPolicy] ERC20 token transfer with 1:1 Safe')

      const { safe, safeCosigner, bob, charlie, owners, safePolicyGuard, coSignerPolicy, token } = await setupTests()

      const to = await charlie.getAddress()
      const data = token.interface.encodeFunctionData('transfer', [to, 100n])

      const selector = token.interface.getFunction('transfer').selector

      // Fund the safe
      await token.mint(safe.target, 1000n)
      // Make receiver balance non-zero to avoid additional gas cost when updating storage from non-zero value
      await token.mint(to, 1000n)

      // Make nonce non-zero to avoid additional gas cost when updating storage from non-zero value
      await execTransaction({ owners, safe })

      // First transaction without guard
      const txWithoutGuard = await execTransaction({ owners, safe, to, data })
      await logGasUsage(txWithoutGuard, 'Tx without guard')

      // Enable guard
      const guardData = safe.interface.encodeFunctionData('setGuard', [await safePolicyGuard.getAddress()])
      const txEnableGuard = await execTransaction({ owners, safe, to: safe.target, data: guardData })
      await logGasUsage(txEnableGuard, 'Set guard')

      // Request configuration
      const cosignerData = ethers.AbiCoder.defaultAbiCoder().encode(['address'], [await safeCosigner.getAddress()])
      const configurations = [
        { target: to, selector, operation: SafeOperation.Call, policy: coSignerPolicy.target, data: cosignerData }
      ]
      const configureRoot = ethers.keccak256(
        ethers.AbiCoder.defaultAbiCoder().encode(
          ['tuple(address target, bytes4 selector, uint8 operation, address policy, bytes data)[]'],
          [configurations]
        )
      )
      const requestPolicyConfiguration = safePolicyGuard.interface.encodeFunctionData('requestConfiguration', [
        configureRoot
      ])
      const txRequest = await execTransaction({
        owners,
        safe,
        to: await safePolicyGuard.getAddress(),
        data: requestPolicyConfiguration
      })
      await logGasUsage(txRequest, 'Request configuration')

      await mine(13, { interval: DELAY * 60n })

      // Apply configuration
      const applyPolicyConfiguration = safePolicyGuard.interface.encodeFunctionData('applyConfiguration', [
        configurations
      ])
      const txApply = await execTransaction({
        owners,
        safe,
        to: await safePolicyGuard.getAddress(),
        data: applyPolicyConfiguration
      })
      await logGasUsage(txApply, 'Apply configuration')

      // Get cosigner signature
      const safeTransactionHash = await getSafeTransactionHash({
        safe,
        to,
        data
      })
      const chainId = (await ethers.provider.getNetwork()).chainId
      const bobSignature = await bob.signTypedData(
        { verifyingContract: safeCosigner.target, chainId: chainId },
        EIP712_SAFE_MESSAGE_TYPE,
        { message: safeTransactionHash }
      )

      // Execute transaction with guard enabled
      const txWithGuard = await execTransaction({
        owners,
        safe,
        to,
        data,
        additionalData: bobSignature
      })
      await logGasUsage(txWithGuard, 'Tx with guard')

      await logGasDiff(txWithoutGuard, txWithGuard)
    })

    it('[CoSignerPolicy] ERC20 token approve with 1:1 Safe', async () => {
      logSection('[CoSignerPolicy] ERC20 token approve with 1:1 Safe')

      const { safe, safeCosigner, bob, charlie, owners, safePolicyGuard, coSignerPolicy, token } = await setupTests()

      const to = token.target
      const approvalReceipent = await charlie.getAddress()
      const dataWithoutGuard = token.interface.encodeFunctionData('approve', [approvalReceipent, 100n])
      const dataWithGuard = token.interface.encodeFunctionData('approve', [approvalReceipent, 1000n])

      const selector = token.interface.getFunction('approve').selector

      // Make storage slots non-zero to avoid additional gas cost when updating storage from non-zero value
      // Slots: Safe nonce, ERC20 allowance
      const dataInitialApprove = token.interface.encodeFunctionData('approve', [approvalReceipent, 99n])
      await execTransaction({ owners, safe, to, data: dataInitialApprove })

      // First transaction without guard
      const txWithoutGuard = await execTransaction({ owners, safe, to, data: dataWithoutGuard })
      await logGasUsage(txWithoutGuard, 'Tx without guard')

      // Enable guard
      const guardData = safe.interface.encodeFunctionData('setGuard', [await safePolicyGuard.getAddress()])
      const txEnableGuard = await execTransaction({ owners, safe, to: safe.target, data: guardData })
      await logGasUsage(txEnableGuard, 'Set guard')

      // Request configuration
      const cosignerData = ethers.AbiCoder.defaultAbiCoder().encode(['address'], [await safeCosigner.getAddress()])
      const configurations = [
        { target: to, selector, operation: SafeOperation.Call, policy: coSignerPolicy.target, data: cosignerData }
      ]
      const configureRoot = ethers.keccak256(
        ethers.AbiCoder.defaultAbiCoder().encode(
          ['tuple(address target, bytes4 selector, uint8 operation, address policy, bytes data)[]'],
          [configurations]
        )
      )
      const calldataConfigurePolicy = safePolicyGuard.interface.encodeFunctionData('requestConfiguration', [
        configureRoot
      ])
      const txRequest = await execTransaction({
        owners,
        safe,
        to: await safePolicyGuard.getAddress(),
        data: calldataConfigurePolicy
      })
      await logGasUsage(txRequest, 'Request configuration')

      await mine(13, { interval: DELAY * 60n })

      // Apply configuration
      const applyPolicyConfiguration = safePolicyGuard.interface.encodeFunctionData('applyConfiguration', [
        configurations
      ])
      const txApply = await execTransaction({
        owners,
        safe,
        to: await safePolicyGuard.getAddress(),
        data: applyPolicyConfiguration
      })
      await logGasUsage(txApply, 'Apply configuration')

      // Get cosigner signature
      const safeTransactionHash = await getSafeTransactionHash({
        safe,
        to,
        data: dataWithGuard
      })
      const chainId = (await ethers.provider.getNetwork()).chainId
      const bobSignature = await bob.signTypedData(
        { verifyingContract: safeCosigner.target, chainId: chainId },
        EIP712_SAFE_MESSAGE_TYPE,
        { message: safeTransactionHash }
      )

      // Execute transaction with guard enabled
      const txWithGuard = await execTransaction({
        owners,
        safe,
        to,
        data: dataWithGuard,
        additionalData: bobSignature
      })
      await logGasUsage(txWithGuard, 'Tx with guard')

      await logGasDiff(txWithoutGuard, txWithGuard)
    })
  })

  describe('ERC20ApprovePolicy', () => {
    it('[ERC20ApprovePolicy] Approve with 1:1 Safe', async () => {
      logSection('[ERC20ApprovePolicy] Approve with 1:1 Safe')

      const { safe, owners, safePolicyGuard, erc20ApprovePolicy, token, charlie } = await setupTests()

      const to = token.target
      const approvalReceipent = await charlie.getAddress()

      // Make storage slots non-zero to avoid additional gas cost when updating storage from non-zero value
      // Slots: Safe nonce, ERC20 allowance
      const calldataApproveFirst = token.interface.encodeFunctionData('approve', [approvalReceipent, 99n])
      await execTransaction({ owners, safe, to, data: calldataApproveFirst })

      const calldataApproveSecond = token.interface.encodeFunctionData('approve', [approvalReceipent, 10000n])
      const txWithoutGuard = await execTransaction({
        owners,
        safe,
        to: token.target,
        data: calldataApproveSecond
      })

      await logGasUsage(txWithoutGuard, 'Tx without guard')

      const callData = safe.interface.encodeFunctionData('setGuard', [await safePolicyGuard.getAddress()])
      const txEnableGuard = await execTransaction({ owners, safe, to: safe.target, data: callData })
      await logGasUsage(txEnableGuard, 'Set guard')

      const erc20Interface = new ethers.Interface(IERC20Artifact.abi)
      const selector = erc20Interface.getFunction('approve')?.selector

      const erc20TokenAddress = await token.getAddress()
      const spenderList = [approvalReceipent]

      // Encode the spender list into a single bytes object
      const spenderData = ethers.AbiCoder.defaultAbiCoder().encode(
        ['tuple(address spender, bool allowed)[]'],
        [spenderList.map((spender) => ({ spender, allowed: true }))]
      )

      const configurations = [
        {
          target: erc20TokenAddress,
          selector,
          operation: SafeOperation.Call,
          policy: await erc20ApprovePolicy.getAddress(),
          data: spenderData
        }
      ]
      const configureRoot = ethers.keccak256(
        ethers.AbiCoder.defaultAbiCoder().encode(
          ['tuple(address target, bytes4 selector, uint8 operation, address policy, bytes data)[]'],
          [configurations]
        )
      )
      const requestPolicyConfiguration = safePolicyGuard.interface.encodeFunctionData('requestConfiguration', [
        configureRoot
      ])
      const txRequest = await execTransaction({
        owners,
        safe,
        to: await safePolicyGuard.getAddress(),
        data: requestPolicyConfiguration
      })
      await logGasUsage(txRequest, 'Request configuration')

      await mine(13, { interval: DELAY * 60n })

      const applyPolicyConfiguration = safePolicyGuard.interface.encodeFunctionData('applyConfiguration', [
        configurations
      ])
      const txApply = await execTransaction({
        owners,
        safe,
        to: await safePolicyGuard.getAddress(),
        data: applyPolicyConfiguration
      })
      await logGasUsage(txApply, 'Apply configuration')

      const calldataApproveThird = token.interface.encodeFunctionData('approve', [approvalReceipent, 100000n])
      const txWithGuard = await execTransaction({
        owners,
        safe,
        to: erc20TokenAddress,
        data: calldataApproveThird
      })

      await logGasUsage(txWithGuard, 'Tx with guard')

      await logGasDiff(txWithoutGuard, txWithGuard)
    })
  })

  describe('ERC20TransferPolicy', () => {
    it('[ERC20TransferPolicy] Token transfer with 1:1 Safe', async () => {
      logSection('[ERC20TransferPolicy] Token transfer with 1:1 Safe')

      const { safe, owners, safePolicyGuard, erc20TransferPolicy, bob, token } = await setupTests()

      const calldataTransferFirst = token.interface.encodeFunctionData('transfer', [await bob.getAddress(), 1n])

      // Make storage slots non-zero to avoid additional gas cost when updating storage from non-zero value
      // Slots: Safe nonce, ERC20 balance
      await execTransaction({ owners, safe, to: token.target, data: calldataTransferFirst })

      const calldataTransferSecond = token.interface.encodeFunctionData('transfer', [await bob.getAddress(), 1n])
      const txWithoutGuard = await execTransaction({
        owners,
        safe,
        to: token.target,
        data: calldataTransferSecond
      })
      await logGasUsage(txWithoutGuard, 'Tx without guard')

      const callData = safe.interface.encodeFunctionData('setGuard', [await safePolicyGuard.getAddress()])
      const txEnableGuard = await execTransaction({ owners, safe, to: safe.target, data: callData })
      await logGasUsage(txEnableGuard, 'Set guard')

      const erc20Interface = new ethers.Interface(IERC20Artifact.abi)
      const selector = erc20Interface.getFunction('transfer')?.selector

      const erc20TokenAddress = await token.getAddress()
      const recipientList = [await bob.getAddress()]

      // Encode the spender list into a single bytes object
      const recipientData = ethers.AbiCoder.defaultAbiCoder().encode(
        ['tuple(address recipient, bool allowed)[]'],
        [recipientList.map((recipient) => ({ recipient, allowed: true }))]
      )

      const configurations = [
        {
          target: erc20TokenAddress,
          selector,
          operation: SafeOperation.Call,
          policy: erc20TransferPolicy.target,
          data: recipientData
        }
      ]
      const configureRoot = ethers.keccak256(
        ethers.AbiCoder.defaultAbiCoder().encode(
          ['tuple(address target, bytes4 selector, uint8 operation, address policy, bytes data)[]'],
          [configurations]
        )
      )
      const requestPolicyConfiguration = safePolicyGuard.interface.encodeFunctionData('requestConfiguration', [
        configureRoot
      ])
      const txRequest = await execTransaction({
        owners,
        safe,
        to: await safePolicyGuard.getAddress(),
        data: requestPolicyConfiguration
      })
      await logGasUsage(txRequest, 'Request configuration')

      await mine(13, { interval: DELAY * 60n })

      const applyPolicyConfiguration = safePolicyGuard.interface.encodeFunctionData('applyConfiguration', [
        configurations
      ])
      const txApply = await execTransaction({
        owners,
        safe,
        to: await safePolicyGuard.getAddress(),
        data: applyPolicyConfiguration
      })
      await logGasUsage(txApply, 'Apply configuration')

      const calldataTransferThird = token.interface.encodeFunctionData('transfer', [await bob.getAddress(), 1n])
      const txWithGuard = await execTransaction({
        owners,
        safe,
        to: erc20TokenAddress,
        data: calldataTransferThird
      })

      await logGasUsage(txWithGuard, 'Tx with guard')
      await logGasDiff(txWithoutGuard, txWithGuard)
    })
  })

  describe('NativeTransferPolicy', () => {
    it('[NativeTransferPolicy] Native token transfer with 1:1 Safe', async () => {
      logSection('[NativeTransferPolicy] Native token transfer with 1:1 Safe')

      const { safe, owners, safePolicyGuard, nativeTransferPolicy, alice, bob } = await setupTests()

      const amount = ethers.parseEther('1')
      const selector = '0x00000000'
      const recipientAddress = await bob.getAddress()
      const configData = '0x' // No additional data needed for native transfer
      // Warmup tx for increment the nonce
      await execTransaction({ owners, safe })

      await alice.sendTransaction({
        to: safe.target,
        value: ethers.parseEther('3')
      })

      const txWithoutGuard = await execTransaction({ owners, safe, to: recipientAddress, value: amount })
      await logGasUsage(txWithoutGuard, 'Tx without guard')

      const callData = safe.interface.encodeFunctionData('setGuard', [await safePolicyGuard.getAddress()])
      const txEnableGuard = await execTransaction({ owners, safe, to: safe.target, data: callData })
      await logGasUsage(txEnableGuard, 'Set guard')

      const configurations = [
        {
          target: recipientAddress,
          selector,
          operation: SafeOperation.Call,
          policy: nativeTransferPolicy.target,
          data: configData
        }
      ]
      const configureRoot = ethers.keccak256(
        ethers.AbiCoder.defaultAbiCoder().encode(
          ['tuple(address target, bytes4 selector, uint8 operation, address policy, bytes data)[]'],
          [configurations]
        )
      )
      const requestPolicyConfiguration = safePolicyGuard.interface.encodeFunctionData('requestConfiguration', [
        configureRoot
      ])
      const txRequest = await execTransaction({
        owners,
        safe,
        to: await safePolicyGuard.getAddress(),
        data: requestPolicyConfiguration
      })
      await logGasUsage(txRequest, 'Request configuration')

      await mine(13, { interval: DELAY * 60n })

      const applyPolicyConfiguration = safePolicyGuard.interface.encodeFunctionData('applyConfiguration', [
        configurations
      ])
      const txApply = await execTransaction({
        owners,
        safe,
        to: await safePolicyGuard.getAddress(),
        data: applyPolicyConfiguration
      })
      await logGasUsage(txApply, 'Apply configuration')

      const txWithGuard = await execTransaction({ owners, safe, to: recipientAddress, value: amount })

      await logGasUsage(txWithGuard, 'Tx with guard')
      await logGasDiff(txWithoutGuard, txWithGuard)
    })
  })
})
