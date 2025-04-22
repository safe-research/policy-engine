import { mine } from '@nomicfoundation/hardhat-network-helpers'
// Artifact imports
import SafeArtifact from '@safe-global/safe-contracts/build/artifacts/contracts/Safe.sol/Safe.json'
import CompatibilityFallbackHandlerArtifact from '@safe-global/safe-contracts/build/artifacts/contracts/handler/CompatibilityFallbackHandler.sol/CompatibilityFallbackHandler.json'
import SafeProxyFactoryArtifact from '@safe-global/safe-contracts/build/artifacts/contracts/proxies/SafeProxyFactory.sol/SafeProxyFactory.json'
import hre, { ethers } from 'hardhat'

import SafePolicyGuardArtifact from '../artifacts/contracts/SafePolicyGuard.sol/SafePolicyGuard.json'
import IERC20Artifact from '../artifacts/contracts/interfaces/IERC20.sol/IERC20.json'
import CoSignerPolicyArtifact from '../artifacts/contracts/policies/CoSignerPolicy.sol/CoSignerPolicy.json'
import ERC20ApprovePolicyArtifact from '../artifacts/contracts/policies/ERC20ApprovePolicy.sol/ERC20ApprovePolicy.json'
import ERC20TransferPolicyArtifact from '../artifacts/contracts/policies/ERC20TransferPolicy.sol/ERC20TransferPolicy.json'
import NativeTransferPolicyArtifact from '../artifacts/contracts/policies/NativeTransferPolicy.sol/NativeTransferPolicy.json'
import TestERC20Artifact from '../artifacts/contracts/test/TestERC20Token.sol/TestERC20Token.json'
import { execTransaction, SafeOperation, getSafeTransactionHash, EIP712_SAFE_MESSAGE_TYPE } from '../src/utils'
import { logSection, logGasUsage, logGasDiff } from './utils/gas'

const ZeroAddress: `0x${string}` = ethers.ZeroAddress

describe('[@bench] Policies', () => {
  const DELAY = 0n

  const setupTests = hre.deployments.createFixture(async () => {
    const [deployer, alice, bob, charlie] = await ethers.getSigners()
    const SafeSingletonFactory = await ethers.getContractFactory(SafeArtifact.abi, SafeArtifact.bytecode)
    const safeSingleton = await SafeSingletonFactory.deploy()

    const SafeProxyFactory = await ethers.getContractFactory(
      SafeProxyFactoryArtifact.abi,
      SafeProxyFactoryArtifact.bytecode
    )
    const safeProxyFactory = await SafeProxyFactory.deploy()

    const CompatibilityFallbackHandlerFactory = await ethers.getContractFactory(
      CompatibilityFallbackHandlerArtifact.abi,
      CompatibilityFallbackHandlerArtifact.bytecode
    )
    const compatibilityFallbackHandler = await CompatibilityFallbackHandlerFactory.deploy()

    const setupData = safeSingleton.interface.encodeFunctionData('setup', [
      [await alice.getAddress()],
      1,
      ZeroAddress,
      '0x',
      compatibilityFallbackHandler.target,
      ZeroAddress,
      0,
      ZeroAddress
    ])

    const safeProxyAddress = await safeProxyFactory.createProxyWithNonce.staticCall(
      await safeSingleton.getAddress(),
      setupData,
      0n
    )
    await safeProxyFactory.createProxyWithNonce(safeSingleton.target, setupData, 0n)
    const safeProxy = await ethers.getContractAt(SafeArtifact.abi, safeProxyAddress)

    const setupCosignerSafeData = safeSingleton.interface.encodeFunctionData('setup', [
      [await bob.getAddress()],
      1,
      ZeroAddress,
      '0x',
      compatibilityFallbackHandler.target,
      ZeroAddress,
      0,
      ZeroAddress
    ])

    const safeProxyCosignerAddress = await safeProxyFactory.createProxyWithNonce.staticCall(
      await safeSingleton.getAddress(),
      setupCosignerSafeData,
      0n
    )
    await safeProxyFactory.createProxyWithNonce(safeSingleton.target, setupCosignerSafeData, 0n)
    const safeProxyCosigner = await ethers.getContractAt(SafeArtifact.abi, safeProxyCosignerAddress)

    // Enable the SafePolicyGuard as Guard
    const SafePolicyGuardFactory = await ethers.getContractFactory(
      SafePolicyGuardArtifact.abi,
      SafePolicyGuardArtifact.bytecode
    )
    const safePolicyGuardContract = await SafePolicyGuardFactory.deploy(DELAY.toString())
    const safePolicyGuard = await ethers.getContractAt(SafePolicyGuardArtifact.abi, safePolicyGuardContract.target)

    // Deploy ERC20ApprovePolicy
    const ERC20ApprovePolicyFactory = await ethers.getContractFactory(
      ERC20ApprovePolicyArtifact.abi,
      ERC20ApprovePolicyArtifact.bytecode
    )
    const ERC20ApprovePolicyContract = await ERC20ApprovePolicyFactory.deploy()
    const erc20ApprovePolicy = await ethers.getContractAt(
      ERC20ApprovePolicyArtifact.abi,
      ERC20ApprovePolicyContract.target
    )

    // Deploy NativeTransferPolicy
    const NativeTransferPolicyFactory = await ethers.getContractFactory(
      NativeTransferPolicyArtifact.abi,
      NativeTransferPolicyArtifact.bytecode
    )
    const NativeTransferPolicyContract = await NativeTransferPolicyFactory.deploy()
    const nativeTransferPolicy = await ethers.getContractAt(
      NativeTransferPolicyArtifact.abi,
      NativeTransferPolicyContract.target
    )

    // Deploy ERC20TransferPolicy
    const ERC20TransferPolicyFactory = await ethers.getContractFactory(
      ERC20TransferPolicyArtifact.abi,
      ERC20TransferPolicyArtifact.bytecode
    )
    const ERC20TransferPolicyContract = await ERC20TransferPolicyFactory.deploy()
    const erc20TransferPolicy = await ethers.getContractAt(
      ERC20TransferPolicyArtifact.abi,
      ERC20TransferPolicyContract.target
    )

    // Deploy CoSignerPolicy
    const CoSignerPolicyFactory = await ethers.getContractFactory(
      CoSignerPolicyArtifact.abi,
      CoSignerPolicyArtifact.bytecode
    )
    const CoSignerPolicyContract = await CoSignerPolicyFactory.deploy()
    const coSignerPolicy = await ethers.getContractAt(CoSignerPolicyArtifact.abi, CoSignerPolicyContract.target)

    // Deploy TestERC20
    const TestERC20Factory = await ethers.getContractFactory(TestERC20Artifact.abi, TestERC20Artifact.bytecode)
    const testERC20Contract = await TestERC20Factory.deploy()
    const testERC20 = await ethers.getContractAt(TestERC20Artifact.abi, testERC20Contract.target)
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
      const data = '0x'
      const selector = '0x00000000'

      // Fund the safe
      await alice.sendTransaction({
        to: safe.target,
        value: ethers.parseEther('1')
      })

      // Warmup tx to increment nonce
      await execTransaction(owners, safe, ZeroAddress, 0n, '0x', SafeOperation.Call)

      // First transaction without guard
      const txWithoutGuard = await execTransaction(owners, safe, to, value, data, SafeOperation.Call)
      await logGasUsage(txWithoutGuard, 'Tx without guard')

      // Enable guard
      const guardData = safe.interface.encodeFunctionData('setGuard', [safePolicyGuard.target])
      const txEnableGuard = await execTransaction(owners, safe, safe.target, 0n, guardData, SafeOperation.Call)
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
      const txRequest = await execTransaction(
        owners,
        safe,
        safePolicyGuard.target,
        0n,
        requestPolicyConfiguration,
        SafeOperation.Call
      )
      await logGasUsage(txRequest, 'Request configuration')

      await mine(13, { interval: DELAY * 60n })

      // Apply configuration
      const applyPolicyConfiguration = safePolicyGuard.interface.encodeFunctionData('applyConfiguration', [
        configurations
      ])
      const txApply = await execTransaction(
        owners,
        safe,
        safePolicyGuard.target,
        0n,
        applyPolicyConfiguration,
        SafeOperation.Call
      )
      await logGasUsage(txApply, 'Apply configuration')

      // Get cosigner signature
      const safeTransactionHash = await getSafeTransactionHash(
        safe,
        to,
        value,
        data,
        SafeOperation.Call,
        0n,
        0n,
        0n,
        ZeroAddress as `0x${string}`,
        ZeroAddress as `0x${string}`
      )
      const chainId = (await ethers.provider.getNetwork()).chainId
      const bobSignature = await bob.signTypedData(
        { verifyingContract: safeCosigner.target, chainId: chainId },
        EIP712_SAFE_MESSAGE_TYPE,
        { message: safeTransactionHash }
      )

      // Execute transaction with guard enabled
      const txWithGuard = await execTransaction(
        owners,
        safe,
        to,
        value,
        data,
        SafeOperation.Call,
        0n,
        0n,
        0n,
        ZeroAddress as `0x${string}`,
        ZeroAddress as `0x${string}`,
        bobSignature
      )
      await logGasUsage(txWithGuard, 'Tx with guard')

      await logGasDiff(txWithoutGuard, txWithGuard)
    })

    it('[CoSignerPolicy] ERC20 token transfer with 1:1 Safe', async () => {
      logSection('[CoSignerPolicy] ERC20 token transfer with 1:1 Safe')

      const { safe, safeCosigner, alice, bob, charlie, owners, safePolicyGuard, coSignerPolicy, token } =
        await setupTests()

      const to = await charlie.getAddress()
      const value = 0n
      const data = token.interface.encodeFunctionData('transfer', [to, 100n])

      const selector = token.interface.getFunction('transfer').selector

      // Fund the safe
      await token.mint(safe.target, 1000n)
      // Make receiver balance non-zero to avoid additional gas cost when updating storage from non-zero value
      await token.mint(to, 1000n)

      // Make nonce non-zero to avoid additional gas cost when updating storage from non-zero value
      await execTransaction(owners, safe, ZeroAddress, 0n, '0x', SafeOperation.Call)

      // First transaction without guard
      const txWithoutGuard = await execTransaction(owners, safe, to, value, data, SafeOperation.Call)
      await logGasUsage(txWithoutGuard, 'Tx without guard')

      // Enable guard
      const guardData = safe.interface.encodeFunctionData('setGuard', [safePolicyGuard.target])
      const txEnableGuard = await execTransaction(owners, safe, safe.target, 0n, guardData, SafeOperation.Call)
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
      const txRequest = await execTransaction(
        owners,
        safe,
        safePolicyGuard.target,
        0n,
        requestPolicyConfiguration,
        SafeOperation.Call
      )
      await logGasUsage(txRequest, 'Request configuration')

      await mine(13, { interval: DELAY * 60n })

      // Apply configuration
      const applyPolicyConfiguration = safePolicyGuard.interface.encodeFunctionData('applyConfiguration', [
        configurations
      ])
      const txApply = await execTransaction(
        owners,
        safe,
        safePolicyGuard.target,
        0n,
        applyPolicyConfiguration,
        SafeOperation.Call
      )
      await logGasUsage(txApply, 'Apply configuration')

      // Get cosigner signature
      const safeTransactionHash = await getSafeTransactionHash(
        safe,
        to,
        value,
        data,
        SafeOperation.Call,
        0n,
        0n,
        0n,
        ZeroAddress as `0x${string}`,
        ZeroAddress as `0x${string}`
      )
      const chainId = (await ethers.provider.getNetwork()).chainId
      const bobSignature = await bob.signTypedData(
        { verifyingContract: safeCosigner.target, chainId: chainId },
        EIP712_SAFE_MESSAGE_TYPE,
        { message: safeTransactionHash }
      )

      // Execute transaction with guard enabled
      const txWithGuard = await execTransaction(
        owners,
        safe,
        to,
        value,
        data,
        SafeOperation.Call,
        0n,
        0n,
        0n,
        ZeroAddress as `0x${string}`,
        ZeroAddress as `0x${string}`,
        bobSignature
      )
      await logGasUsage(txWithGuard, 'Tx with guard')

      await logGasDiff(txWithoutGuard, txWithGuard)
    })

    it('[CoSignerPolicy] ERC20 token approve with 1:1 Safe', async () => {
      logSection('[CoSignerPolicy] ERC20 token approve with 1:1 Safe')

      const { safe, safeCosigner, alice, bob, charlie, owners, safePolicyGuard, coSignerPolicy, token } =
        await setupTests()

      const to = token.target
      const approvalReceipent = await charlie.getAddress()
      const value = 0n
      const dataWithoutGuard = token.interface.encodeFunctionData('approve', [approvalReceipent, 100n])
      const dataWithGuard = token.interface.encodeFunctionData('approve', [approvalReceipent, 1000n])

      const selector = token.interface.getFunction('approve').selector

      // Make storage slots non-zero to avoid additional gas cost when updating storage from non-zero value
      // Slots: Safe nonce, ERC20 allowance
      const dataInitialApprove = token.interface.encodeFunctionData('approve', [approvalReceipent, 99n])
      await execTransaction(owners, safe, to, value, dataInitialApprove, SafeOperation.Call)

      // First transaction without guard
      const txWithoutGuard = await execTransaction(owners, safe, to, value, dataWithoutGuard, SafeOperation.Call)
      await logGasUsage(txWithoutGuard, 'Tx without guard')

      // Enable guard
      const guardData = safe.interface.encodeFunctionData('setGuard', [safePolicyGuard.target])
      const txEnableGuard = await execTransaction(owners, safe, safe.target, 0n, guardData, SafeOperation.Call)
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
      const txRequest = await execTransaction(
        owners,
        safe,
        safePolicyGuard.target,
        0n,
        calldataConfigurePolicy,
        SafeOperation.Call
      )
      await logGasUsage(txRequest, 'Request configuration')

      await mine(13, { interval: DELAY * 60n })

      // Apply configuration
      const applyPolicyConfiguration = safePolicyGuard.interface.encodeFunctionData('applyConfiguration', [
        configurations
      ])
      const txApply = await execTransaction(
        owners,
        safe,
        safePolicyGuard.target,
        0n,
        applyPolicyConfiguration,
        SafeOperation.Call
      )
      await logGasUsage(txApply, 'Apply configuration')

      // Get cosigner signature
      const safeTransactionHash = await getSafeTransactionHash(
        safe,
        to,
        value,
        dataWithGuard,
        SafeOperation.Call,
        0n,
        0n,
        0n,
        ZeroAddress as `0x${string}`,
        ZeroAddress as `0x${string}`
      )
      const chainId = (await ethers.provider.getNetwork()).chainId
      const bobSignature = await bob.signTypedData(
        { verifyingContract: safeCosigner.target, chainId: chainId },
        EIP712_SAFE_MESSAGE_TYPE,
        { message: safeTransactionHash }
      )

      // Execute transaction with guard enabled
      const txWithGuard = await execTransaction(
        owners,
        safe,
        to,
        value,
        dataWithGuard,
        SafeOperation.Call,
        0n,
        0n,
        0n,
        ZeroAddress as `0x${string}`,
        ZeroAddress as `0x${string}`,
        bobSignature
      )
      await logGasUsage(txWithGuard, 'Tx with guard')

      await logGasDiff(txWithoutGuard, txWithGuard)
    })
  })

  describe('ERC20ApprovePolicy', () => {
    it('[ERC20ApprovePolicy] Approve with 1:1 Safe', async () => {
      logSection('[ERC20ApprovePolicy] Approve with 1:1 Safe')

      const { safe, owners, safePolicyGuard, erc20ApprovePolicy, token, charlie } = await setupTests()

      const to = token.target
      const value = 0n
      const approvalReceipent = await charlie.getAddress()

      // Make storage slots non-zero to avoid additional gas cost when updating storage from non-zero value
      // Slots: Safe nonce, ERC20 allowance
      const calldataApproveFirst = token.interface.encodeFunctionData('approve', [approvalReceipent, 99n])
      await execTransaction(owners, safe, to, value, calldataApproveFirst, SafeOperation.Call)

      const calldataApproveSecond = token.interface.encodeFunctionData('approve', [approvalReceipent, 10000n])
      const txWithoutGuard = await execTransaction(
        owners,
        safe,
        token.target,
        value,
        calldataApproveSecond,
        SafeOperation.Call
      )

      await logGasUsage(txWithoutGuard, 'Tx without guard')

      const callData = safe.interface.encodeFunctionData('setGuard', [safePolicyGuard.target])
      const txEnableGuard = await execTransaction(owners, safe, safe.target, 0n, callData, SafeOperation.Call)
      await logGasUsage(txEnableGuard, 'Set guard')

      const erc20Interface = new ethers.Interface(IERC20Artifact.abi)
      const selector = erc20Interface.getFunction('approve').selector

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
          policy: erc20ApprovePolicy.target,
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
      const txRequest = await execTransaction(
        owners,
        safe,
        safePolicyGuard.target,
        0n,
        requestPolicyConfiguration,
        SafeOperation.Call
      )
      await logGasUsage(txRequest, 'Request configuration')

      await mine(13, { interval: DELAY * 60n })

      const applyPolicyConfiguration = safePolicyGuard.interface.encodeFunctionData('applyConfiguration', [
        configurations
      ])
      const txApply = await execTransaction(
        owners,
        safe,
        safePolicyGuard.target,
        0n,
        applyPolicyConfiguration,
        SafeOperation.Call
      )
      await logGasUsage(txApply, 'Apply configuration')

      const calldataApproveThird = token.interface.encodeFunctionData('approve', [approvalReceipent, 100000n])
      const txWithGuard = await execTransaction(
        owners,
        safe,
        erc20TokenAddress,
        0n,
        calldataApproveThird,
        SafeOperation.Call
      )

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
      await execTransaction(owners, safe, token.target, 0n, calldataTransferFirst, SafeOperation.Call)

      const calldataTransferSecond = token.interface.encodeFunctionData('transfer', [await bob.getAddress(), 1n])
      const txWithoutGuard = await execTransaction(
        owners,
        safe,
        token.target,
        0n,
        calldataTransferSecond,
        SafeOperation.Call
      )
      await logGasUsage(txWithoutGuard, 'Tx without guard')

      const callData = safe.interface.encodeFunctionData('setGuard', [safePolicyGuard.target])
      const txEnableGuard = await execTransaction(owners, safe, safe.target, 0n, callData, SafeOperation.Call)
      await logGasUsage(txEnableGuard, 'Set guard')

      const erc20Interface = new ethers.Interface(IERC20Artifact.abi)
      const selector = erc20Interface.getFunction('transfer').selector

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
      const txRequest = await execTransaction(
        owners,
        safe,
        safePolicyGuard.target,
        0n,
        requestPolicyConfiguration,
        SafeOperation.Call
      )
      await logGasUsage(txRequest, 'Request configuration')

      await mine(13, { interval: DELAY * 60n })

      const applyPolicyConfiguration = safePolicyGuard.interface.encodeFunctionData('applyConfiguration', [
        configurations
      ])
      const txApply = await execTransaction(
        owners,
        safe,
        safePolicyGuard.target,
        0n,
        applyPolicyConfiguration,
        SafeOperation.Call
      )
      await logGasUsage(txApply, 'Apply configuration')

      const calldataTransferThird = token.interface.encodeFunctionData('transfer', [await bob.getAddress(), 1n])
      const txWithGuard = await execTransaction(
        owners,
        safe,
        erc20TokenAddress,
        0n,
        calldataTransferThird,
        SafeOperation.Call
      )

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
      await execTransaction(owners, safe, ZeroAddress, 0n, '0x', SafeOperation.Call)

      await alice.sendTransaction({
        to: safe.target,
        value: ethers.parseEther('3')
      })

      const txWithoutGuard = await execTransaction(owners, safe, recipientAddress, amount, '0x', SafeOperation.Call)
      await logGasUsage(txWithoutGuard, 'Tx without guard')

      const callData = safe.interface.encodeFunctionData('setGuard', [safePolicyGuard.target])
      const txEnableGuard = await execTransaction(owners, safe, safe.target, 0n, callData, SafeOperation.Call)
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
      const txRequest = await execTransaction(
        owners,
        safe,
        safePolicyGuard.target,
        0n,
        requestPolicyConfiguration,
        SafeOperation.Call
      )
      await logGasUsage(txRequest, 'Request configuration')

      await mine(13, { interval: DELAY * 60n })

      const applyPolicyConfiguration = safePolicyGuard.interface.encodeFunctionData('applyConfiguration', [
        configurations
      ])
      const txApply = await execTransaction(
        owners,
        safe,
        safePolicyGuard.target,
        0n,
        applyPolicyConfiguration,
        SafeOperation.Call
      )
      await logGasUsage(txApply, 'Apply configuration')

      const txWithGuard = await execTransaction(owners, safe, recipientAddress, amount, '0x', SafeOperation.Call)

      await logGasUsage(txWithGuard, 'Tx with guard')
      await logGasDiff(txWithoutGuard, txWithGuard)
    })
  })
})
