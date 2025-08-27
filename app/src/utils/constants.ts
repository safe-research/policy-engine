/**
 * Policy Engine Smart Contract Configuration
 *
 * This file contains all the constants and configuration needed to interact
 * with the Policy Engine protocol across different networks.
 *
 * Contents:
 * - Contract addresses for Policy Engine and all policy types
 * - Function selectors and storage slots
 * - ABI interfaces for contract interactions
 * - Network-specific configurations
 * - Time conversion constants
 *
 * Network Support:
 * - Gnosis Chain (mainnet)
 * - Ethereum Sepolia (testnet)
 * - Base Sepolia (testnet)
 *
 * Security Note:
 * All addresses are validated using ethers.getAddress() to ensure
 * proper checksum formatting and prevent address-related errors.
 */

import { ethers } from 'ethers'

/**
 * Supported blockchain networks for the Policy Engine Contracts
 */
export const SUPPORTED_CHAINS = [100, 11155111, 84532]

// ================================
// Contract Addresses
// ================================

/**
 * Core Policy Engine contract address
 * Deployed on supported networks with the same address
 */
export const POLICY_ENGINE_ADDRESS = ethers.getAddress(
  '0x1392AE18434d5040D032E29C9c900489d1d3Ba92'
)

/**
 * Allow Policy - Permits unrestricted access to specified functions
 */
export const ALLOW_POLICY_ADDRESS = ethers.getAddress(
  '0x3e40e32CE2BC4aFF4D1A9BE293C119ce4Fb52eAc'
)

/**
 * Allowed Module Policy - Controls which Safe modules can be used
 */
export const ALLOWED_MODULE_POLICY_ADDRESS = ethers.getAddress(
  '0x8d2fA07068F55a1934C6A4EdE1C460C3d7D50e4A'
)

/**
 * Cosigner Policy - Requires additional signature for transaction approval
 */
export const COSIGNER_POLICY_ADDRESS = ethers.getAddress(
  '0xC49f4786aF99b7c3Edf0A3F71E6B969B76302ca5'
)

/**
 * ERC20 Approve Policy - Controls ERC20 token approval operations
 */
export const ERC20_APPROVE_POLICY_ADDRESS = ethers.getAddress(
  '0x2382b4680C610788eD9b00046c0f7F979F195575'
)

/**
 * ERC20 Transfer Policy - Controls ERC20 transfer operations
 */
export const ERC20_TRANSFER_POLICY_ADDRESS = ethers.getAddress(
  '0xec399EE72199DBc1f7DCf8b69cFa0290d1e06Fb7'
)

/**
 * MultiSend Policy - Enables batch transaction execution
 */
export const MULTISEND_POLICY_ADDRESS = ethers.getAddress(
  '0x297127E77B51bB9E3F4a59E6b8Ac4d42f99CdAD5'
)

/**
 * Native Transfer Policy - Controls native transfer (ETH transfer) operations
 */
export const NATIVE_TRANSFER_POLICY_ADDRESS = ethers.getAddress(
  '0x77d29DEaE811D5E42fbe292d3f2729403e11cA3A'
)

/**
 * Safe MultiSendCallOnly v1.4.1 contract address
 */
export const MULTISEND_CALL_ONLY = ethers.getAddress(
  '0x9641d764fc13c8B624c04430C7356C1C7C8102e2'
)

// ================================
// Storage Slots
// ================================

/**
 * Storage slot for the transaction guard in Safe contracts
 * This slot contains the address of the current transaction guard
 */
export const GUARD_STORAGE_SLOT =
  '0x4a204f620c8c5ccdca3fd54d003badd85ba500436a431f0cbda4f558c93c34c8' as const

// ================================
// Contract Interface
// ================================

/**
 * ABI interface for interacting with Policy Engine and Safe contracts
 * Contains all necessary function signatures for the application
 */
const CONTRACT_INTERFACE_ABI = [
  // Safe Contract Functions
  'function setGuard(address guard)',
  'function getStorageAt(uint256 offset, uint256 length) public view returns (bytes memory)',

  // Policy Engine Core Functions
  'function configureImmediately(tuple(address target, bytes4 selector, uint8 operation, address policy, bytes memory data)[]) external',
  'function requestConfiguration(bytes32 configureRoot) public',
  'function complementRequestConfiguration(tuple(address target, bytes4 selector, uint8 operation, address policy, bytes memory data)[] calldata) external',
  'function invalidateRoot(bytes32 configureRoot) public',
  'function applyConfiguration(tuple(address target, bytes4 selector, uint8 operation, address policy, bytes memory data)[]) external',

  // Policy Engine View Functions
  'function rootConfigured(address safe, bytes32 configureRoot) external view returns (uint256 timestamp)',
  'function getAccesses(address safe) external view returns (uint256[] memory)',
  'function getAccessInfo(address safe, uint256 access) external view returns (address target, bytes4 selector, uint8 operation, bytes memory data)',
  'function getPolicy(address safe, address to, bytes calldata data, uint8 operation) external view returns (uint256 accessSelector, address policy)',
  'function getConfigurations(bytes32 configureRoot) external view returns (tuple(address target, bytes4 selector, uint8 operation, address policy, bytes memory data)[] memory)',
  'function getConfigurationRoots(address safe) external view returns (bytes32[] memory)',

  // Other Functions
  'function multiSend(bytes memory transactions) public payable',
  'function decimals() public view returns (uint8)',
] as const

export const CONTRACT_INTERFACE = new ethers.Interface(CONTRACT_INTERFACE_ABI)

// ================================
// Time Constants
// ================================

/** Conversion factor from seconds to milliseconds */
export const MILLISECONDS_IN_SECOND = 1000n

/** Zero Selector */
export const ZERO_SELECTOR = '0x00000000' as const

/** List of known function selectors with their human-readable names */
export const ADDRESS_NAME = [
  { address: POLICY_ENGINE_ADDRESS, name: 'Policy Engine' },
  { address: ALLOW_POLICY_ADDRESS, name: 'Allow Policy' },
  { address: ALLOWED_MODULE_POLICY_ADDRESS, name: 'Allowed Module Policy' },
  { address: COSIGNER_POLICY_ADDRESS, name: 'Cosigner Policy' },
  { address: ERC20_APPROVE_POLICY_ADDRESS, name: 'ERC20 Approve Policy' },
  { address: ERC20_TRANSFER_POLICY_ADDRESS, name: 'ERC20 Transfer Policy' },
  { address: MULTISEND_POLICY_ADDRESS, name: 'MultiSend Policy' },
  { address: NATIVE_TRANSFER_POLICY_ADDRESS, name: 'Native Transfer Policy' },
  { address: MULTISEND_CALL_ONLY, name: 'MultiSendCallOnly v1.4.1' },
  { address: ethers.ZeroAddress, name: 'Zero Address' },
]

/** List of known function selectors with their human-readable names */
export const SELECTOR_NAME = [
  { selector: '0x00000000', name: 'Zero Selector' },
  { selector: '0x8d80ff0a', name: 'multiSend(bytes)' },
  { selector: '0xa9059cbb', name: 'transfer(address,uint256)' },
  { selector: '0x095ea7b3', name: 'approve(address,uint256)' },
  { selector: '0x23b872dd', name: 'transferFrom(address,address,uint256)' },
  { selector: '0xe19a9dd9', name: 'setGuard(address)' },
]
