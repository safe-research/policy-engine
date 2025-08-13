import { ethers } from 'ethers'

/**
 * Policy Engine Smart Contract Configuration
 *
 * This file contains all the constants and configuration needed to interact
 * with the Policy Engine protocol across different networks.
 */

// ================================
// Contract Addresses
// ================================

/** Policy Engine contract address on Sepolia testnet */
export const POLICY_ENGINE_ADDRESS_SEPOLIA = ethers.getAddress('')

/** Policy Engine contract address on Gnosis Chain */
export const POLICY_ENGINE_ADDRESS_GNOSIS = ethers.getAddress('')

/** Safe MultiSendCallOnly contract address */
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
export const CONTRACT_INTERFACE_ABI = [
  // Safe Contract Functions
  'function setGuard(address guard)',
  'function getStorageAt(uint256 offset, uint256 length) public view returns (bytes memory)',

  // Policy Engine Core Functions
  'function configureImmediately(tuple(address target, bytes4 selector, uint8 operation, address policy, bytes memory data)[]) external',
  'function requestConfiguration(bytes32 configureRoot) public',
  'function complementRequestConfiguration(tuple(address target, bytes4 selector, uint8 operation, address policy, bytes memory data)[]) external',
  'function invalidateRoot(bytes32 configureRoot) public',
  'function applyConfiguration(tuple(address target, bytes4 selector, uint8 operation, address policy, bytes memory data)[]) external',

  // Policy Engine View Functions
  'function getConfigurations(bytes32 configureRoot) external view returns (tuple(address target, bytes4 selector, uint8 operation, address policy, bytes memory data)[] memory)',
  'function getConfigurationRoots(address safe) external view returns (bytes32[] memory)',

  // Other Functions
  'function multiSend(bytes memory transactions) public payable',
  'function decimals() public view returns (uint8)',
] as const

// ================================
// Time Constants
// ================================

/** Conversion factor from seconds to milliseconds */
export const MILLISECONDS_IN_SECOND = 1000n
