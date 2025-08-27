/**
 * Helper Utilities for Policy Engine Safe App
 *
 * This file contains utility functions for interacting with the Policy Engine
 * protocol and Safe contracts. These functions handle common operations like
 * contract calls, data encoding/decoding, and address resolution.
 *
 * Key Functions:
 * - call(): Universal contract interaction function
 * - encodeData() / decodeData(): ABI encoding/decoding helpers
 * - getAddressName(): Human-readable address names
 * - decodeSelector(): Function selector to name mapping
 * - getCosignerAddress(): Environment-based cosigner address retrieval
 */

import { ethers, type AddressLike } from 'ethers'
import type SafeAppsSDK from '@safe-global/safe-apps-sdk'
import {
  ADDRESS_NAME,
  ALLOW_POLICY_ADDRESS,
  ALLOWED_MODULE_POLICY_ADDRESS,
  CONTRACT_INTERFACE,
  COSIGNER_POLICY_ADDRESS,
  ERC20_APPROVE_POLICY_ADDRESS,
  ERC20_TRANSFER_POLICY_ADDRESS,
  MULTISEND_POLICY_ADDRESS,
  NATIVE_TRANSFER_POLICY_ADDRESS,
  SELECTOR_NAME,
} from './constants'
import type { BytesLike } from 'ethers'

/**
 * Get human-readable name for known addresses
 *
 * @param address - Address to resolve name for
 * @param safeAddress - Safe address for special handling
 * @returns Human-readable name or null if unknown
 */
export function getAddressName(
  address: AddressLike,
  safeAddress?: string
): string | null {
  const entry = ADDRESS_NAME.find(entry => entry.address === address)
  return entry
    ? entry.name
    : safeAddress && address === safeAddress
      ? 'This Safe'
      : null
}

/**
 * Decodes a function selector to its human-readable name
 * @param selector - 4-byte function selector (e.g., "0x12345678")
 * @returns Human-readable function name or the selector if unknown
 */
export function decodeSelector(selector: string): string {
  const entry = SELECTOR_NAME.find(entry => entry.selector === selector)
  return entry ? entry.name : String(selector)
}

/**
 * Decodes policy configuration data into human-readable format
 * @param policy - Policy contract address
 * @param data - Encoded policy configuration data
 * @returns Human-readable string representation of the policy data
 */
export function decodeData(policy: AddressLike, data: BytesLike): string {
  if (
    policy == ALLOWED_MODULE_POLICY_ADDRESS ||
    policy == COSIGNER_POLICY_ADDRESS
  ) {
    return String(ethers.AbiCoder.defaultAbiCoder().decode(['address'], data))
  }
  if (
    policy == ERC20_APPROVE_POLICY_ADDRESS ||
    policy == ERC20_TRANSFER_POLICY_ADDRESS
  ) {
    let readableData = ''
    const decoded = ethers.AbiCoder.defaultAbiCoder().decode(
      ['tuple(address,bool)[]'],
      data
    )[0]
    for (const item of decoded) {
      if (item[1] === true) {
        readableData += item[0] + '\n'
      }
    }
    return readableData
  }
  if (
    policy == ALLOW_POLICY_ADDRESS ||
    policy == MULTISEND_POLICY_ADDRESS ||
    policy == NATIVE_TRANSFER_POLICY_ADDRESS
  ) {
    return '-'
  }
  return String(data)
}

/**
 * Encodes policy configuration data for contract interaction
 * @param policy - Policy contract address
 * @param data - Raw policy configuration data
 * @returns Encoded data ready for contract submission
 */
export function encodeData(
  policy: AddressLike,
  data: BytesLike | undefined
): BytesLike | undefined {
  let encodedData = data
  if (
    ethers.getAddress(String(policy)) === ALLOWED_MODULE_POLICY_ADDRESS ||
    ethers.getAddress(String(policy)) === COSIGNER_POLICY_ADDRESS
  ) {
    encodedData = ethers.AbiCoder.defaultAbiCoder().encode(
      ['address'],
      [ethers.getAddress(String(data))]
    )
  } else if (
    ethers.getAddress(String(policy)) === ERC20_APPROVE_POLICY_ADDRESS ||
    ethers.getAddress(String(policy)) === ERC20_TRANSFER_POLICY_ADDRESS
  ) {
    // Parse multiple address:bool pairs separated by commas
    // Format: "address1:bool1,address2:bool2,address3:bool3"
    const pairs = String(data)
      .split(',')
      .map(pair => {
        const [address, boolStr] = pair.split(':')
        return [ethers.getAddress(address.trim()), boolStr.trim() === 'true']
      })

    encodedData = ethers.AbiCoder.defaultAbiCoder().encode(
      ['tuple(address,bool)[]'],
      [pairs]
    )
  }
  return encodedData
}

/**
 * Makes a contract call using the Safe Apps SDK
 * @param sdk - Safe Apps SDK instance for making the call
 * @param address - Contract address to call
 * @param method - Contract method name to invoke
 * @param params - Array of parameters for the method call
 * @param returnArray - Whether to return the full result array or just the first element
 * @returns Promise resolving to the decoded contract call result
 */
export const call = async (
  sdk: SafeAppsSDK,
  address: string,
  method: string,
  params: unknown[],
  returnArray: boolean = false
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
): Promise<any> => {
  const resp = await sdk.eth.call([
    {
      to: address,
      data: CONTRACT_INTERFACE.encodeFunctionData(method, params),
    },
  ])
  if (returnArray) {
    return CONTRACT_INTERFACE.decodeFunctionResult(method, resp)
  } else {
    return CONTRACT_INTERFACE.decodeFunctionResult(method, resp)[0]
  }
}

/**
 * Get cosigner address from environment variables
 * @returns Cosigner address from VITE_COSIGNER_ADDRESS or zero address as fallback
 */
export function getCosignerAddress(): string {
  const envAddress = import.meta.env.VITE_COSIGNER_ADDRESS
  if (!envAddress) {
    console.warn('VITE_COSIGNER_ADDRESS not configured, using zero address')
    return ethers.ZeroAddress
  }
  try {
    return ethers.getAddress(envAddress)
  } catch {
    console.error('Invalid VITE_COSIGNER_ADDRESS format:', envAddress)
    return ethers.ZeroAddress
  }
}
