import { ethers, type AddressLike } from 'ethers'
import {
  ADDRESS_NAME,
  ALLOW_POLICY_ADDRESS,
  ALLOWED_MODULE_POLICY_ADDRESS,
  COSIGNER_POLICY_ADDRESS,
  ERC20_APPROVE_POLICY_ADDRESS,
  ERC20_TRANSFER_POLICY_ADDRESS,
  MULTISEND_POLICY_ADDRESS,
  NATIVE_TRANSFER_POLICY_ADDRESS,
  SELECTOR_NAME,
} from './constants'
import type { BytesLike } from 'ethers'

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

export function decodeSelector(selector: string): string {
  const entry = SELECTOR_NAME.find(entry => entry.selector === selector)
  return entry ? entry.name : String(selector)
}

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
