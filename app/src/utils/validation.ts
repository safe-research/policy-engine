import { ethers } from 'ethers'

/**
 * Validates if a string is a valid Ethereum address
 * @param address - The address string to validate
 * @returns true if valid, false otherwise
 */
export const isValidAddress = (address: string): boolean => {
  try {
    ethers.getAddress(address)
    return true
  } catch {
    return false
  }
}

/**
 * Validates if a function selector is properly formatted
 * @param selector - The function selector to validate
 * @returns object with isValid boolean and error message if invalid
 */
export const validateSelector = (
  selector: string
): { isValid: boolean; error?: string } => {
  if (!selector) {
    return { isValid: true } // Empty selector is allowed (defaults to 0x00000000)
  }

  if (!selector.startsWith('0x')) {
    return { isValid: false, error: 'Selector must start with 0x' }
  }

  if (selector.length !== 10) {
    return {
      isValid: false,
      error: 'Selector must be 4 bytes (8 hex characters plus 0x prefix)',
    }
  }

  if (!/^0x[0-9a-fA-F]{8}$/.test(selector)) {
    return {
      isValid: false,
      error: 'Selector must contain only valid hexadecimal characters',
    }
  }

  return { isValid: true }
}

/**
 * Validates if an operation value is valid (0 for Call, 1 for DelegateCall)
 * @param operation - The operation number to validate
 * @returns true if valid, false otherwise
 */
export const isValidOperation = (operation: number): boolean => {
  return operation === 0 || operation === 1
}
