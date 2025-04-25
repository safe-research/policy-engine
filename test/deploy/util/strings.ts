/**
 * Compares two strings and returns whether they are the same.
 * @param a - The first string to compare.
 * @param b - The second string to compare.
 * @param ignoreCase - Optional. Specifies whether the comparison should be case-insensitive. Default is true.
 * @returns True if the strings are the same, false otherwise.
 */
const sameString = (a: string, b: string, ignoreCase = true): boolean => {
  return ignoreCase ? a.toLowerCase() === b.toLowerCase() : a === b
}

/**
 * Checks if two hexadecimal strings are the same, ignoring case by default.
 * @param a - The first hexadecimal string.
 * @param b - The second hexadecimal string.
 * @param ignoreCase - Optional. If true, the comparison is case-insensitive. Default is true.
 * @returns True if the hexadecimal strings are the same, false otherwise.
 */
const sameHexString = (a: string, b: string, ignoreCase = true): boolean => {
  const normalized = (s: string) => s.toLowerCase().replace(/^0x/, '')
  return sameString(normalized(a), normalized(b), ignoreCase)
}

/**
 * Calculates the length of a hexadecimal string in bytes.
 * @param hexString - The hexadecimal string to calculate the length of.
 * @returns The length of the hexadecimal string in bytes.
 */
const hexStringLengthInBytes = (hexString: string): number => {
  const hasPrefix = hexString.startsWith('0x')
  const length = hexString.length

  return hasPrefix ? (length - 2) / 2 : length / 2
}

export { sameString, sameHexString, hexStringLengthInBytes }
