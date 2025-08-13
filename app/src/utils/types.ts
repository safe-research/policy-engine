/**
 * Type definitions for the Policy Engine app
 */

/**
 * Form data for setting allowed transactions
 */
export interface SetConfigurationFormData {
  /** Target contract address for the transaction */
  to: string
  /** Function selector (4 bytes) - leave empty for value transfers */
  selector: string
  /** Operation type: 0 = Call, 1 = DelegateCall */
  operation: number
  /** Address of the policy to be applied */
  policy: string
  /** Additional data to be passed to the policy for configuration */
  data: string
}

/**
 * Transaction information structure
 */
export interface AllowedConfigurationInfo {
  /** Target contract address */
  to: string
  /** Function selector */
  selector: string
  /** Operation type as string */
  operation: string
  /** Address of the policy applied to this configuration */
  policy: string
  /** Additional data passed to the policy */
  data: string
  /** Timestamp when the configuration becomes active (in milliseconds) */
  activeFrom: bigint
}
