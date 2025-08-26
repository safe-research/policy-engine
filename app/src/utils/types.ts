/**
 * Type definitions for the Policy Engine app
 */

import type { AddressLike, BytesLike } from 'ethers'

export interface TxMeta {
  /** Target contract address for the transaction */
  target: AddressLike
  /** Function selector (4 bytes) - leave empty for value transfers */
  selector: string
  /** Operation type: 0 = Call, 1 = DelegateCall */
  operation: bigint
  /** Address of the policy to be applied */
  policy: AddressLike
}

/**
 * Form data for setting allowed transactions
 */
export interface FormData extends TxMeta {
  /** Additional data to be passed to the policy for configuration */
  data?: BytesLike
}

export interface AccessInfo extends TxMeta {
  /** Additional data passed to the policy */
  data: BytesLike
}

/**
 * Transaction information structure
 */
export interface PendingInfo extends AccessInfo {
  /** Timestamp when the configuration becomes active (in milliseconds) */
  activeFrom: bigint
}
