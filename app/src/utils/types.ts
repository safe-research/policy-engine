/**
 * Type Definitions for Policy Engine Safe App
 *
 * This file contains all TypeScript type definitions used throughout the
 * Policy Engine application. These types ensure type safety and provide
 * clear data structures.
 *
 * Key Type Categories:
 * - Transaction metadata types (TxMeta)
 * - Form input types (FormData)
 * - API response types (AccessInfo, PendingConfiguration, etc.)
 */

import type { AddressLike, BytesLike } from 'ethers'

/**
 * Base transaction metadata interface
 * Contains the core information needed to identify and configure a transaction policy
 */
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
 * Extends TxMeta with optional data field for policy configuration
 */
export interface FormData extends TxMeta {
  /** Additional data to be passed to the policy for configuration */
  data?: BytesLike
}

/**
 * Access information returned from Policy Engine queries
 * Similar to TxMeta but with required data field
 */
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
