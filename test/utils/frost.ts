import { AbiCoder, concat, SigningKey, toBeHex, zeroPadValue } from 'ethers'
import { ethers } from 'hardhat'

import { TestFROST } from '../../typechain-types'

/** Order of the secp256k1 group. */
export const SECP256K1_N = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141n

export type Point = { x: bigint; y: bigint }
export type FrostSignature = { r: Point; z: bigint }

/**
 * The EIP-712 type hashes `ConsensusMessages` carries as precomputed literals. Derived here from
 * the type strings so a test asserts the literals rather than trusting them.
 */
export const DOMAIN_TYPEHASH = ethers.id('EIP712Domain(uint256 chainId,address verifyingContract)')
export const EPOCH_ROLLOVER_TYPEHASH = ethers.id(
  'EpochRollover(uint64 activeEpoch,uint64 proposedEpoch,uint64 rolloverBlock,uint256 groupKeyX,uint256 groupKeyY)'
)
export const TRANSACTION_PROPOSAL_TYPEHASH = ethers.id(
  'TransactionProposal(uint64 epoch,address oracle,bytes oracleData,bytes32 safeTxHash)'
)

const coder = AbiCoder.defaultAbiCoder()

/**
 * Multiplies the secp256k1 generator by `scalar`.
 * @dev `SigningKey.computePublicKey` is exactly scalar-base multiplication, so no curve library is
 *      needed beyond what ethers already bundles.
 */
export function pointFromScalar(scalar: bigint): Point {
  const uncompressed = SigningKey.computePublicKey(zeroPadValue(toBeHex(scalar), 32), false)
  return {
    x: BigInt(`0x${uncompressed.slice(4, 68)}`),
    y: BigInt(`0x${uncompressed.slice(68, 132)}`)
  }
}

/** Computes the Consensus EIP-712 domain separator. */
export function consensusDomainSeparator(chainId: bigint, verifyingContract: string): string {
  return ethers.keccak256(
    coder.encode(['bytes32', 'uint256', 'address'], [DOMAIN_TYPEHASH, chainId, verifyingContract])
  )
}

function eip712(domainSeparator: string, structHash: string): string {
  return ethers.keccak256(concat(['0x1901', domainSeparator, structHash]))
}

/** Rebuilds the `TransactionProposal` message the validator set attests to. */
export function transactionProposalMessage(
  domainSeparator: string,
  epoch: bigint,
  oracle: string,
  oracleDataHash: string,
  safeTxHash: string
): string {
  return eip712(
    domainSeparator,
    ethers.keccak256(
      coder.encode(
        ['bytes32', 'uint64', 'address', 'bytes32', 'bytes32'],
        [TRANSACTION_PROPOSAL_TYPEHASH, epoch, oracle, oracleDataHash, safeTxHash]
      )
    )
  )
}

/** Rebuilds the `EpochRollover` message a rollover is signed over. */
export function epochRolloverMessage(
  domainSeparator: string,
  activeEpoch: bigint,
  proposedEpoch: bigint,
  rolloverBlock: bigint,
  groupKey: Point
): string {
  return eip712(
    domainSeparator,
    ethers.keccak256(
      coder.encode(
        ['bytes32', 'uint64', 'uint64', 'uint64', 'uint256', 'uint256'],
        [EPOCH_ROLLOVER_TYPEHASH, activeEpoch, proposedEpoch, rolloverBlock, groupKey.x, groupKey.y]
      )
    )
  )
}

/**
 * Produces a FROST signature over `message` for the group key derived from `secret`.
 * @dev A single-participant FROST signature is a Schnorr signature: with `Y = x*G` and `R = k*G`,
 *      the verification equation `z*G == R + c*Y` is satisfied by `z = k + c*x mod n`. The
 *      challenge comes from the library itself via `TestFROST`, but verification independently
 *      recomputes it and checks the group equation, so an incorrect `z` is still rejected.
 */
export async function signFrost(
  testFrost: TestFROST,
  secret: bigint,
  nonce: bigint,
  message: string
): Promise<{ groupKey: Point; signature: FrostSignature }> {
  const groupKey = pointFromScalar(secret)
  const r = pointFromScalar(nonce)
  const challenge = await testFrost.challenge(r, groupKey, message)
  const z = (nonce + challenge * secret) % SECP256K1_N
  return { groupKey, signature: { r, z } }
}

/**
 * Encodes the attestation payload `SafenetPolicy` reads out of the policy context.
 * @dev Mirrors `AttestationTrailer`'s payload schema: eight static words, no offsets.
 */
export function encodeAttestation({
  epoch,
  oracle,
  oracleDataHash,
  groupKey,
  signature
}: {
  epoch: bigint
  oracle: string
  oracleDataHash: string
  groupKey: Point
  signature: FrostSignature
}): string {
  return coder.encode(
    ['uint64', 'address', 'bytes32', 'tuple(uint256 x, uint256 y)', 'tuple(tuple(uint256 x, uint256 y) r, uint256 z)'],
    [epoch, oracle, oracleDataHash, groupKey, signature]
  )
}
