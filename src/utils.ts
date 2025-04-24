import { AddressLike, ethers, Signer, TransactionResponse } from 'ethers'

import { ISafe } from '../typechain-types/contracts/interfaces/ISafe'

const { solidityPacked } = ethers
const ZeroAddress: `0x${string}` = ethers.ZeroAddress as `0x${string}`

export enum SafeOperation {
  Call = 0,
  DelegateCall = 1
}

async function preApprovedSignature(owner: AddressLike): Promise<string> {
  const ownerAddress = await ethers.resolveAddress(owner)
  return ethers.solidityPacked(['uint256', 'uint256', 'uint8'], [ownerAddress, 0, 1])
}

export async function getSafeTransactionHash(
  safe: ISafe,
  to: `0x${string}`,
  value: bigint,
  data: `0x${string}`,
  operation: SafeOperation,
  safeTxGas: bigint = 0n,
  baseGas: bigint = 0n,
  gasPrice: bigint = 0n,
  gasToken: `0x${string}` = ZeroAddress as `0x${string}`,
  refundReceiver: `0x${string}` = ZeroAddress as `0x${string}`
): Promise<string> {
  const nonce = BigInt(await safe.nonce())

  return await safe.getTransactionHash(
    to,
    value,
    data,
    operation,
    safeTxGas,
    baseGas,
    gasPrice,
    gasToken,
    refundReceiver,
    nonce
  )
}

export async function execTransaction(
  wallets: Signer[],
  safe: ISafe,
  to: `0x${string}`,
  value: bigint,
  data: `0x${string}`,
  operation: SafeOperation,
  safeTxGas: bigint = 0n,
  baseGas: bigint = 0n,
  gasPrice: bigint = 0n,
  gasToken: `0x${string}` = ZeroAddress,
  refundReceiver: `0x${string}` = ZeroAddress,
  additionalData: `0x${string}` = '0x',
  signingMethod: 'signMessage' | 'preApprovedSignature' = 'preApprovedSignature'
): Promise<TransactionResponse> {
  const nonce = BigInt(await safe.nonce())

  const transactionHash = await safe.getTransactionHash(
    to,
    value,
    data,
    operation,
    safeTxGas,
    baseGas,
    gasPrice,
    gasToken,
    refundReceiver,
    nonce
  )

  let signatureBytes: `0x${string}` = '0x'

  if (signingMethod === 'signMessage') {
    const bytesDataHash = ethers.getBytes(transactionHash)

    const sorted = await Promise.all(
      Array.from(wallets).map(async (wallet) => ({
        wallet,
        address: await wallet.getAddress()
      }))
    ).then((walletInfos) =>
      walletInfos
        .sort((a, b) => a.address.toLowerCase().localeCompare(b.address.toLowerCase(), 'en', { sensitivity: 'base' }))
        .map((info) => info.wallet)
    )

    for (let i = 0; i < sorted.length; i++) {
      const flatSig = (await sorted[i].signMessage(bytesDataHash)).replace(/1b$/, '1f').replace(/1c$/, '20')
      signatureBytes += flatSig.slice(2)
    }
  } else if (signingMethod === 'preApprovedSignature') {
    signatureBytes = (await preApprovedSignature(wallets[0])) as `0x${string}`
  } else {
    throw new Error('signing method not supported')
  }

  if (additionalData.length > 2) {
    signatureBytes = solidityPacked(
      ['bytes', 'bytes', 'uint256'],
      [signatureBytes, additionalData, (additionalData.length - 2) / 2]
    ) as `0x${string}`
  }

  return await safe
    .connect(wallets[0])
    .execTransaction(to, value, data, operation, safeTxGas, baseGas, gasPrice, gasToken, refundReceiver, signatureBytes)
}

export const EIP712_SAFE_MESSAGE_TYPE = {
  // "SafeMessage(bytes message)"
  SafeMessage: [{ type: 'bytes', name: 'message' }]
}

export async function calculateSafeMessageHash(safeAddress: string, message: string, chainId: number): Promise<string> {
  return ethers.TypedDataEncoder.hash({ verifyingContract: safeAddress, chainId }, EIP712_SAFE_MESSAGE_TYPE, {
    message
  })
}
