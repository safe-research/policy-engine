import { ContractRunner } from 'ethers'
import { ethers } from 'hardhat'

import { NativeTransferPolicy } from '../../typechain-types'
import { deterministicDeployment } from './util/create2'

export type DeployOptions =
  | {
      runner?: ContractRunner
    }
  | undefined

export async function deploy({ runner }: DeployOptions = {}) {
  const nativeTransferPolicyFactory = await ethers.getContractFactory('NativeTransferPolicy')
  const factory = runner ? nativeTransferPolicyFactory.connect(runner) : nativeTransferPolicyFactory
  const nativeTransferPolicy = (await deterministicDeployment(factory, [])) as unknown as NativeTransferPolicy

  return {
    nativeTransferPolicy
  }
}
