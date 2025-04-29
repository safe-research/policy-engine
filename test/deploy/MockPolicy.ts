import { ContractRunner } from 'ethers'
import { ethers } from 'hardhat'

import { MockPolicy } from '../../typechain-types'
import { deterministicDeployment } from './util/create2'

export type DeployOptions =
  | {
      runner?: ContractRunner
    }
  | undefined

export async function deploy({ runner }: DeployOptions = {}) {
  const mockPolicyFactory = await ethers.getContractFactory('MockPolicy')
  const factory = runner ? mockPolicyFactory.connect(runner) : mockPolicyFactory
  const mockPolicy = (await deterministicDeployment(factory, [])) as unknown as MockPolicy

  return {
    mockPolicy
  }
}
