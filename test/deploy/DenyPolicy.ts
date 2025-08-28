import { ContractRunner } from 'ethers'
import { ethers } from 'hardhat'

import { DenyPolicy } from '../../typechain-types'
import { deterministicDeployment } from './util/create2'

export type DeployOptions =
  | {
      runner?: ContractRunner
    }
  | undefined

export async function deploy({ runner }: DeployOptions = {}) {
  const denyPolicyFactory = await ethers.getContractFactory('DenyPolicy')
  const factory = runner ? denyPolicyFactory.connect(runner) : denyPolicyFactory
  const denyPolicy = (await deterministicDeployment(factory, [])) as unknown as DenyPolicy

  return {
    denyPolicy
  }
}
