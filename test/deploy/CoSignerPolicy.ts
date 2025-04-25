import { ContractRunner } from 'ethers'
import { ethers } from 'hardhat'

import { CoSignerPolicy } from '../../typechain-types'
import { deterministicDeployment } from './util/create2'

export type DeployOptions =
  | {
      runner?: ContractRunner
    }
  | undefined

export async function deploy({ runner }: DeployOptions = {}) {
  const coSignerPolicyFactory = await ethers.getContractFactory('CoSignerPolicy')
  const factory = runner ? coSignerPolicyFactory.connect(runner) : coSignerPolicyFactory
  const coSignerPolicy = (await deterministicDeployment(factory, [])) as unknown as CoSignerPolicy

  return {
    coSignerPolicy
  }
}
