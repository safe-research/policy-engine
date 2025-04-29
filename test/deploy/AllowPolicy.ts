import { ContractRunner } from 'ethers'
import { ethers } from 'hardhat'

import { AllowPolicy } from '../../typechain-types'
import { deterministicDeployment } from './util/create2'

export type DeployOptions =
  | {
      runner?: ContractRunner
    }
  | undefined

export async function deploy({ runner }: DeployOptions = {}) {
  const allowPolicyFactory = await ethers.getContractFactory('AllowPolicy')
  const factory = runner ? allowPolicyFactory.connect(runner) : allowPolicyFactory
  const allowPolicy = (await deterministicDeployment(factory, [])) as unknown as AllowPolicy

  return {
    allowPolicy
  }
}
