import { ContractRunner } from 'ethers'
import { ethers } from 'hardhat'

import { AllowedModulePolicy } from '../../typechain-types'
import { deterministicDeployment } from './util/create2'

export type DeployOptions =
  | {
      runner?: ContractRunner
    }
  | undefined

export async function deploy({ runner }: DeployOptions = {}) {
  const allowedModulePolicyFactory = await ethers.getContractFactory('AllowedModulePolicy')
  const factory = runner ? allowedModulePolicyFactory.connect(runner) : allowedModulePolicyFactory
  const allowedModulePolicy = (await deterministicDeployment(factory, [])) as unknown as AllowedModulePolicy

  return {
    allowedModulePolicy
  }
}
