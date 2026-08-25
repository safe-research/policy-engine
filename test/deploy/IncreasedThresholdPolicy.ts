import { ContractRunner } from 'ethers'
import { ethers } from 'hardhat'

import { IncreasedThresholdPolicy } from '../../typechain-types'
import { deterministicDeployment } from './util/create2'

export type DeployOptions =
  | {
      runner?: ContractRunner
    }
  | undefined

export async function deploy({ runner }: DeployOptions = {}) {
  const increasedThresholdPolicyFactory = await ethers.getContractFactory('IncreasedThresholdPolicy')
  const factory = runner ? increasedThresholdPolicyFactory.connect(runner) : increasedThresholdPolicyFactory
  const increasedThresholdPolicy = (await deterministicDeployment(factory, [])) as unknown as IncreasedThresholdPolicy

  return {
    increasedThresholdPolicy
  }
}
