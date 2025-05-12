import { ContractRunner } from 'ethers'
import { ethers } from 'hardhat'

import { MultiSendPolicy } from '../../typechain-types'
import { deterministicDeployment } from './util/create2'

export type DeployOptions =
  | {
      runner?: ContractRunner
    }
  | undefined

export async function deploy({ runner }: DeployOptions = {}) {
  const multiSendPolicyFactory = await ethers.getContractFactory('MultiSendPolicy')
  const factory = runner ? multiSendPolicyFactory.connect(runner) : multiSendPolicyFactory
  const multiSendPolicy = (await deterministicDeployment(factory, [])) as unknown as MultiSendPolicy

  return {
    multiSendPolicy
  }
}
