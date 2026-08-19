import { ContractRunner } from 'ethers'
import { ethers } from 'hardhat'

import { OneTimeAllowPolicy } from '../../typechain-types'
import { deterministicDeployment } from './util/create2'

export type DeployOptions =
  | {
      runner?: ContractRunner
    }
  | undefined

export async function deploy({ runner }: DeployOptions = {}) {
  const oneTimeAllowPolicyFactory = await ethers.getContractFactory('OneTimeAllowPolicy')
  const factory = runner ? oneTimeAllowPolicyFactory.connect(runner) : oneTimeAllowPolicyFactory
  const oneTimeAllowPolicy = (await deterministicDeployment(factory, [])) as unknown as OneTimeAllowPolicy

  return {
    oneTimeAllowPolicy
  }
}
