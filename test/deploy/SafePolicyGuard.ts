import { ContractRunner } from 'ethers'
import { ethers } from 'hardhat'

import { SEVEN_DAYS_IN_SECONDS } from '../../lib/constants'
import { SafePolicyGuard } from '../../typechain-types'
import { deterministicDeployment } from './util/create2'

export type DeployOptions =
  | {
      delay?: bigint
      runner?: ContractRunner
    }
  | undefined

export async function deploy({ delay, runner }: DeployOptions = { delay: SEVEN_DAYS_IN_SECONDS }) {
  delay = delay ?? SEVEN_DAYS_IN_SECONDS

  const safePolicyGuardFactory = await ethers.getContractFactory('SafePolicyGuard')
  const factory = runner ? safePolicyGuardFactory.connect(runner) : safePolicyGuardFactory
  const safePolicyGuard = (await deterministicDeployment(factory, [delay])) as unknown as SafePolicyGuard

  return {
    options: { delay },
    safePolicyGuard
  }
}
