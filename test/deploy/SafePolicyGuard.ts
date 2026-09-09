import { ContractRunner } from 'ethers'
import { ethers } from 'hardhat'

import { ONE_DAY_IN_SECONDS, SEVEN_DAYS_IN_SECONDS } from '../../lib/constants'
import { SafePolicyGuard } from '../../typechain-types'
import { deterministicDeployment } from './util/create2'

export type DeployOptions =
  | {
      delay?: bigint
      expiry?: bigint
      runner?: ContractRunner
    }
  | undefined

/**
 * @dev The expiry default is deliberately not the delay default. Equal values would let the two
 *      constructor arguments be transposed without any test noticing.
 */
export async function deploy({ delay, expiry, runner }: DeployOptions = {}) {
  // Defaults declared once. Stating them in the parameter object as well would mean the two
  // could disagree, with the behaviour depending on whether the caller passed an options object.
  delay = delay ?? SEVEN_DAYS_IN_SECONDS
  expiry = expiry ?? ONE_DAY_IN_SECONDS

  const safePolicyGuardFactory = await ethers.getContractFactory('SafePolicyGuard')
  const factory = runner ? safePolicyGuardFactory.connect(runner) : safePolicyGuardFactory
  const safePolicyGuard = (await deterministicDeployment(factory, [delay, expiry])) as unknown as SafePolicyGuard

  return {
    options: { delay, expiry },
    safePolicyGuard
  }
}
