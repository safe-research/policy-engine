import { ContractRunner } from 'ethers'
import { ethers } from 'hardhat'

import { TestERC20Token } from '../../typechain-types'
import { deterministicDeployment } from './util/create2'

export type DeployOptions =
  | {
      runner?: ContractRunner
    }
  | undefined

export async function deploy({ runner }: DeployOptions = {}) {
  const testERC20Token = await ethers.getContractFactory('TestERC20Token')
  const factory = runner ? testERC20Token.connect(runner) : testERC20Token
  const token = (await deterministicDeployment(factory, [])) as unknown as TestERC20Token

  return {
    token
  }
}
