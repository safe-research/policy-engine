import { ContractRunner } from 'ethers'
import { ethers } from 'hardhat'

import { ERC20ApprovePolicy } from '../../typechain-types'
import { deterministicDeployment } from './util/create2'

export type DeployOptions =
  | {
      runner?: ContractRunner
    }
  | undefined

export async function deploy({ runner }: DeployOptions = {}) {
  const erc20ApprovePolicyFactory = await ethers.getContractFactory('ERC20ApprovePolicy')
  const factory = runner ? erc20ApprovePolicyFactory.connect(runner) : erc20ApprovePolicyFactory
  const erc20ApprovePolicy = (await deterministicDeployment(factory, [])) as unknown as ERC20ApprovePolicy

  return {
    erc20ApprovePolicy
  }
}
