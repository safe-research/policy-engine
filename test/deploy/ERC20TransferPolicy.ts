import { ContractRunner } from 'ethers'
import { ethers } from 'hardhat'

import { ERC20TransferPolicy } from '../../typechain-types'
import { deterministicDeployment } from './util/create2'

export type DeployOptions =
  | {
      runner?: ContractRunner
    }
  | undefined

export async function deploy({ runner }: DeployOptions = {}) {
  const erc20TransferPolicyFactory = await ethers.getContractFactory('ERC20TransferPolicy')
  const factory = runner ? erc20TransferPolicyFactory.connect(runner) : erc20TransferPolicyFactory
  const erc20TransferPolicy = (await deterministicDeployment(factory, [])) as unknown as ERC20TransferPolicy

  return {
    erc20TransferPolicy
  }
}
