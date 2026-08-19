import { ContractRunner } from 'ethers'
import { ethers } from 'hardhat'

import { SafenetPolicy } from '../../typechain-types'
import { Point } from '../utils/frost'
import { deterministicDeployment } from './util/create2'

export type DeployOptions = {
  consensusChainId: bigint
  consensusAddress: string
  initialEpoch: bigint
  initialGroupKey: Point
  runner?: ContractRunner
}

export async function deploy({
  consensusChainId,
  consensusAddress,
  initialEpoch,
  initialGroupKey,
  runner
}: DeployOptions) {
  const safenetPolicyFactory = await ethers.getContractFactory('SafenetPolicy')
  const factory = runner ? safenetPolicyFactory.connect(runner) : safenetPolicyFactory
  const safenetPolicy = (await deterministicDeployment(factory, [
    consensusChainId,
    consensusAddress,
    initialEpoch,
    initialGroupKey
  ])) as unknown as SafenetPolicy

  return {
    safenetPolicy
  }
}
