import SafeArtifact from '@safe-global/safe-smart-account/build/artifacts/contracts/Safe.sol/Safe.json'
import CompatibilityFallbackHandlerArtifact from '@safe-global/safe-smart-account/build/artifacts/contracts/handler/CompatibilityFallbackHandler.sol/CompatibilityFallbackHandler.json'
import MultiSendArtifact from '@safe-global/safe-smart-account/build/artifacts/contracts/libraries/MultiSend.sol/MultiSend.json'
import SafeProxyFactoryArtifact from '@safe-global/safe-smart-account/build/artifacts/contracts/proxies/SafeProxyFactory.sol/SafeProxyFactory.json'
import type { Contract } from 'ethers'
import { ethers } from 'hardhat'

import { Safe, SafeProxyFactory } from '../../typechain-types'
import { deterministicDeployment } from './util/create2'

async function deployArtifact({ abi, bytecode }: { abi: any[]; bytecode: string }, args: unknown[] = []) {
  const factory = await ethers.getContractFactory(abi, bytecode)
  return (await deterministicDeployment(factory, args)) as Contract
}

export async function deploy() {
  const safe = (await deployArtifact(SafeArtifact)) as unknown as Safe
  const compatibilityFallbackHandler = await deployArtifact(CompatibilityFallbackHandlerArtifact)
  const multiSend = await deployArtifact(MultiSendArtifact)
  const safeProxyFactory = (await deployArtifact(SafeProxyFactoryArtifact)) as unknown as SafeProxyFactory

  return {
    safe,
    compatibilityFallbackHandler,
    multiSend,
    safeProxyFactory
  }
}
