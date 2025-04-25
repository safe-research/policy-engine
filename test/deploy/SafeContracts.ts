import SafeArtifact from '@safe-global/safe-contracts/build/artifacts/contracts/Safe.sol/Safe.json'
import SafeL2Artifact from '@safe-global/safe-contracts/build/artifacts/contracts/SafeL2.sol/SafeL2.json'
import SimulateTxAccessorArtifact from '@safe-global/safe-contracts/build/artifacts/contracts/accessors/SimulateTxAccessor.sol/SimulateTxAccessor.json'
import CompatibilityFallbackHandlerArtifact from '@safe-global/safe-contracts/build/artifacts/contracts/handler/CompatibilityFallbackHandler.sol/CompatibilityFallbackHandler.json'
import CreateCallArtifact from '@safe-global/safe-contracts/build/artifacts/contracts/libraries/CreateCall.sol/CreateCall.json'
import MultiSendArtifact from '@safe-global/safe-contracts/build/artifacts/contracts/libraries/MultiSend.sol/MultiSend.json'
import MultiSendCallOnlyArtifact from '@safe-global/safe-contracts/build/artifacts/contracts/libraries/MultiSendCallOnly.sol/MultiSendCallOnly.json'
import SafeMigrationArtifact from '@safe-global/safe-contracts/build/artifacts/contracts/libraries/SafeMigration.sol/SafeMigration.json'
import SafeToL2MigrationArtifact from '@safe-global/safe-contracts/build/artifacts/contracts/libraries/SafeToL2Migration.sol/SafeToL2Migration.json'
import SafeToL2SetupArtifact from '@safe-global/safe-contracts/build/artifacts/contracts/libraries/SafeToL2Setup.sol/SafeToL2Setup.json'
import SignMessageLibArtifact from '@safe-global/safe-contracts/build/artifacts/contracts/libraries/SignMessageLib.sol/SignMessageLib.json'
import SafeProxyFactoryArtifact from '@safe-global/safe-contracts/build/artifacts/contracts/proxies/SafeProxyFactory.sol/SafeProxyFactory.json'
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
  const safeL2 = await deployArtifact(SafeL2Artifact)
  const simulateTxAccessor = await deployArtifact(SimulateTxAccessorArtifact)
  const compatibilityFallbackHandler = await deployArtifact(CompatibilityFallbackHandlerArtifact)
  const createCall = await deployArtifact(CreateCallArtifact)
  const multiSend = await deployArtifact(MultiSendArtifact)
  const multiSendCallOnly = await deployArtifact(MultiSendCallOnlyArtifact)
  const safeMigration = await deployArtifact(SafeMigrationArtifact, [
    safe.target,
    safeL2.target,
    compatibilityFallbackHandler.target
  ])
  const safeToL2Migration = await deployArtifact(SafeToL2MigrationArtifact)
  const safeToL2Setup = await deployArtifact(SafeToL2SetupArtifact)
  const signMessageLib = await deployArtifact(SignMessageLibArtifact)
  const safeProxyFactory = (await deployArtifact(SafeProxyFactoryArtifact)) as unknown as SafeProxyFactory

  return {
    safe,
    safeL2,
    simulateTxAccessor,
    compatibilityFallbackHandler,
    createCall,
    multiSend,
    multiSendCallOnly,
    safeMigration,
    safeToL2Migration,
    safeToL2Setup,
    signMessageLib,
    safeProxyFactory
  }
}
