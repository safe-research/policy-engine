import { ZeroAddress } from 'ethers'
import { ethers } from 'hardhat'

import { createSafe } from '../src/utils'
import { deployMockPolicy, deploySafeContracts, deploySafePolicyGuard } from './deploy'

/**
 * A Safe with no guard installed, alongside the guard, a mock policy and an access-selector helper.
 * Shared by the `safePolicyGuard*` specs, which each cover one concern of the same contract.
 */
export async function safePolicyGuardFixture() {
  const [, owner, other] = await ethers.getSigners()

  const {
    safePolicyGuard,
    options: { delay }
  } = await deploySafePolicyGuard()

  const { safeProxyFactory, safe: safeSingleton } = await deploySafeContracts()
  const safe = await createSafe({
    owners: [owner],
    guard: ZeroAddress, // No guard at this point
    saltNonce: BigInt(0x1),
    safeProxyFactory,
    singleton: safeSingleton
  })

  const { mockPolicy } = await deployMockPolicy()

  const accessSelector = await (await ethers.getContractFactory('TestAccessSelector')).deploy()

  return { owner, other, safePolicyGuard, safe, delay, mockPolicy, accessSelector }
}
