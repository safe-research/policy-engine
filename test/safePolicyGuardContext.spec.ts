import { loadFixture } from '@nomicfoundation/hardhat-network-helpers'
import { expect } from 'chai'
import { ZeroAddress } from 'ethers'
import { ethers } from 'hardhat'

import {
  createConfiguration,
  enableGuard,
  execTransaction,
  POLICY_CONTEXT_TYPE_HASH,
  preApprovedSignature,
  randomAddress,
  SafeOperation
} from '../src/utils'
import { safePolicyGuardFixture as fixture } from './fixtures'

describe('SafePolicyGuard -- context decoding', function () {
  describe('Context decoding', function () {
    // Context rides in the Safe `signatures` tail as a `SignatureExtension` envelope:
    // [payload][uint256 payloadLength][bytes32 typeHash]. The terminal type hash is what keeps
    // unrelated signature data -- an EIP-1271 contract signature, say -- from being read as context.
    //
    // These assert on the context the guard actually handed the policy, rather than on a downstream
    // policy's verdict, because two different decodings can produce the same verdict.
    async function contextFixture() {
      const base = await loadFixture(fixture)
      const { owner, safe, safePolicyGuard } = base

      const recorder = await (await ethers.getContractFactory('ContextRecorderPolicy')).deploy()
      const target = randomAddress()

      await enableGuard({
        owner,
        safe,
        safePolicyGuard,
        configurations: [createConfiguration({ target, policy: await recorder.getAddress() })]
      })

      return { ...base, recorder, target }
    }

    it('Should treat signatures not ending in the type hash as carrying no context', async function () {
      const { owner, safe, recorder, target } = await contextFixture()

      // A raw 32-byte tail appended with NO envelope -- structurally what an EIP-1271 contract
      // signature's trailing data looks like. The value is deliberately small enough to be a
      // plausible length: the previous format read this final word as one and would have sliced 32
      // bytes of the signature out as context.
      const signatures = ethers.solidityPacked(['bytes', 'uint256'], [await preApprovedSignature(owner), 32n])

      await safe
        .connect(owner)
        .execTransaction(target, 0n, '0x', SafeOperation.Call, 0n, 0n, 0n, ZeroAddress, ZeroAddress, signatures)

      expect(await recorder.lastContext()).to.equal('0x')
    })

    it('Should decode the payload of a well-formed envelope', async function () {
      const { owner, safe, recorder, target } = await contextFixture()
      const payload = ethers.id('some policy context')

      await execTransaction({ owners: [owner], safe, to: target, additionalData: payload })

      expect(await recorder.lastContext()).to.equal(payload)
    })

    it('Should revert on a malformed envelope claiming the type hash', async function () {
      const { owner, safe, safePolicyGuard, target } = await contextFixture()

      // Terminal word is the type hash, but the declared payload length runs past the front of the
      // blob. Claiming the type and then being malformed is an error, not "no context".
      const signatures = ethers.solidityPacked(
        ['bytes', 'uint256', 'bytes32'],
        [await preApprovedSignature(owner), ethers.MaxUint256, POLICY_CONTEXT_TYPE_HASH]
      )

      await expect(
        safe
          .connect(owner)
          .execTransaction(target, 0n, '0x', SafeOperation.Call, 0n, 0n, 0n, ZeroAddress, ZeroAddress, signatures)
      ).to.be.revertedWithCustomError(safePolicyGuard, 'MalformedSignatureExtension')
    })
  })
})
