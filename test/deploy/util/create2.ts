import { getSingletonFactoryInfo } from '@safe-global/safe-singleton-factory'
import type { BytesLike, ContractFactory, Overrides, TransactionResponseParams } from 'ethers'
import { ethers } from 'hardhat'

type TypedContractFactory<ArgsT extends any[], ContractT> = ContractFactory & {
  deploy(...args: ArgsT): Promise<ContractT>
}
type Head<T extends any[]> = Required<T> extends [...infer Head, any] ? Head : any[]

export async function deterministicDeployment<ArgsT extends any[], ContractT>(
  contractFactory: TypedContractFactory<ArgsT, ContractT>,
  args: Head<ArgsT>,
  overrides?: Overrides & { salt: BytesLike }
): Promise<ContractT> {
  const [defaultRunner] = await ethers.getSigners()
  const runner = contractFactory.runner ?? defaultRunner
  if (runner?.sendTransaction === undefined) {
    throw new Error('runner does not support sending transactions')
  }
  const provider = runner.provider
  if (!provider) {
    throw new Error('provider not found')
  }

  const { chainId } = await provider.getNetwork()
  const factory = getSingletonFactoryInfo(Number(chainId))
  if (factory === undefined) {
    throw new Error(`singleton factory not available on chain ${chainId}`)
  }

  const factoryCode = await provider.getCode(factory.address)
  if (ethers.dataLength(factoryCode) === 0) {
    const factoryPrefund = await runner.sendTransaction({
      to: factory.signerAddress,
      value: BigInt(factory.gasLimit) * BigInt(factory.gasPrice)
    })
    await factoryPrefund.wait()
    if (!('send' in provider)) {
      throw new Error('provider does not support sending JSON-RPC requests')
    }

    const factoryDeploymentTxHash = await provider.send('eth_sendRawTransaction', [factory.transaction])
    const factoryDeployment = new ethers.TransactionResponse(
      {
        ...ethers.Transaction.from(factory.transaction),
        hash: factoryDeploymentTxHash
      } as unknown as TransactionResponseParams,
      ethers.provider
    )
    await factoryDeployment.wait()
  }

  const { salt, ...deploymentOverrides } = overrides ?? { salt: ethers.ZeroHash }
  const initCode = ethers.concat([contractFactory.bytecode, contractFactory.interface.encodeDeploy(args)])
  const contractAddress = ethers.getCreate2Address(factory.address, salt, ethers.keccak256(initCode))
  const contractCode = await provider.getCode(contractAddress)
  if (ethers.dataLength(contractCode) === 0) {
    const contractDeployment = await runner.sendTransaction({
      to: factory.address,
      data: ethers.concat([salt, initCode]),
      ...deploymentOverrides
    })
    await contractDeployment.wait()
  }

  return new ethers.BaseContract(contractAddress, contractFactory.interface, runner) as ContractT
}
