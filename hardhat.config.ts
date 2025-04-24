import '@nomicfoundation/hardhat-ethers'
import '@nomicfoundation/hardhat-toolbox'
import { getSingletonFactoryInfo } from '@safe-global/safe-singleton-factory'
import 'dotenv/config'
import 'hardhat-deploy'
import { DeterministicDeploymentInfo } from 'hardhat-deploy/dist/types'
import { HardhatUserConfig, HttpNetworkUserConfig } from 'hardhat/types'

const { MNEMONIC, PK, ETHERSCAN_API_KEY, HARDHAT_GAS_REPORTER_ENABLED } = process.env

const DEFAULT_MNEMONIC = 'candy maple cake sugar pudding cream honey rich smooth crumble sweet treat'

const sharedNetworkConfig: HttpNetworkUserConfig = {}
if (PK) {
  sharedNetworkConfig.accounts = [PK]
} else {
  sharedNetworkConfig.accounts = {
    mnemonic: MNEMONIC || DEFAULT_MNEMONIC
  }
}

const deterministicDeployment = (chainId: string): DeterministicDeploymentInfo => {
  const info = getSingletonFactoryInfo(parseInt(chainId))
  if (!info) {
    throw new Error(`
      Safe factory not found for network ${chainId}. You can request a new deployment at https://github.com/safe-global/safe-singleton-factory.
    `)
  }
  return {
    factory: info.address,
    deployer: info.signerAddress,
    funding: String(BigInt(info.gasLimit) * BigInt(info.gasPrice)),
    signedTx: info.transaction
  }
}

const config: HardhatUserConfig = {
  solidity: {
    version: '0.8.28',
    settings: {
      optimizer: {
        enabled: true,
        runs: 1000000
      },
      viaIR: true
    }
  },
  networks: {
    sepolia: {
      ...sharedNetworkConfig,
      url: 'https://1rpc.io/sepolia'
    }
  },
  deterministicDeployment,
  gasReporter: {
    enabled: HARDHAT_GAS_REPORTER_ENABLED === 'true'
  },
  paths: {
    sources: 'contracts'
  },
  namedAccounts: {
    deployer: 0
  },
  etherscan: {
    apiKey: ETHERSCAN_API_KEY
  }
}

export default config
