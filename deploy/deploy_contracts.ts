import { DeployFunction } from 'hardhat-deploy/types'
import { promises as fs } from 'node:fs'

const POLICIES_CONFIG_DELAY = process.env.POLICIES_CONFIG_DELAY ? parseInt(process.env.POLICIES_CONFIG_DELAY) : 3600n
const DEMO = process.env.DEMO ? process.env.DEMO === 'true' : false

type Networks = Record<string, Record<string, string>>

const deploy: DeployFunction = async function ({ run, getChainId, getNamedAccounts, deployments, network }) {
  const { deployer } = await getNamedAccounts()
  const chainId = await getChainId()

  let networks: Networks
  try {
    networks = JSON.parse(await fs.readFile('./networks.json', 'utf-8'))
  } catch {
    networks = {}
  }

  const deployContract = async (contract: string, args: unknown[] = []) => {
    const { address } = await deployments.deploy(contract, {
      from: deployer,
      args: args,
      log: true,
      deterministicDeployment: true
    })
    networks[chainId] = {
      ...networks[chainId],
      [contract]: address
    }

    // Verify contracts
    if (network.name !== 'hardhat' && network.name !== 'localhost' && process.env.ETHERSCAN_API_KEY) {
      try {
        await run('verify:verify', {
          address: address,
          constructorArguments: args
        })
      } catch (error) {
        console.error(`Verification failed for ${contract} at ${address}:`, error)
      }
    }
  }

  const recordNetworks = () => {
    const json = JSON.stringify(networks, null, 2) + '\n'
    return fs.writeFile('./networks.json', json, 'utf-8')
  }

  // Guard
  if (DEMO) {
    await deployContract('AppSafePolicyGuard', [POLICIES_CONFIG_DELAY])
  } else {
    await deployContract('SafePolicyGuard', [POLICIES_CONFIG_DELAY])
  }

  // Policies
  await deployContract('AllowPolicy')
  await deployContract('AllowedModulePolicy')
  await deployContract('CoSignerPolicy')
  await deployContract('ERC20ApprovePolicy')
  await deployContract('ERC20TransferPolicy')
  await deployContract('MultiSendPolicy')
  await deployContract('NativeTransferPolicy')

  // Record the deployments
  if (network.name !== 'hardhat') {
    await recordNetworks()
  }
}

deploy.tags = ['policies']

export default deploy
