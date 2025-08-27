/**
 * Safe Connection Management Hook
 *
 * This hook manages the connection to Safe wallets and determines the appropriate
 * Policy Engine contract address based on the current chain.
 *
 * Features:
 * - Automatic Safe connection detection
 * - Connection error handling
 * - Real-time connection state updates
 *
 * Supported Chains:
 * - Gnosis Chain (100)
 * - Ethereum Sepolia (11155111)
 * - Base Sepolia (84532)
 *
 * @returns Object containing Safe info, SDK instance, Policy Engine address, and connection state
 */

import { useCallback, useEffect, useState } from 'react'
import { useSafeAppsSDK } from '@safe-global/safe-apps-react-sdk'
import { POLICY_ENGINE_ADDRESS, SUPPORTED_CHAINS } from '../utils/constants'

/**
 * Custom hook to manage Safe connection and Policy Engine address selection
 * @returns Object containing safe connection state and policyEngine address
 */
export const useSafeConnection = () => {
  const [policyEngineAddress, setPolicyEngineAddress] = useState<string>()
  const [isConnected, setIsConnected] = useState(false)
  const [error, setError] = useState<string | null>(null)

  const { safe, connected, sdk } = useSafeAppsSDK()

  /**
   * Only supports specific chains where Policy Engine is deployed
   */
  const selectPolicyEngineAddress = useCallback(async () => {
    try {
      const chainId = (await sdk.safe.getInfo()).chainId
      if (SUPPORTED_CHAINS.includes(chainId)) {
        setPolicyEngineAddress(POLICY_ENGINE_ADDRESS)
      } else {
        setError('Policy Engine not available in this chain')
        return
      }
      setError(null)
    } catch (err) {
      setError('Failed to get chain information: ' + err)
    }
  }, [sdk.safe])

  useEffect(() => {
    if (connected && safe) {
      setIsConnected(true)
      selectPolicyEngineAddress()
    } else {
      setIsConnected(false)
      // Not setting error message here, as we handle it in the App component
    }
  }, [connected, safe, selectPolicyEngineAddress])

  return {
    safe,
    sdk,
    policyEngineAddress,
    isConnected,
    error,
  }
}
