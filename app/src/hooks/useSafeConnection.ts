import { useCallback, useEffect, useState } from 'react'
import { useSafeAppsSDK } from '@safe-global/safe-apps-react-sdk'
import { POLICY_ENGINE_ADDRESS } from '../utils/constants'

/**
 * Custom hook to manage Safe connection and Policy Engine address selection
 * @returns Object containing safe connection state and policyEngine address
 */
export const useSafeConnection = () => {
  const [policyEngineAddress, setPolicyEngineAddress] = useState<string>()
  const [isConnected, setIsConnected] = useState(false)
  const [error, setError] = useState<string | null>(null)

  const { safe, connected, sdk } = useSafeAppsSDK()

  const selectPolicyEngineAddress = useCallback(async () => {
    try {
      const chainId = (await sdk.safe.getInfo()).chainId
      if (chainId === 100 || chainId === 11155111 || chainId === 84532) {
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
