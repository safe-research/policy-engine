import { useCallback, useEffect, useState } from 'react'
import './App.css'
import type { BaseTransaction } from '@safe-global/safe-apps-sdk'
import SafeAppsSDK, { Operation } from '@safe-global/safe-apps-sdk'
import { ethers, ZeroAddress } from 'ethers'
import Button from '@mui/material/Button'
import {
  Alert,
  Paper,
  Select,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  TextField,
} from '@mui/material'
import {
  ALLOW_POLICY_ADDRESS,
  ALLOWED_MODULE_POLICY_ADDRESS,
  CONTRACT_INTERFACE,
  COSIGNER_POLICY_ADDRESS,
  ERC20_APPROVE_POLICY_ADDRESS,
  ERC20_TRANSFER_POLICY_ADDRESS,
  GUARD_STORAGE_SLOT,
  MILLISECONDS_IN_SECOND,
  MULTISEND_CALL_ONLY,
  MULTISEND_POLICY_ADDRESS,
  NATIVE_TRANSFER_POLICY_ADDRESS,
  ZERO_SELECTOR,
} from './utils/constants'
import type { FormData, AccessInfo, PendingInfo } from './utils/types'
import {
  isValidAddress,
  validateSelector,
  isValidOperation,
} from './utils/validation'
import { useSafeConnection } from './hooks/useSafeConnection'
import {
  SafeResearchBanner,
  SafeResearchFooter,
} from './components/SafeResearch'
import {
  decodeData,
  decodeSelector,
  encodeData,
  getAddressName,
  getCosignerAddress,
} from './utils/helper'

const call = async (
  sdk: SafeAppsSDK,
  address: string,
  method: string,
  params: any[],
  returnArray: boolean = false
): Promise<any> => {
  const resp = await sdk.eth.call([
    {
      to: address,
      data: CONTRACT_INTERFACE.encodeFunctionData(method, params),
    },
  ])
  if (returnArray) {
    return CONTRACT_INTERFACE.decodeFunctionResult(method, resp)
  } else {
    return CONTRACT_INTERFACE.decodeFunctionResult(method, resp)[0]
  }
}

function App() {
  const [loading, setLoading] = useState(false)
  const [errorMessage, setErrorMessage] = useState<string | null>(null)
  const [txGuard, setTxGuard] = useState<string | null>(null)
  const [policyEngineInSafe, setPolicyEngineInSafe] = useState<boolean>(false)
  const [removalTimestamp, setRemovalTimestamp] = useState<bigint>(0n)
  const [currentPendingConfigurations, setCurrentPendingConfigurations] =
    useState<PendingInfo[]>([])
  const [allowedAccessesInfo, setAllowedAccessesInfo] = useState<AccessInfo[]>(
    []
  )

  // Use the custom hook for Safe connection management
  const {
    safe,
    sdk,
    policyEngineAddress,
    isConnected,
    error: connectionError,
  } = useSafeConnection()

  // Handle connection errors from the custom hook
  useEffect(() => {
    if (connectionError) {
      setErrorMessage(connectionError)
    } else {
      setErrorMessage(null)
    }
  }, [connectionError])

  // Fetch the transaction guard info
  const fetchTxGuardInfo = useCallback(async () => {
    setLoading(true)
    setErrorMessage(null)
    try {
      // Get the Tx Guard
      const result = ethers.getAddress(
        '0x' +
          (
            await call(sdk, safe.safeAddress, 'getStorageAt', [
              GUARD_STORAGE_SLOT,
              1,
            ])
          ).slice(26)
      )
      setTxGuard(result)
    } catch (error) {
      setErrorMessage('Failed to fetch transaction guard with error: ' + error)
    } finally {
      setLoading(false)
    }
  }, [safe.safeAddress, sdk])

  // Fetch the guard removal info
  const fetchGuardRemovalInfo = useCallback(async () => {
    setLoading(true)
    setErrorMessage(null)
    try {
      if (!policyEngineAddress) {
        setErrorMessage('Policy Engine address not available')
        setLoading(false)
        return
      }
      // Fetch all the configurations
      const configurationRoots = await call(
        sdk,
        policyEngineAddress,
        'getConfigurationRoots',
        [ethers.getAddress(safe.safeAddress)]
      )

      // Fetch the configurations of each configuration
      // Check if we have one with target is safe itself, selector is `setGuard`, operation is CALL and policy is `AllowPolicy`
      let removalRoot = null
      for (const root of configurationRoots) {
        const config: AccessInfo[] = await call(
          sdk,
          policyEngineAddress,
          'getConfigurations',
          [root]
        )
        if (
          ethers.getAddress(String(config[0].target)) ===
            ethers.getAddress(safe.safeAddress) &&
          config[0].selector ===
            CONTRACT_INTERFACE.getFunction('setGuard')?.selector &&
          config[0].operation === BigInt(Operation.CALL) &&
          ethers.getAddress(String(config[0].policy)) ===
            ethers.getAddress(ALLOW_POLICY_ADDRESS)
        ) {
          removalRoot = root
          break
        }
      }

      // If yes, we set the removal timestamp of the guard based on that.
      if (removalRoot != null) {
        const getRootTimestamp = await call(
          sdk,
          policyEngineAddress,
          'rootConfigured',
          [ethers.getAddress(safe.safeAddress), removalRoot]
        )
        if (getRootTimestamp && getRootTimestamp > 0n) {
          setRemovalTimestamp(BigInt(getRootTimestamp) * MILLISECONDS_IN_SECOND)
        }
      } else {
        const [, policy] = await call(
          sdk,
          policyEngineAddress,
          'getPolicy',
          [
            safe.safeAddress,
            safe.safeAddress,
            CONTRACT_INTERFACE.getFunction('setGuard')?.selector,
            Operation.CALL,
          ],
          true
        )
        if (ethers.getAddress(policy) === ALLOW_POLICY_ADDRESS) {
          setRemovalTimestamp(1n)
        }
      }
    } catch (error) {
      setErrorMessage('Failed to fetch guard removal info with error: ' + error)
    } finally {
      setLoading(false)
    }
  }, [policyEngineAddress, safe.safeAddress, sdk])

  // Fetch the current pending configurations
  const fetchCurrentPendingConfigurations = useCallback(async () => {
    setLoading(true)
    setErrorMessage(null)
    try {
      if (!policyEngineAddress) {
        setErrorMessage('Policy Engine address not available')
        setLoading(false)
        return
      }
      // Fetch all the configuration roots
      const configurationRoots = await call(
        sdk,
        policyEngineAddress,
        'getConfigurationRoots',
        [ethers.getAddress(safe.safeAddress)]
      )

      // Fetch the configurations of each configuration root
      const pendingConfigurations: PendingInfo[] = await Promise.all(
        configurationRoots.map(async (root: string) => {
          const config = (
            await call(sdk, policyEngineAddress, 'getConfigurations', [root])
          )[0]
          const timestamp = await call(
            sdk,
            policyEngineAddress,
            'rootConfigured',
            [ethers.getAddress(safe.safeAddress), root]
          )
          return {
            target: config.target,
            selector: config.selector,
            operation: BigInt(config.operation),
            policy: config.policy,
            data: config.data,
            activeFrom: timestamp * MILLISECONDS_IN_SECOND,
          }
        })
      )
      setCurrentPendingConfigurations(pendingConfigurations)
    } catch (error) {
      setErrorMessage(
        'Failed to fetch current pending configurations with error: ' + error
      )
    } finally {
      setLoading(false)
    }
  }, [policyEngineAddress, safe.safeAddress, sdk])

  // Fetch the current allowed accesses
  const fetchCurrentAllowedAccesses = useCallback(async () => {
    setLoading(true)
    setErrorMessage(null)
    try {
      if (!policyEngineAddress) {
        setErrorMessage('Policy Engine address not available')
        setLoading(false)
        return
      }
      // Fetch allowed accesses
      const accesses: bigint[] = await call(
        sdk,
        policyEngineAddress,
        'getAccesses',
        [ethers.getAddress(safe.safeAddress)]
      )
      // Fetch access info using getAccessInfo
      const accessInfos = await Promise.all(
        accesses.map(async (access: bigint) => {
          const [target, selector, operation, data] = await call(
            sdk,
            policyEngineAddress,
            'getAccessInfo',
            [ethers.getAddress(safe.safeAddress), access],
            true
          )
          return { access, target, selector, operation, data }
        })
      )
      // Fetch the policy from getPolicy with the info from previous round.
      const allowedAccesses: AccessInfo[] = await Promise.all(
        accessInfos.map(async ({ target, selector, operation, data }) => {
          // For getPolicy, we need to construct proper calldata that includes the selector
          const [, policy] = await call(
            sdk,
            policyEngineAddress,
            'getPolicy',
            [
              ethers.getAddress(safe.safeAddress),
              ethers.getAddress(target),
              selector,
              operation,
            ],
            true
          )
          return {
            target,
            selector,
            operation,
            policy,
            data,
          }
        })
      )
      setAllowedAccessesInfo(allowedAccesses)
    } catch (error) {
      setErrorMessage(
        'Failed to fetch current allowed accesses with error: ' + error
      )
    } finally {
      setLoading(false)
    }
  }, [policyEngineAddress, safe.safeAddress, sdk])

  // Fetch all necessary data when connected and policyEngineAddress is available
  useEffect(() => {
    if (isConnected && policyEngineAddress && safe?.safeAddress) {
      fetchTxGuardInfo()
      fetchGuardRemovalInfo()
      fetchCurrentAllowedAccesses()
      fetchCurrentPendingConfigurations()
    } else {
      setLoading(false)
    }
  }, [
    isConnected,
    policyEngineAddress,
    safe?.safeAddress,
    fetchTxGuardInfo,
    fetchGuardRemovalInfo,
    fetchCurrentAllowedAccesses,
    fetchCurrentPendingConfigurations,
  ])

  // Effect to determine if Policy Engine is in Safe
  useEffect(() => {
    if (txGuard && policyEngineAddress) {
      setPolicyEngineInSafe(txGuard === policyEngineAddress)
    } else {
      setPolicyEngineInSafe(false)
    }
  }, [txGuard, policyEngineAddress])

  // Activate or deactivate the Policy Engine
  const activatePolicyEngine = useCallback(
    async (activate: boolean) => {
      setLoading(true)
      setErrorMessage(null)
      if (!policyEngineAddress) {
        setErrorMessage('Policy Engine address not available')
        setLoading(false)
        return
      }
      const guardAddress = activate ? policyEngineAddress : ethers.ZeroAddress
      const setupConfigurations: FormData[] = [
        {
          // MultiSend
          target: ethers.getAddress(MULTISEND_CALL_ONLY),
          selector: CONTRACT_INTERFACE.getFunction('multiSend')?.selector || '',
          operation: BigInt(Operation.DELEGATE),
          policy: MULTISEND_POLICY_ADDRESS,
          data: '0x',
        },
        {
          // Fallback for CALL
          target: ethers.ZeroAddress,
          selector: ZERO_SELECTOR,
          operation: BigInt(Operation.CALL),
          policy: COSIGNER_POLICY_ADDRESS,
          data: ethers.AbiCoder.defaultAbiCoder().encode(
            ['address'],
            [getCosignerAddress()]
          ),
        },
        {
          // Removing `setGuard` from Allowed configuration if already set
          target: safe.safeAddress,
          selector: CONTRACT_INTERFACE.getFunction('setGuard')?.selector || '',
          operation: BigInt(Operation.CALL),
          policy: ZeroAddress,
          data: '0x',
        },
      ]
      const immediateConfiguration = {
        to: policyEngineAddress,
        value: '0',
        data: CONTRACT_INTERFACE.encodeFunctionData('configureImmediately', [
          setupConfigurations,
        ]),
      }
      try {
        const txs: BaseTransaction[] = [
          ...(activate ? [immediateConfiguration] : []),
          {
            to: safe.safeAddress,
            value: '0',
            data: CONTRACT_INTERFACE.encodeFunctionData('setGuard', [
              guardAddress,
            ]),
          },
        ]
        await sdk.txs.send({
          txs,
        })
      } catch (error) {
        setErrorMessage('Failed to submit transaction: ' + error)
      } finally {
        setLoading(false)
      }
    },
    [policyEngineAddress, safe.safeAddress, sdk.txs]
  )

  // Schedule Policy Engine removal
  const schedulePolicyEngineRemoval = useCallback(async () => {
    setLoading(true)
    setErrorMessage(null)
    if (!policyEngineAddress) {
      setErrorMessage('Policy Engine address not available')
      setLoading(false)
      return
    }
    const configurations: FormData[] = [
      {
        // Adding `setGuard` in Allowed configuration
        target: safe.safeAddress,
        selector: CONTRACT_INTERFACE.getFunction('setGuard')?.selector || '',
        operation: BigInt(Operation.CALL),
        policy: ALLOW_POLICY_ADDRESS,
        data: '0x',
      },
    ]

    try {
      const txs: BaseTransaction[] = [
        {
          to: policyEngineAddress,
          value: '0',
          data: CONTRACT_INTERFACE.encodeFunctionData('requestConfiguration', [
            ethers.keccak256(
              ethers.AbiCoder.defaultAbiCoder().encode(
                [
                  'tuple(address target, bytes4 selector, uint8 operation, address policy, bytes data)[]',
                ],
                [configurations]
              )
            ),
          ]),
        },
        {
          to: policyEngineAddress,
          value: '0',
          data: CONTRACT_INTERFACE.encodeFunctionData(
            'complementRequestConfiguration',
            [configurations]
          ),
        },
      ]
      await sdk.txs.send({
        txs,
      })
      await fetchGuardRemovalInfo()
    } catch (error) {
      setErrorMessage('Failed to schedule policy engine removal: ' + error)
    } finally {
      setLoading(false)
    }
  }, [fetchGuardRemovalInfo, policyEngineAddress, safe.safeAddress, sdk.txs])

  // Schedule allowed transactions
  const setAllowedTx = useCallback(
    async (formData: FormData) => {
      setLoading(true)
      setErrorMessage(null)

      if (!policyEngineAddress) {
        setErrorMessage('Policy Engine address not available')
        setLoading(false)
        return
      }

      // Validate 'target' address
      if (!isValidAddress(formData.target)) {
        setErrorMessage('Invalid "Target" address format')
        setLoading(false)
        return
      }

      // Validate selector
      const selectorValidation = validateSelector(formData.selector)
      if (!selectorValidation.isValid) {
        setErrorMessage(selectorValidation.error!)
        setLoading(false)
        return
      }

      // Validate operation
      if (!isValidOperation(formData.operation)) {
        setErrorMessage('Operation must be Call (0) or DelegateCall (1)')
        setLoading(false)
        return
      }

      // Validate policy address
      if (!isValidAddress(formData.policy)) {
        setErrorMessage('Invalid "Policy" address format')
        setLoading(false)
        return
      }

      const data = encodeData(formData.policy, formData.data)

      // Set default selector if empty (For fallback)
      const selector = formData.selector || '0x00000000'

      const configurations: FormData[] = [
        {
          target: ethers.getAddress(String(formData.target)),
          selector,
          operation: formData.operation,
          policy: formData.policy,
          data,
        },
      ]

      try {
        const txs: BaseTransaction[] = policyEngineInSafe
          ? [
              {
                to: policyEngineAddress,
                value: '0',
                data: CONTRACT_INTERFACE.encodeFunctionData(
                  'requestConfiguration',
                  [
                    ethers.keccak256(
                      ethers.AbiCoder.defaultAbiCoder().encode(
                        [
                          'tuple(address target, bytes4 selector, uint8 operation, address policy, bytes data)[]',
                        ],
                        [configurations]
                      )
                    ),
                  ]
                ),
              },
              {
                to: policyEngineAddress,
                value: '0',
                data: CONTRACT_INTERFACE.encodeFunctionData(
                  'complementRequestConfiguration',
                  [configurations]
                ),
              },
            ]
          : [
              {
                to: policyEngineAddress,
                value: '0',
                data: CONTRACT_INTERFACE.encodeFunctionData(
                  'configureImmediately',
                  [configurations]
                ),
              },
            ]
        await sdk.txs.send({ txs })
      } catch (error) {
        setErrorMessage('Failed to set Tx allowance: ' + error)
      } finally {
        setLoading(false)
      }
    },
    [policyEngineAddress, policyEngineInSafe, sdk.txs]
  )

  // Apply configuration
  const applyConfiguration = useCallback(
    async (formData: FormData) => {
      setLoading(true)
      setErrorMessage(null)

      if (!policyEngineAddress) {
        setErrorMessage('Policy Engine address not available')
        setLoading(false)
        return
      }

      // Validate 'target' address
      if (!isValidAddress(formData.target)) {
        setErrorMessage('Invalid "Target" address format')
        setLoading(false)
        return
      }

      // Validate selector
      const selectorValidation = validateSelector(formData.selector)
      if (!selectorValidation.isValid) {
        setErrorMessage(selectorValidation.error!)
        setLoading(false)
        return
      }

      // Validate operation
      if (!isValidOperation(formData.operation)) {
        setErrorMessage('Operation must be Call (0) or DelegateCall (1)')
        setLoading(false)
        return
      }

      // Validate policy address
      if (!isValidAddress(formData.policy)) {
        setErrorMessage('Invalid "Policy" address format')
        setLoading(false)
        return
      }

      const configurations: FormData[] = [
        {
          target: ethers.getAddress(String(formData.target)),
          selector: formData.selector,
          operation: formData.operation,
          policy: formData.policy,
          data: formData.data,
        },
      ]

      try {
        const txs: BaseTransaction[] = [
          {
            to: policyEngineAddress,
            value: '0',
            data: CONTRACT_INTERFACE.encodeFunctionData('applyConfiguration', [
              configurations,
            ]),
          },
        ]
        await sdk.txs.send({ txs })
      } catch (error) {
        setErrorMessage('Failed to set Tx allowance: ' + error)
      } finally {
        setLoading(false)
      }
    },
    [policyEngineAddress, sdk.txs]
  )

  return (
    <>
      {/* Disclaimer */}
      <SafeResearchBanner />
      {/* Logo */}
      <div>
        <a
          href="https://github.com/safe-research/policy-engine"
          target="_blank"
        >
          <img
            src={'./policy-engine.svg'}
            className="logo"
            alt="Policy Engine logo"
          />
        </a>
      </div>
      <h1>Policy Engine</h1>
      <div className="card">
        {loading ? (
          <p>Loading...</p>
        ) : !isConnected ? (
          <div className="error">Not connected to any Safe</div>
        ) : !policyEngineAddress ? (
          <div className="error">Policy Engine not available in this chain</div>
        ) : (
          <>
            {/* Enable or disable Guard */}
            <div>
              {policyEngineInSafe ? (
                removalTimestamp == 0n ? (
                  <div className="card">
                    <Alert severity="success" style={{ margin: '1em' }}>
                      Policy Engine is Activated!
                    </Alert>
                    <Button
                      variant="contained"
                      onClick={() => schedulePolicyEngineRemoval()}
                      disabled={loading}
                    >
                      {loading
                        ? 'Submitting transaction...'
                        : 'Schedule Policy Engine Removal'}
                    </Button>
                  </div>
                ) : (
                  <div className="card">
                    {removalTimestamp === 1n ? (
                      <Button
                        variant="contained"
                        color="error"
                        onClick={() => activatePolicyEngine(false)}
                        disabled={loading}
                      >
                        {loading
                          ? 'Submitting transaction...'
                          : 'Deactivate Policy Engine'}
                      </Button>
                    ) : (
                      <>
                        <Alert severity="info" style={{ margin: '1em' }}>
                          {removalTimestamp > BigInt(Date.now())
                            ? `Policy Engine Removal Scheduled for ${new Date(Number(removalTimestamp)).toLocaleString()}`
                            : 'Policy Engine Removal Can be Executed Now after AllowPolicy for setGuard is Applied'}
                        </Alert>
                        <Button
                          variant="contained"
                          color="error"
                          style={{
                            color: 'grey',
                            border: '1px solid',
                            borderColor: 'grey',
                          }}
                          disabled
                        >
                          Deactivate Policy Engine
                        </Button>
                      </>
                    )}
                  </div>
                )
              ) : (
                <div className="card">
                  <Button
                    variant="contained"
                    color="success"
                    onClick={() => activatePolicyEngine(true)}
                    disabled={loading}
                  >
                    {loading
                      ? 'Submitting transaction...'
                      : 'Activate Policy Engine'}
                  </Button>
                </div>
              )}
            </div>
            <br />
            {/* Set Allowed Tx */}
            <div>
              <h2>Set Allowed Transaction</h2>
              <form
                onSubmit={(e: React.FormEvent<HTMLFormElement>) => {
                  e.preventDefault()
                  const formData: FormData = {
                    target: (
                      e.currentTarget.elements.namedItem(
                        'target'
                      ) as HTMLInputElement
                    ).value,
                    selector: (
                      e.currentTarget.elements.namedItem(
                        'selector'
                      ) as HTMLInputElement
                    ).value,
                    // Operation should have select box with two options: Call (0) and DelegateCall (1) with default value as Call (0)
                    operation: BigInt(
                      (
                        e.currentTarget.elements.namedItem(
                          'operation'
                        ) as HTMLInputElement
                      ).value
                    ),
                    // Policy should be a select from one of the policy addresses
                    policy: (
                      e.currentTarget.elements.namedItem(
                        'policy'
                      ) as HTMLInputElement
                    ).value,
                    data: (
                      e.currentTarget.elements.namedItem(
                        'data'
                      ) as HTMLInputElement
                    ).value,
                  }
                  setAllowedTx(formData)
                }}
              >
                <div
                  style={{
                    display: 'flex',
                    flexDirection: 'column',
                    gap: '10px',
                  }}
                >
                  <TextField
                    slotProps={{
                      inputLabel: { style: { color: '#fff' } },
                      input: { style: { color: '#fff' } },
                    }}
                    sx={{
                      '& .MuiOutlinedInput-root': {
                        '& fieldset': {
                          borderColor: '#fff',
                        },
                        '&:hover .MuiOutlinedInput-notchedOutline': {
                          borderColor: '#fff',
                          borderWidth: '0.15rem',
                        },
                      },
                    }}
                    variant="outlined"
                    type="text"
                    id="target"
                    name="target"
                    label="Target Address"
                    required
                  />
                  <TextField
                    slotProps={{
                      inputLabel: { style: { color: '#fff' } },
                      input: { style: { color: '#fff' } },
                    }}
                    sx={{
                      '& .MuiOutlinedInput-root': {
                        '& fieldset': {
                          borderColor: '#fff',
                        },
                        '&:hover .MuiOutlinedInput-notchedOutline': {
                          borderColor: '#fff',
                          borderWidth: '0.15rem',
                        },
                      },
                    }}
                    variant="outlined"
                    type="text"
                    id="selector"
                    name="selector"
                    label="Function Selector (4 bytes)"
                  />
                  <Select
                    slotProps={{
                      input: { style: { color: '#fff' } },
                    }}
                    sx={{
                      '& .MuiOutlinedInput-notchedOutline': {
                        borderColor: '#fff',
                      },
                      '&:hover .MuiOutlinedInput-notchedOutline': {
                        borderColor: '#fff',
                        borderWidth: '0.15rem',
                      },
                    }}
                    native
                    id="operation"
                    name="operation"
                    defaultValue={0}
                    label="Operation"
                    required
                  >
                    <option value={0}>Call</option>
                    <option value={1}>DelegateCall</option>
                  </Select>
                  <TextField
                    slotProps={{
                      inputLabel: { style: { color: '#fff' } },
                      input: { style: { color: '#fff' } },
                    }}
                    sx={{
                      '& .MuiOutlinedInput-root': {
                        '& fieldset': {
                          borderColor: '#fff',
                        },
                        '&:hover .MuiOutlinedInput-notchedOutline': {
                          borderColor: '#fff',
                          borderWidth: '0.15rem',
                        },
                      },
                    }}
                    variant="outlined"
                    type="text"
                    id="data"
                    name="data"
                    label="Data"
                  />
                  <Select
                    slotProps={{
                      input: { style: { color: '#fff' } },
                    }}
                    sx={{
                      '& .MuiOutlinedInput-notchedOutline': {
                        borderColor: '#fff',
                      },
                      '&:hover .MuiOutlinedInput-notchedOutline': {
                        borderColor: '#fff',
                        borderWidth: '0.15rem',
                      },
                    }}
                    native
                    id="policy"
                    name="policy"
                    defaultValue={0}
                    label="Policy"
                    required
                  >
                    <option value={ALLOW_POLICY_ADDRESS}>Allow Policy</option>
                    <option value={ALLOWED_MODULE_POLICY_ADDRESS}>
                      Allow Module Policy
                    </option>
                    <option value={COSIGNER_POLICY_ADDRESS}>
                      Cosigner Policy
                    </option>
                    <option value={ERC20_APPROVE_POLICY_ADDRESS}>
                      ERC20 Approve Policy
                    </option>
                    <option value={ERC20_TRANSFER_POLICY_ADDRESS}>
                      ERC20 Transfer Policy
                    </option>
                    <option value={MULTISEND_POLICY_ADDRESS}>
                      Multisend Policy
                    </option>
                    <option value={NATIVE_TRANSFER_POLICY_ADDRESS}>
                      Native Transfer Policy
                    </option>
                  </Select>
                  <Button
                    variant="contained"
                    color="primary"
                    type="submit"
                    disabled={loading}
                  >
                    {loading ? 'Submitting...' : 'Set Allowed Tx'}
                  </Button>
                </div>
              </form>
            </div>
            <br />
            {/* Current Allowed Transactions */}
            <div>
              {allowedAccessesInfo.length > 0 ? (
                <>
                  <h3>Showing current allowed transactions</h3>
                  <TableContainer component={Paper}>
                    <Table
                      sx={{ minWidth: 650 }}
                      aria-label="allowed txs table"
                    >
                      <TableHead>
                        <TableRow>
                          <TableCell>Target Address</TableCell>
                          <TableCell>Function Selector</TableCell>
                          <TableCell>Operation</TableCell>
                          <TableCell>Policy</TableCell>
                          <TableCell>Data</TableCell>
                          <TableCell>Active</TableCell>
                          <TableCell></TableCell>
                        </TableRow>
                      </TableHead>
                      <TableBody>
                        {allowedAccessesInfo.map(accesses => (
                          <TableRow
                            key={accesses.target + accesses.selector}
                            sx={{
                              '&:last-child td, &:last-child th': { border: 0 },
                            }}
                          >
                            <TableCell component="th" scope="row">
                              {getAddressName(
                                accesses.target,
                                safe.safeAddress
                              ) !== null
                                ? getAddressName(
                                    accesses.target,
                                    safe.safeAddress
                                  )
                                : String(accesses.target)}
                            </TableCell>
                            <TableCell>
                              {decodeSelector(accesses.selector)}
                            </TableCell>
                            <TableCell>
                              {accesses.operation === 0n
                                ? 'Call'
                                : 'DelegateCall'}
                            </TableCell>
                            <TableCell>
                              {getAddressName(accesses.policy) !== null
                                ? getAddressName(accesses.policy)
                                : String(accesses.policy)}
                            </TableCell>
                            <TableCell>
                              {decodeData(accesses.policy, accesses.data)}
                            </TableCell>
                            <TableCell>{'Yes'}</TableCell>
                            <TableCell align="right">
                              <Button
                                variant="contained"
                                color="error"
                                onClick={() => {
                                  setAllowedTx({
                                    target: accesses.target,
                                    selector: accesses.selector,
                                    operation: accesses.operation,
                                    policy: ZeroAddress,
                                    data: '0x',
                                  })
                                }}
                              >
                                Remove
                              </Button>
                            </TableCell>
                          </TableRow>
                        ))}
                      </TableBody>
                    </Table>
                  </TableContainer>
                  <p>
                    Allowed Transactions count: {allowedAccessesInfo.length}
                  </p>
                </>
              ) : (
                <>
                  <h3>Showing current allowed transactions</h3>
                  <TableContainer component={Paper}>
                    <Table
                      sx={{ minWidth: 650 }}
                      aria-label="allowed txs table"
                    >
                      <TableHead>
                        <TableRow>
                          <TableCell align="center">
                            No Allowed Transactions Found
                          </TableCell>
                        </TableRow>
                      </TableHead>
                    </Table>
                  </TableContainer>
                </>
              )}
            </div>
            <br />
            {/* Current Pending Transactions */}
            <div>
              {currentPendingConfigurations.length > 0 ? (
                <>
                  <h3>Showing current pending transactions</h3>
                  <TableContainer component={Paper}>
                    <Table
                      sx={{ minWidth: 650 }}
                      aria-label="allowed txs table"
                    >
                      <TableHead>
                        <TableRow>
                          <TableCell>Target Address</TableCell>
                          <TableCell>Function Selector</TableCell>
                          <TableCell>Operation</TableCell>
                          <TableCell>Policy</TableCell>
                          <TableCell>Data</TableCell>
                          <TableCell>Activate By</TableCell>
                          <TableCell></TableCell>
                        </TableRow>
                      </TableHead>
                      <TableBody>
                        {currentPendingConfigurations.map(configuration => (
                          <TableRow
                            key={configuration.target + configuration.selector}
                            sx={{
                              '&:last-child td, &:last-child th': { border: 0 },
                            }}
                          >
                            <TableCell component="th" scope="row">
                              {getAddressName(
                                configuration.target,
                                safe.safeAddress
                              ) !== null
                                ? getAddressName(
                                    configuration.target,
                                    safe.safeAddress
                                  )
                                : String(configuration.target)}
                            </TableCell>
                            <TableCell>
                              {decodeSelector(configuration.selector)}
                            </TableCell>
                            <TableCell>
                              {configuration.operation === 0n
                                ? 'Call'
                                : 'DelegateCall'}
                            </TableCell>
                            <TableCell>
                              {getAddressName(configuration.policy) !== null
                                ? getAddressName(configuration.policy)
                                : String(configuration.policy)}
                            </TableCell>
                            <TableCell>
                              {decodeData(
                                configuration.policy,
                                configuration.data
                              )}
                            </TableCell>
                            <TableCell>
                              {configuration.activeFrom < BigInt(Date.now())
                                ? 'Now'
                                : 'Will be active at ' +
                                  new Date(
                                    Number(configuration.activeFrom)
                                  ).toLocaleString()}
                            </TableCell>
                            <TableCell align="right">
                              <Button
                                variant="contained"
                                color="primary"
                                onClick={() => {
                                  applyConfiguration({
                                    target: configuration.target,
                                    selector: configuration.selector,
                                    operation: configuration.operation,
                                    policy: configuration.policy,
                                    data: configuration.data,
                                  })
                                }}
                                disabled={
                                  loading ||
                                  configuration.activeFrom > BigInt(Date.now())
                                }
                              >
                                Apply
                              </Button>
                            </TableCell>
                          </TableRow>
                        ))}
                      </TableBody>
                    </Table>
                  </TableContainer>
                  <p>
                    All Pending Transactions count:{' '}
                    {currentPendingConfigurations.length}
                  </p>
                </>
              ) : (
                <>
                  <h3>Showing current pending transactions</h3>
                  <TableContainer component={Paper}>
                    <Table
                      sx={{ minWidth: 650 }}
                      aria-label="allowed txs table"
                    >
                      <TableHead>
                        <TableRow>
                          <TableCell align="center">
                            No Pending Transactions Found
                          </TableCell>
                        </TableRow>
                      </TableHead>
                    </Table>
                  </TableContainer>
                </>
              )}
            </div>
            <br />
          </>
        )}
        {errorMessage ? <p className="error">{errorMessage}</p> : null}
      </div>
      <SafeResearchFooter repo="policy-engine" />
    </>
  )
}

export default App
