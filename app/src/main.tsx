/**
 * Application Entry Point
 *
 * Sets up the React application with necessary providers:
 * - StrictMode: React development mode for highlighting potential problems
 * - SafeProvider: Safe Apps SDK provider for Safe wallet integration
 * - ErrorBoundary: Catches and handles React component errors gracefully
 */

import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'
import './index.css'
import App from './App.tsx'
import ErrorBoundary from './components/ErrorBoundary.tsx'
import SafeProvider from '@safe-global/safe-apps-react-sdk'

createRoot(document.getElementById('root')!).render(
  <StrictMode>
    <SafeProvider>
      <ErrorBoundary>
        <App />
      </ErrorBoundary>
    </SafeProvider>
  </StrictMode>
)
