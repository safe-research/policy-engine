import { Component } from 'react'
import type { ErrorInfo, ReactNode } from 'react'
import { Alert, Button, Paper } from '@mui/material'

interface Props {
  children: ReactNode
}

interface State {
  hasError: boolean
  error?: Error
}

/**
 * Error Boundary component to catch and handle React errors gracefully
 */
class ErrorBoundary extends Component<Props, State> {
  public state: State = {
    hasError: false,
  }

  public static getDerivedStateFromError(error: Error): State {
    return { hasError: true, error }
  }

  public componentDidCatch(error: Error, errorInfo: ErrorInfo) {
    console.error('Error caught by boundary:', error, errorInfo)
  }

  private handleRetry = () => {
    this.setState({ hasError: false, error: undefined })
  }

  public render() {
    if (this.state.hasError) {
      return (
        <Paper style={{ padding: '2rem', margin: '2rem', textAlign: 'center' }}>
          <Alert severity="error" style={{ marginBottom: '1rem' }}>
            <strong>Something went wrong</strong>
            <br />
            {this.state.error?.message || 'An unexpected error occurred'}
          </Alert>
          <Button variant="contained" onClick={this.handleRetry}>
            Try Again
          </Button>
        </Paper>
      )
    }

    return this.props.children
  }
}

export default ErrorBoundary
