# Policy Engine Safe App

A React-based Safe App that provides a user interface for managing policy-based access controls in Safe wallets using the Policy Engine protocol.

## 📋 Overview

The Policy Engine Safe App enables Safe owners to:

- **Activate/Deactivate Policy Engine**: Set up the Policy Engine as a transaction guard
- **Configure Allowed Transactions**: Define which transactions are permitted with specific policies
- **Manage Policies**: Apply different policy types (Allow, Cosigner, ERC20, etc.)
- **Schedule Guard Removal**: Use timelock mechanisms for secure Policy Engine removal
- **Monitor Status**: View current allowed accesses and pending configurations

## 🏗️ Architecture

### Core Components

- **App.tsx**: Main application orchestrator and business logic
- **Custom Hooks**: Data fetching and state management
- **Utilities**: Helper functions, constants, and type definitions

### Key Features

- **Type-Safe**: Full TypeScript implementation with comprehensive type definitions
- **Modular Design**: Separation of concerns with custom hooks and reusable components
- **Error Handling**: Comprehensive error states and user feedback
- **Responsive UI**: Material-UI components

## 🚀 Getting Started

### Prerequisites

- Node.js 18+ and npm
- A Safe wallet accessible through the Safe Web App
- Access to a supported network (Ethereum Sepolia, Gnosis Chain, Base Sepolia)

### Installation

1. **Clone the repository**:
   ```bash
   git clone https://github.com/safe-research/policy-engine.git
   cd policy-engine/app
   ```

2. **Install dependencies**:
   ```bash
   npm install
   ```

3. **Configure environment variables**:
   ```bash
   cp .env.example .env
   ```
   Edit `.env` and configure the required variables:
   ```
   VITE_COSIGNER_ADDRESS=0xYourCosignerAddressHere
   VITE_BASE_URL=/policy-engine/
   ```

4. **Start development server**:
   ```bash
   npm run dev
   ```

5. **Build for production**:
   ```bash
   npm run build
   ```

### Safe App Integration

1. **Load in Safe Web App**:
   - Open your Safe at [Safe Wallet](https://app.safe.global/)
   - Navigate to "Apps" section
   - Click "Add Custom App"
   - Enter your app URL: `http://localhost:3000` (for development)

2. **Network Support**:
   - Gnosis Chain (Chain ID: 100)
   - Ethereum Sepolia (Chain ID: 11155111)
   - Base Sepolia (Chain ID: 84532)

## 🔧 Development

### Scripts

- `npm run dev` - Start development server with hot reload
- `npm run build` - Build production bundle
- `npm run lint` - Run ESLint for code quality

### Code Quality

- **TypeScript**: Strict type checking enabled
- **ESLint**: Code linting with React and TypeScript rules
- **Prettier**: Code formatting (configured in `.prettierrc`)
- **Material-UI**: Consistent component styling and theming

### Development Guidelines

1. **Type Safety**: All components and functions must be properly typed
2. **Error Handling**: Implement proper error boundaries and user feedback
3. **Documentation**: Add JSDoc comments for all public functions and components
4. **Testing**: Test components and hooks individually
5. **Accessibility**: Follow WCAG guidelines for UI components
