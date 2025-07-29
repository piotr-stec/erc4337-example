# ERC-4337 Privacy Pool 


## Architecture Overview

```
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
│    User Wallet  │    │   Privacy Pool   │    │   EntryPoint    │
│                 │    │  Contract (AA)   │    │                 │
└─────────────────┘    └──────────────────┘    └─────────────────┘
         │                       │                       │
         │                       │                       │
         │ 1. Direct deposit()   │                       │
         │─────────────────────▶│                       │
         │                       │                       │
         │                       │ 2. UserOperation      │
         │                       │   with ZK proof       │
         │                       │─────────────────────▶│
         │                       │                       │
         │                       │ 3. validateUserOp()   │
         │                       │◀─────────────────────│
         │                       │                       │
         │                       │ 4. withdraw()         │
         │                       │◀─────────────────────│
         │                       │                       │
```

## Communication Flow

### Phase 1: Deposit (Direct Contract Interaction)
1. **User** calls `deposit()` directly on Privacy Pool contract
   - Transfers tokens from user wallet to contract
   - Creates commitment and adds to Merkle tree
   - Emits Deposit event
   - **No anonymity** - transaction is linked to user's address

### Phase 2: Withdrawal (Anonymous via ERC-4337)
1. **Owner** calls `depositTo(PrivacyPool)` on EntryPoint to fund gas fees
2. **Privacy Pool Contract** (as AA Account) creates UserOperation with:
   - `sender`: Privacy Pool contract address
   - `callData`: encoded `execute()` function call on itself
   - `signature`: ZK proof + public inputs (encoded)
3. **EntryPoint** validates UserOperation:
   - Calls `validateUserOp()` on Privacy Pool
   - Verifies ZK proof and verification key
4. **EntryPoint** executes UserOperation:
   - Calls `withdraw()` on Privacy Pool
   - Re-verifies proof for security
   - Increments counter (example operation)

**Key Point**: The Privacy Pool contract acts as both the ERC-4337 Account and the target contract. It validates and executes operations on itself, enabling anonymous interactions without revealing the original user's wallet.


## Setup

Run local EVM node:
```bash
npx hardhat node
```

Test using scripts:
```bash
npx hardhat run scripts/example.sh
```
