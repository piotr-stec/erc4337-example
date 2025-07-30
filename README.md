# ERC-4337 Privacy Pool 


## Architecture Overview

```
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
│    User/Relayer │    │   Privacy Pool   │    │   EntryPoint    │
│                 │    │  Contract (AA)   │    │                 │
└─────────────────┘    └──────────────────┘    └─────────────────┘
         │                       │                       │
         │                       │                       │
         │ 1. Direct deposit()   │                       │
         │─────────────────────▶│                       │
         │                       │                       │
         │                       │                       │
         │ 2. UserOperation      │                       │
         │   (sender=PrivacyPool,│                       │
         │    signature=ZK proof)│                       │
         │─────────────────────────────────────────────▶│
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
2. **User/Relayer** constructs UserOperation with:
   - `sender`: Privacy Pool contract address (not user's wallet!)
   - `callData`: encoded `withdraw()` function call 
   - `signature`: ZK proof + public inputs (encoded)
3. **User/Relayer** calls `handleOps([userOp])` on EntryPoint
4. **EntryPoint** validates UserOperation:
   - Calls `validateUserOp()` on Privacy Pool
   - Verifies ZK proof and verification key
5. **EntryPoint** executes UserOperation:
   - Calls `withdraw()` on Privacy Pool
   - Re-verifies proof for security
   - Transfers tokens to recipient

**Key Points**: 
- The **User/Relayer** sends the transaction to EntryPoint, but `sender` field points to Privacy Pool
- Privacy Pool acts as both ERC-4337 Account and target contract
- ZK proof in signature proves user's right to withdraw without revealing identity
- Original user's wallet is never directly involved in withdrawal transaction


## Setup

Run local EVM node:
```bash
npx hardhat node
```

Test using scripts:
```bash
npx hardhat run scripts/example.sh
```
