# ERC-XXXX BNPL Reference Implementation

Reference implementation of the Buy Now Pay Later Standard.

## Structure

```
src/
  interfaces/
    IPaymentAuth.sol       — Authorization abstraction interface
    IOperatorManager.sol   — Operator management interface
    IBNPL.sol              — Core BNPL interface
  strategies/
    AllowanceAuth.sol      — ERC-20 allowance strategy
    PermitAuth.sol         — ERC-2612 permit strategy
    Permit2Auth.sol        — Uniswap Permit2 strategy
    MerkleScheduleAuth.sol — Variable-schedule merkle strategy
  BNPLManager.sol          — Full IBNPL + IOperatorManager implementation

test/
  BNPLManager.t.sol        — Foundry test suite (6 test suites, ~30 tests)

script/
  OrderAuthorization.ts    — EIP-712 signing utilities (ethers v6 + viem)
  MerkleSchedule.ts        — Merkle tree builder, proof generator, authData encoder
```

## Strategy combinations

| Down payment    | Installments        | Use case                                      |
|-----------------|---------------------|-----------------------------------------------|
| `Permit2Auth`   | `AllowanceAuth`     | Recommended: gasless checkout, auto collection|
| `Permit2Auth`   | `Permit2Auth`       | Maximum security, no standing approval        |
| `AllowanceAuth` | `AllowanceAuth`     | Simplest: one approval covers everything      |
| `PermitAuth`    | `AllowanceAuth`     | ERC-2612 tokens at checkout                   |
| `Permit2Auth`   | `MerkleScheduleAuth`| Variable-amount installment schedules         |
| `AllowanceAuth` | `MerkleScheduleAuth`| Variable amounts, standing approval           |

## Getting started

```bash
# Install dependencies
forge install OpenZeppelin/openzeppelin-contracts

# Run tests
forge test -vvv

# Run specific test suite
forge test --match-contract TestAllowanceAllowance -vvv
forge test --match-contract TestMerkleScheduleAuth -vvv

# Gas report
forge test --gas-report
```

## Dependencies

- [OpenZeppelin Contracts v5](https://github.com/OpenZeppelin/openzeppelin-contracts)
- [Uniswap Permit2](https://github.com/Uniswap/permit2) (for Permit2Auth)
- [forge-std](https://github.com/foundry-rs/forge-std) (test only)

## TypeScript utilities

```typescript
import { buildOrderAuthorization, signOrderAuthorizationViem }
  from "./script/OrderAuthorization";
import { buildMerkleSchedule, encodeMerkleAuthData, computeSpecTestVectors }
  from "./script/MerkleSchedule";

// Verify spec test vectors
const vectors = computeSpecTestVectors();
console.log("Root:", vectors.root);

// Build and sign an order at checkout
const auth = buildOrderAuthorization({ ... });
const sig  = await signOrderAuthorizationViem(walletClient, auth, managerAddress, chainId);
```

## Security notes

- All strategies use `SafeERC20.safeTransferFrom` — compatible with USDT and other
  non-bool-returning tokens
- `BNPLManager` applies checks-effects-interactions throughout — nonce incremented
  and order stored before any external calls
- `MerkleScheduleAuth.registerSchedule` is immutable — roots cannot be replaced
  after registration
- ERC-165 validation on both auth strategies in `createOrder` prevents permanently
  broken orders

## License

CC0-1.0 — see individual files
