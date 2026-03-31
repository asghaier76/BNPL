/**
 * OrderAuthorization.ts
 *
 * TypeScript utilities for constructing and signing EIP-712 OrderAuthorization
 * structs at e-commerce checkout. Works with ethers v6 and viem.
 *
 * Usage:
 *   import { buildOrderAuthorization, signOrderAuthorization } from "./OrderAuthorization";
 *
 *   // At checkout, merchant backend calls:
 *   const auth = buildOrderAuthorization({
 *     merchant:                 "0x...",
 *     token:                    "0x...",   // USDC address
 *     totalAmount:              400_000000n, // $400 USDC (6 decimals)
 *     installments:             4,
 *     downPaymentBps:           2500,       // 25%
 *     installmentPeriod:        30n * 24n * 60n * 60n, // 30 days
 *     gracePeriod:              3n  * 24n * 60n * 60n, // 3 days
 *     lateFeeBps:               500,        // 5%
 *     downPaymentAuthStrategy:  PERMIT2_AUTH_ADDRESS,
 *     installmentAuthStrategy:  ALLOWANCE_AUTH_ADDRESS,
 *     nonce:                    await manager.authorizationNonce(customerAddress),
 *     deadline:                 BigInt(Math.floor(Date.now() / 1000) + 1800), // 30 min
 *   });
 *
 *   // Customer wallet signs:
 *   const sig = await signOrderAuthorization(walletClient, auth, bnplManagerAddress, chainId);
 *
 *   // Merchant submits createOrder with sig + downPaymentAuthData
 */

// ============ Types ============

export interface OrderAuthorizationParams {
  merchant:                 `0x${string}`;
  token:                    `0x${string}`;
  totalAmount:              bigint;
  installments:             number;        // 2–12
  downPaymentBps:           number;        // 1000–5000
  installmentPeriod:        bigint;        // seconds
  gracePeriod:              bigint;        // seconds
  lateFeeBps:               number;        // 0–1500
  downPaymentAuthStrategy:  `0x${string}`;
  installmentAuthStrategy:  `0x${string}`;
  nonce:                    bigint;
  deadline:                 bigint;
}

export interface SignedOrderAuthorization extends OrderAuthorizationParams {
  signature: `0x${string}`;
}

// ============ EIP-712 domain and types ============

export const BNPL_DOMAIN_NAME    = "BNPL";
export const BNPL_DOMAIN_VERSION = "1";

export const ORDER_AUTHORIZATION_TYPES = {
  OrderAuthorization: [
    { name: "merchant",                 type: "address" },
    { name: "token",                    type: "address" },
    { name: "totalAmount",              type: "uint256" },
    { name: "installments",             type: "uint8"   },
    { name: "downPaymentBps",           type: "uint256" },
    { name: "installmentPeriod",        type: "uint256" },
    { name: "gracePeriod",              type: "uint256" },
    { name: "lateFeeBps",               type: "uint256" },
    { name: "downPaymentAuthStrategy",  type: "address" },
    { name: "installmentAuthStrategy",  type: "address" },
    { name: "nonce",                    type: "uint256" },
    { name: "deadline",                 type: "uint256" },
  ],
} as const;

// ============ Builder ============

/**
 * Build an OrderAuthorization params object with validation.
 * Throws if any parameter is out of spec range.
 */
export function buildOrderAuthorization(
  params: OrderAuthorizationParams
): OrderAuthorizationParams {
  if (params.installments < 2 || params.installments > 12) {
    throw new Error(`installments must be 2–12, got ${params.installments}`);
  }
  if (params.downPaymentBps < 1000 || params.downPaymentBps > 5000) {
    throw new Error(`downPaymentBps must be 1000–5000, got ${params.downPaymentBps}`);
  }
  if (params.lateFeeBps > 1500) {
    throw new Error(`lateFeeBps must be ≤ 1500, got ${params.lateFeeBps}`);
  }
  if (params.gracePeriod > 2592000n) {
    throw new Error(`gracePeriod must be ≤ 2592000 seconds, got ${params.gracePeriod}`);
  }
  if (params.totalAmount === 0n) {
    throw new Error("totalAmount must be non-zero");
  }
  if (params.deadline < BigInt(Math.floor(Date.now() / 1000))) {
    throw new Error("deadline is in the past");
  }
  return params;
}

// ============ Signing (viem) ============

/**
 * Sign an OrderAuthorization using viem's signTypedData.
 * Works with any viem WalletClient (MetaMask, Coinbase Wallet, etc.)
 *
 * @param walletClient  viem WalletClient with the customer's account
 * @param params        OrderAuthorization parameters (use buildOrderAuthorization first)
 * @param verifyingContract  Address of the BNPLManager contract
 * @param chainId       Target chain ID
 */
export async function signOrderAuthorizationViem(
  walletClient: {
    signTypedData: (args: {
      account:          `0x${string}`;
      domain:           Record<string, unknown>;
      types:            Record<string, unknown>;
      primaryType:      string;
      message:          Record<string, unknown>;
    }) => Promise<`0x${string}`>;
    account: { address: `0x${string}` };
  },
  params: OrderAuthorizationParams,
  verifyingContract: `0x${string}`,
  chainId: number
): Promise<`0x${string}`> {
  return walletClient.signTypedData({
    account: walletClient.account.address,
    domain: {
      name:              BNPL_DOMAIN_NAME,
      version:           BNPL_DOMAIN_VERSION,
      chainId,
      verifyingContract,
    },
    types:       ORDER_AUTHORIZATION_TYPES,
    primaryType: "OrderAuthorization",
    message: {
      merchant:                params.merchant,
      token:                   params.token,
      totalAmount:             params.totalAmount,
      installments:            params.installments,
      downPaymentBps:          params.downPaymentBps,
      installmentPeriod:       params.installmentPeriod,
      gracePeriod:             params.gracePeriod,
      lateFeeBps:              params.lateFeeBps,
      downPaymentAuthStrategy: params.downPaymentAuthStrategy,
      installmentAuthStrategy: params.installmentAuthStrategy,
      nonce:                   params.nonce,
      deadline:                params.deadline,
    },
  });
}

// ============ Signing (ethers v6) ============

/**
 * Sign an OrderAuthorization using ethers v6 Signer.
 */
export async function signOrderAuthorizationEthers(
  signer: {
    signTypedData: (
      domain: Record<string, unknown>,
      types:  Record<string, unknown>,
      value:  Record<string, unknown>
    ) => Promise<string>;
  },
  params:            OrderAuthorizationParams,
  verifyingContract: string,
  chainId:           number
): Promise<string> {
  return signer.signTypedData(
    {
      name:    BNPL_DOMAIN_NAME,
      version: BNPL_DOMAIN_VERSION,
      chainId,
      verifyingContract,
    },
    ORDER_AUTHORIZATION_TYPES,
    {
      merchant:                params.merchant,
      token:                   params.token,
      totalAmount:             params.totalAmount,
      installments:            params.installments,
      downPaymentBps:          params.downPaymentBps,
      installmentPeriod:       params.installmentPeriod,
      gracePeriod:             params.gracePeriod,
      lateFeeBps:              params.lateFeeBps,
      downPaymentAuthStrategy: params.downPaymentAuthStrategy,
      installmentAuthStrategy: params.installmentAuthStrategy,
      nonce:                   params.nonce,
      deadline:                params.deadline,
    }
  );
}

// ============ Schedule utilities ============

export interface InstallmentSchedule {
  installmentIndex: number;
  amount:           bigint;
  dueDate:          bigint;  // unix timestamp
}

/**
 * Derive the uniform installment schedule from order parameters.
 * For MerkleScheduleAuth orders, use MerkleSchedule.ts instead.
 *
 * Dust (integer remainder) is added to the final installment.
 */
export function deriveUniformSchedule(
  totalAmount:     bigint,
  downPaymentBps:  number,
  installments:    number,
  orderCreatedAt:  bigint,   // unix timestamp of createOrder transaction
  installmentPeriod: bigint
): InstallmentSchedule[] {
  const downPayment = (totalAmount * BigInt(downPaymentBps)) / 10000n;
  const remaining   = totalAmount - downPayment;
  const baseAmt     = remaining / BigInt(installments);
  const dust        = remaining % BigInt(installments);

  return Array.from({ length: installments }, (_, i) => ({
    installmentIndex: i,
    amount:   i === installments - 1 ? baseAmt + dust : baseAmt,
    dueDate:  orderCreatedAt + installmentPeriod * BigInt(i + 1),
  }));
}

/**
 * Encode AllowanceAuth authData (empty bytes — no data needed).
 */
export const ALLOWANCE_AUTH_DATA: `0x${string}` = "0x";

/**
 * Encode PermitAuth authData.
 */
export function encodePermitAuthData(
  deadline: bigint,
  v:        number,
  r:        `0x${string}`,
  s:        `0x${string}`
): `0x${string}` {
  // ABI encode: (uint256 deadline, uint8 v, bytes32 r, bytes32 s)
  const deadlineHex = deadline.toString(16).padStart(64, "0");
  const vHex        = v.toString(16).padStart(64, "0");
  const rHex        = r.slice(2).padStart(64, "0");
  const sHex        = s.slice(2).padStart(64, "0");
  return `0x${deadlineHex}${vHex}${rHex}${sHex}`;
}

/**
 * Encode Permit2Auth authData.
 * signature is the full 65-byte ECDSA sig over the Permit2 PermitTransferFrom struct.
 */
export function encodePermit2AuthData(
  nonce:     bigint,
  deadline:  bigint,
  signature: `0x${string}`
): `0x${string}` {
  // ABI encode: (uint256 nonce, uint256 deadline, bytes signature)
  // This is a simplified encoder — use viem's encodeAbiParameters in production.
  const nonceHex    = nonce.toString(16).padStart(64, "0");
  const deadlineHex = deadline.toString(16).padStart(64, "0");
  // bytes offset = 0x60 (3 * 32 bytes)
  const offset      = "60".padStart(64, "0");
  const sigBytes    = signature.slice(2);
  const sigLen      = (sigBytes.length / 2).toString(16).padStart(64, "0");
  const sigPadded   = sigBytes.padEnd(Math.ceil(sigBytes.length / 64) * 64, "0");
  return `0x${nonceHex}${deadlineHex}${offset}${sigLen}${sigPadded}`;
}
