/**
 * MerkleSchedule.ts
 *
 * TypeScript utilities for building merkle trees, generating proofs,
 * and encoding authData for MerkleScheduleAuth installment collection.
 *
 * Compatible with OpenZeppelin's MerkleProof library (sorted-sibling hashing).
 *
 * Usage:
 *   import { buildMerkleSchedule, encodeMerkleAuthData } from "./MerkleSchedule";
 *
 *   const schedule = [
 *     { installmentIndex: 0, amount: 100_000000n, dueDate: 1740000000n },
 *     { installmentIndex: 1, amount: 200_000000n, dueDate: 1742592000n },
 *     { installmentIndex: 2, amount: 200_000000n, dueDate: 1745270400n },
 *     { installmentIndex: 3, amount: 250_000000n, dueDate: 1747862400n },
 *   ];
 *
 *   const tree = buildMerkleSchedule(schedule);
 *   console.log("merkleRoot:", tree.root);  // submit to registerSchedule()
 *
 *   // At collection time:
 *   const authData = encodeMerkleAuthData(orderId, tree, 0);
 *   await manager.collectInstallment(orderId, authData);
 */

import { keccak256, encodePacked, encodeAbiParameters, parseAbiParameters } from "viem";

// ============ Types ============

export interface ScheduleLeaf {
  installmentIndex: number;
  amount:           bigint;    // token base units
  dueDate:          bigint;    // unix timestamp
}

export interface MerkleTree {
  root:   `0x${string}`;
  leaves: `0x${string}`[];    // hashed leaves, same order as input schedule
  layers: `0x${string}`[][];  // all tree layers, layers[0] = leaf layer
}

// ============ Leaf construction ============

/**
 * Compute the leaf hash for an installment.
 * Matches the on-chain: keccak256(abi.encode(installmentIndex, amount, dueDate))
 *
 * IMPORTANT: uses abi.encode (padded 32-byte slots), NOT encodePacked,
 * to match the Solidity implementation exactly.
 */
export function hashLeaf(leaf: ScheduleLeaf): `0x${string}` {
  // Equivalent to Solidity: keccak256(abi.encode(uint256 installmentIndex, uint256 amount, uint256 dueDate))
  const encoded = encodeAbiParameters(
    parseAbiParameters("uint256, uint256, uint256"),
    [BigInt(leaf.installmentIndex), leaf.amount, leaf.dueDate]
  );
  return keccak256(encoded);
}

// ============ Tree construction ============

/**
 * Hash a pair of sibling nodes (sorted before hashing to match OZ MerkleProof).
 */
function hashPair(a: `0x${string}`, b: `0x${string}`): `0x${string}` {
  const [left, right] = a < b ? [a, b] : [b, a];
  const encoded = encodeAbiParameters(
    parseAbiParameters("bytes32, bytes32"),
    [left, right]
  );
  return keccak256(encoded);
}

/**
 * Build a merkle tree from a schedule of installments.
 * Pads with zero-leaves if the schedule length is not a power of 2.
 *
 * @param schedule  Array of ScheduleLeaf objects, in installment order.
 * @returns MerkleTree with root, leaves, and all layers for proof generation.
 */
export function buildMerkleSchedule(schedule: ScheduleLeaf[]): MerkleTree {
  if (schedule.length === 0) {
    throw new Error("schedule must have at least one leaf");
  }

  // Hash each leaf
  const hashedLeaves: `0x${string}`[] = schedule.map(hashLeaf);

  // Pad to next power of 2 with zero-value leaves
  const size = nextPowerOfTwo(hashedLeaves.length);
  const paddedLeaves: `0x${string}`[] = [
    ...hashedLeaves,
    ...Array(size - hashedLeaves.length).fill(
      "0x0000000000000000000000000000000000000000000000000000000000000000" as `0x${string}`
    ),
  ];

  // Build layers bottom-up
  const layers: `0x${string}`[][] = [paddedLeaves];
  let current = paddedLeaves;

  while (current.length > 1) {
    const next: `0x${string}`[] = [];
    for (let i = 0; i < current.length; i += 2) {
      next.push(hashPair(current[i], current[i + 1]));
    }
    layers.push(next);
    current = next;
  }

  return {
    root:   current[0],
    leaves: hashedLeaves,          // only real leaves, not padded
    layers,
  };
}

// ============ Proof generation ============

/**
 * Generate a merkle proof for a specific leaf index.
 *
 * @param tree        MerkleTree built by buildMerkleSchedule.
 * @param leafIndex   0-based index into the original schedule array.
 * @returns Array of bytes32 sibling hashes forming the proof.
 */
export function generateProof(
  tree:      MerkleTree,
  leafIndex: number
): `0x${string}`[] {
  if (leafIndex < 0 || leafIndex >= tree.leaves.length) {
    throw new Error(`leafIndex ${leafIndex} out of bounds (${tree.leaves.length} leaves)`);
  }

  const proof: `0x${string}`[] = [];
  let index = leafIndex;

  // Walk up from leaf layer to root layer
  for (let layer = 0; layer < tree.layers.length - 1; layer++) {
    const isRight = index % 2 === 1;
    const siblingIndex = isRight ? index - 1 : index + 1;

    // Guard against odd-length layers (shouldn't happen with power-of-2 padding)
    if (siblingIndex < tree.layers[layer].length) {
      proof.push(tree.layers[layer][siblingIndex]);
    }

    index = Math.floor(index / 2);
  }

  return proof;
}

// ============ Proof verification ============

/**
 * Verify a proof client-side (matches OZ MerkleProof.verify).
 * Use this to validate proofs before submitting on-chain.
 */
export function verifyProof(
  root:      `0x${string}`,
  leaf:      ScheduleLeaf,
  proof:     `0x${string}`[]
): boolean {
  let computedHash = hashLeaf(leaf);
  for (const sibling of proof) {
    computedHash = hashPair(computedHash, sibling);
  }
  return computedHash === root;
}

// ============ authData encoding ============

/**
 * Encode the authData bytes for a MerkleScheduleAuth.pullPayment call.
 * Pass the result to BNPLManager.collectInstallment() as installmentAuthData.
 *
 * authData format: abi.encode(bytes32 orderId, uint256 installmentIndex,
 *                             uint256 leafAmount, uint256 dueDate, bytes32[] proof)
 */
export function encodeMerkleAuthData(
  orderId:   `0x${string}`,
  tree:      MerkleTree,
  schedule:  ScheduleLeaf[],
  leafIndex: number
): `0x${string}` {
  const leaf  = schedule[leafIndex];
  const proof = generateProof(tree, leafIndex);

  return encodeAbiParameters(
    parseAbiParameters("bytes32, uint256, uint256, uint256, bytes32[]"),
    [
      orderId,
      BigInt(leaf.installmentIndex),
      leaf.amount,
      leaf.dueDate,
      proof,
    ]
  );
}

// ============ IPFS publishing helper ============

/**
 * Serialize a schedule to JSON for IPFS/content-addressed publishing.
 * The CID of this JSON is what you pass to registerSchedule() as dataCID.
 *
 * Format is intentionally simple for interoperability.
 */
export function serializeScheduleForIPFS(
  schedule:  ScheduleLeaf[],
  tree:      MerkleTree,
  orderId?:  string
): string {
  return JSON.stringify({
    orderId:   orderId || null,
    merkleRoot: tree.root,
    schedule: schedule.map(leaf => ({
      installmentIndex: leaf.installmentIndex,
      amount:           leaf.amount.toString(),
      dueDate:          leaf.dueDate.toString(),
      leafHash:         hashLeaf(leaf),
    })),
  }, null, 2);
}

// ============ Test vectors ============

/**
 * Compute the ERC spec test vectors.
 * Run this to verify your implementation produces the correct root.
 */
export function computeSpecTestVectors(): {
  leaf0: `0x${string}`;
  leaf1: `0x${string}`;
  root:  `0x${string}`;
} {
  const leaf0 = hashLeaf({ installmentIndex: 0, amount: 500000n,  dueDate: 1740000000n });
  const leaf1 = hashLeaf({ installmentIndex: 1, amount: 750000n,  dueDate: 1742592000n });
  const root  = hashPair(leaf0, leaf1);
  return { leaf0, leaf1, root };
}

// ============ Utility ============

function nextPowerOfTwo(n: number): number {
  if (n <= 1) return 1;
  let p = 1;
  while (p < n) p *= 2;
  return p;
}
