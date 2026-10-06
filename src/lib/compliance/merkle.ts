import crypto from "node:crypto";

export interface MerkleProofElement {
  position: "left" | "right";
  hash: string;
}

export interface MerkleTree {
  root: string;
  leaves: string[];
  depth: number;
}

function sha256(data: string): string {
  return crypto.createHash("sha256").update(data).digest("hex");
}

function combineHashes(left: string, right: string): string {
  return sha256(`${left}${right}`);
}

/**
 * Builds a Merkle Tree from an array of SHA-256 leaf hashes.
 */
export function buildMerkleTree(leafHashes: string[]): MerkleTree {
  if (leafHashes.length === 0) {
    const emptyRoot = sha256("EMPTY_TREE");
    return { root: emptyRoot, leaves: [], depth: 0 };
  }

  let currentLevel = [...leafHashes];
  let depth = 0;

  while (currentLevel.length > 1) {
    const nextLevel: string[] = [];
    for (let i = 0; i < currentLevel.length; i += 2) {
      const left = currentLevel[i];
      // If odd count of elements, duplicate last hash (RFC 6962 / Bitcoin style)
      const right = i + 1 < currentLevel.length ? currentLevel[i + 1] : left;
      nextLevel.push(combineHashes(left, right));
    }
    currentLevel = nextLevel;
    depth++;
  }

  return {
    root: currentLevel[0],
    leaves: leafHashes,
    depth,
  };
}

/**
 * Generates an audit inclusion proof for a target leaf index in the Merkle Tree.
 */
export function generateMerkleProof(
  leafHashes: string[],
  targetIndex: number
): MerkleProofElement[] {
  if (targetIndex < 0 || targetIndex >= leafHashes.length) {
    throw new Error(`INDEX_OUT_OF_BOUNDS: Target index ${targetIndex} exceeds leaf count ${leafHashes.length}`);
  }

  const proof: MerkleProofElement[] = [];
  let currentLevel = [...leafHashes];
  let idx = targetIndex;

  while (currentLevel.length > 1) {
    const nextLevel: string[] = [];
    for (let i = 0; i < currentLevel.length; i += 2) {
      const left = currentLevel[i];
      const right = i + 1 < currentLevel.length ? currentLevel[i + 1] : left;

      if (i === idx || i + 1 === idx) {
        if (idx % 2 === 0) {
          // Target is left sibling, sibling is right
          proof.push({ position: "right", hash: right });
        } else {
          // Target is right sibling, sibling is left
          proof.push({ position: "left", hash: left });
        }
      }

      nextLevel.push(combineHashes(left, right));
    }
    idx = Math.floor(idx / 2);
    currentLevel = nextLevel;
  }

  return proof;
}

/**
 * Cryptographically verifies a Merkle inclusion proof against a known root hash.
 */
export function verifyMerkleProof(
  leafHash: string,
  proof: MerkleProofElement[],
  expectedRoot: string
): boolean {
  let currentHash = leafHash;

  for (const step of proof) {
    if (step.position === "left") {
      currentHash = combineHashes(step.hash, currentHash);
    } else {
      currentHash = combineHashes(currentHash, step.hash);
    }
  }

  return currentHash === expectedRoot;
}
