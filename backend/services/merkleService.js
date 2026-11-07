const crypto = require('crypto');

function hash(data) {
  return '0x' + crypto.createHash('sha256')
    .update(data)
    .digest('hex');
}

// Domain separation prevents leaf hashes being confused with
// internal-node hashes.
function hashLeaf(commitment) {
  return hash(Buffer.concat([
    Buffer.from([0]),
    Buffer.from(commitment.slice(2), 'hex')
  ]));
}

function hashPair(left, right) {
  const a = Buffer.from(left.slice(2), 'hex');
  const b = Buffer.from(right.slice(2), 'hex');

  return hash(Buffer.concat([
    Buffer.from([1]), a, b
  ]));
}

function buildMerkleTree(commitments) {
  if (!commitments.length) {
    throw new Error('Cannot build an empty Merkle tree');
  }

  let levels = [commitments.map(hashLeaf)];

  while (levels[levels.length - 1].length > 1) {
    const current = levels[levels.length - 1];
    const next = [];

    for (let i = 0; i < current.length; i += 2) {
      const left = current[i];
      const right = current[i + 1] || current[i];

      next.push(hashPair(left, right));
    }

    levels.push(next);
  }

  const proofs = commitments.map((_, index) => {
    const proof = [];
    let position = index;

    for (let level = 0; level < levels.length - 1; level++) {
      const nodes = levels[level];
      const siblingIndex = position ^ 1;

      proof.push(nodes[siblingIndex] || nodes[position]);
      position = Math.floor(position / 2);
    }

    return proof;
  });

  return {
    root: levels[levels.length - 1][0],
    proofs
  };
}

function verifyMerkleProof(commitment, proof, leafIndex, expectedRoot) {
  let current = hashLeaf(commitment);
  let position = leafIndex;

  for (const sibling of proof) {
    current = position % 2 === 0
      ? hashPair(current, sibling)
      : hashPair(sibling, current);

    position = Math.floor(position / 2);
  }

  return current.toLowerCase() === expectedRoot.toLowerCase();
}

module.exports = {
  buildMerkleTree,
  verifyMerkleProof
};