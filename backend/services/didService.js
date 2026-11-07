const crypto = require('crypto');

const BASE58 = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
const ED25519_MULTICODEC = Buffer.from([0xed, 0x01]);
const ED25519_SPKI_PREFIX = Buffer.from('302a300506032b6570032100', 'hex');

function base58Decode(value) {
  if (typeof value !== 'string' || value.length === 0) {
    throw new Error('Invalid did:key encoding');
  }

  let number = 0n;
  for (const char of value) {
    const digit = BASE58.indexOf(char);
    if (digit < 0) throw new Error('Invalid base58 character in DID');
    number = number * 58n + BigInt(digit);
  }

  let hex = number.toString(16);
  if (hex.length % 2) hex = `0${hex}`;
  let body = number === 0n ? Buffer.alloc(0) : Buffer.from(hex, 'hex');

  let leadingZeroes = 0;
  while (leadingZeroes < value.length && value[leadingZeroes] === '1') leadingZeroes++;
  return Buffer.concat([Buffer.alloc(leadingZeroes), body]);
}

function getEd25519PublicKeyFromDid(did) {
  if (typeof did !== 'string' || !did.startsWith('did:key:z')) {
    throw new Error('Only did:key using base58btc is supported');
  }

  const fingerprint = did.slice('did:key:z'.length);
  const decoded = base58Decode(fingerprint);

  if (
    decoded.length !== 34 ||
    !decoded.subarray(0, 2).equals(ED25519_MULTICODEC)
  ) {
    throw new Error('DID must contain an Ed25519 public key');
  }

  const rawPublicKey = decoded.subarray(2);
  return crypto.createPublicKey({
    key: Buffer.concat([ED25519_SPKI_PREFIX, rawPublicKey]),
    format: 'der',
    type: 'spki'
  });
}

function isValidDidKey(did) {
  try {
    getEd25519PublicKeyFromDid(did);
    return true;
  } catch {
    return false;
  }
}

function verifyDidSignature({ did, challenge, signature }) {
  if (typeof signature !== 'string' || !/^[A-Za-z0-9+/]+={0,2}$/.test(signature)) {
    return false;
  }

  const signatureBytes = Buffer.from(signature, 'base64');
  if (signatureBytes.length !== 64) return false;

  const publicKey = getEd25519PublicKeyFromDid(did);
  // Both sides sign the exact JSON representation returned by the server.
  const message = Buffer.from(JSON.stringify(challenge), 'utf8');
  return crypto.verify(null, message, publicKey, signatureBytes);
}

module.exports = {
  getEd25519PublicKeyFromDid,
  isValidDidKey,
  verifyDidSignature
};
