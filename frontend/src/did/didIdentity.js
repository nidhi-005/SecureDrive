/**
 * SecureDrive self-managed did:key identity (Ed25519).
 *
 * The private CryptoKey is persisted as a non-extractable CryptoKey in
 * IndexedDB. A separately encrypted PKCS#8 backup is downloadable for
 * cross-device restoration. Never send private key material to the API.
 *
 * Requires a secure context (HTTPS or localhost) and WebCrypto Ed25519.
 */

const DB_NAME = 'secureDriveIdentity';
const DB_VERSION = 1;
const STORE_NAME = 'identities';
const IDENTITY_KEY = 'primary';
const DID_PREFIX = new Uint8Array([0xed, 0x01]); // multicodec ed25519-pub
const BACKUP_FORMAT = 'securedrive-did-backup';
const BACKUP_VERSION = 1;
const PBKDF2_ITERATIONS = 600_000;
const encoder = new TextEncoder();
const decoder = new TextDecoder();

function concatBytes(...parts) {
  const length = parts.reduce((sum, part) => sum + part.length, 0);
  const result = new Uint8Array(length);
  let offset = 0;
  for (const part of parts) {
    result.set(part, offset);
    offset += part.length;
  }
  return result;
}

function toBase64(bytes) {
  let binary = '';
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary);
}

function fromBase64(value) {
  const binary = atob(value);
  return Uint8Array.from(binary, char => char.charCodeAt(0));
}

// Bitcoin base58 alphabet, used by the base58-btc multibase encoding.
const BASE58_ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
function base58Encode(input) {
  if (!input.length) return '';
  const digits = [0];
  for (const byte of input) {
    let carry = byte;
    for (let i = 0; i < digits.length; i++) {
      carry += digits[i] << 8;
      digits[i] = carry % 58;
      carry = Math.floor(carry / 58);
    }
    while (carry > 0) {
      digits.push(carry % 58);
      carry = Math.floor(carry / 58);
    }
  }
  let result = '';
  for (const byte of input) {
    if (byte !== 0) break;
    result += '1';
  }
  for (let i = digits.length - 1; i >= 0; i--) result += BASE58_ALPHABET[digits[i]];
  return result;
}

function base58Decode(value) {
  if (typeof value !== 'string' || !value.length) throw new Error('Invalid base58 value');
  const bytes = [0];
  for (const char of value) {
    const digit = BASE58_ALPHABET.indexOf(char);
    if (digit < 0) throw new Error('Invalid base58 character');
    let carry = digit;
    for (let i = 0; i < bytes.length; i++) {
      carry += bytes[i] * 58;
      bytes[i] = carry & 0xff;
      carry >>= 8;
    }
    while (carry > 0) {
      bytes.push(carry & 0xff);
      carry >>= 8;
    }
  }
  let leadingZeroes = 0;
  while (leadingZeroes < value.length && value[leadingZeroes] === '1') leadingZeroes++;
  const body = bytes.reverse();
  if (body.length === 1 && body[0] === 0) body.length = 0;
  return new Uint8Array([...new Array(leadingZeroes).fill(0), ...body]);
}

function didFromPublicKey(rawPublicKey) {
  if (!(rawPublicKey instanceof Uint8Array) || rawPublicKey.length !== 32) {
    throw new Error('Ed25519 public key must be 32 bytes');
  }
  return `did:key:z${base58Encode(concatBytes(DID_PREFIX, rawPublicKey))}`;
}

function decodeDidKey(did) {
  if (typeof did !== 'string' || !did.startsWith('did:key:z')) {
    throw new Error('Unsupported DID. Expected did:key using base58btc.');
  }
  const decoded = base58Decode(did.slice('did:key:z'.length));
  if (decoded.length !== 34 || decoded[0] !== 0xed || decoded[1] !== 0x01) {
    throw new Error('DID does not contain an Ed25519 public key');
  }
  return decoded.slice(2);
}

function openDatabase() {
  return new Promise((resolve, reject) => {
    const request = indexedDB.open(DB_NAME, DB_VERSION);
    request.onupgradeneeded = () => {
      const db = request.result;
      if (!db.objectStoreNames.contains(STORE_NAME)) db.createObjectStore(STORE_NAME);
    };
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error || new Error('Could not open identity storage'));
  });
}

async function storeIdentity(identity) {
  const db = await openDatabase();
  try {
    await new Promise((resolve, reject) => {
      const tx = db.transaction(STORE_NAME, 'readwrite');
      tx.objectStore(STORE_NAME).put(identity, IDENTITY_KEY);
      tx.oncomplete = resolve;
      tx.onerror = () => reject(tx.error);
      tx.onabort = () => reject(tx.error || new Error('Identity storage transaction aborted'));
    });
  } finally {
    db.close();
  }
}

export async function getStoredIdentity() {
  const db = await openDatabase();
  try {
    return await new Promise((resolve, reject) => {
      const request = db.transaction(STORE_NAME, 'readonly').objectStore(STORE_NAME).get(IDENTITY_KEY);
      request.onsuccess = () => resolve(request.result || null);
      request.onerror = () => reject(request.error);
    });
  } finally {
    db.close();
  }
}

export async function createDidIdentity(backupPassword) {
  if (!globalThis.crypto?.subtle || !globalThis.indexedDB) {
    throw new Error('Secure identity storage requires a modern browser on HTTPS or localhost.');
  }
  let pair;
  try {
    pair = await crypto.subtle.generateKey({ name: 'Ed25519' }, true, ['sign', 'verify']);
  } catch {
    throw new Error('This browser does not support WebCrypto Ed25519. Please use a current version of Chrome, Edge, Firefox or Safari.');
  }

  const publicRaw = new Uint8Array(await crypto.subtle.exportKey('raw', pair.publicKey));
  const privatePkcs8 = new Uint8Array(await crypto.subtle.exportKey('pkcs8', pair.privateKey));
  const did = didFromPublicKey(publicRaw);
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const backupKey = await deriveBackupKey(backupPassword, salt);
  const ciphertext = new Uint8Array(await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv }, backupKey, privatePkcs8
  ));
  const backup = {
    format: BACKUP_FORMAT, version: BACKUP_VERSION, did, method: 'did:key',
    publicKey: toBase64(publicRaw),
    kdf: { name: 'PBKDF2', hash: 'SHA-256', iterations: PBKDF2_ITERATIONS, salt: toBase64(salt) },
    cipher: { name: 'AES-256-GCM', iv: toBase64(iv), ciphertext: toBase64(ciphertext) },
    createdAt: new Date().toISOString()
  };
  const privateKey = await crypto.subtle.importKey(
    'pkcs8', privatePkcs8, { name: 'Ed25519' }, false, ['sign']
  );
  privatePkcs8.fill(0);

  const identity = {
    did, method: 'did:key', publicKey: toBase64(publicRaw), privateKey, backup,
    createdAt: backup.createdAt
  };
  await storeIdentity(identity);
  return { did, method: identity.method, publicKey: identity.publicKey, createdAt: identity.createdAt };
}

export async function signDidChallenge(challenge) {
  const identity = await getStoredIdentity();
  if (!identity?.privateKey || !identity?.did) throw new Error('No local DID identity found on this device. Import your identity backup first.');
  const bytes = encoder.encode(JSON.stringify(challenge));
  const signature = new Uint8Array(await crypto.subtle.sign({ name: 'Ed25519' }, identity.privateKey, bytes));
  return { did: identity.did, signature: toBase64(signature) };
}

async function deriveBackupKey(password, salt) {
  if (typeof password !== 'string' || password.length < 12) {
    throw new Error('Identity backup password must contain at least 12 characters.');
  }
  const material = await crypto.subtle.importKey('raw', encoder.encode(password), 'PBKDF2', false, ['deriveKey']);
  return crypto.subtle.deriveKey(
    { name: 'PBKDF2', salt, iterations: PBKDF2_ITERATIONS, hash: 'SHA-256' },
    material,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt']
  );
}

export async function createEncryptedIdentityBackup() {
  const identity = await getStoredIdentity();
  if (!identity?.backup) throw new Error('No encrypted identity backup is available on this device.');
  return identity.backup;
}

export async function restoreEncryptedIdentityBackup(backup, password) {
  if (!backup || backup.format !== BACKUP_FORMAT || backup.version !== BACKUP_VERSION || backup.method !== 'did:key') {
    throw new Error('Unsupported or invalid SecureDrive identity backup.');
  }
  const publicRaw = fromBase64(backup.publicKey);
  if (didFromPublicKey(publicRaw) !== backup.did || !decodeDidKey(backup.did).every((byte, i) => byte === publicRaw[i])) {
    throw new Error('Backup DID and public key do not match.');
  }
  if (backup.kdf?.name !== 'PBKDF2' || backup.kdf?.iterations !== PBKDF2_ITERATIONS || backup.cipher?.name !== 'AES-256-GCM') {
    throw new Error('Unsupported backup cryptographic parameters.');
  }
  const key = await deriveBackupKey(password, fromBase64(backup.kdf.salt));
  let pkcs8;
  try {
    pkcs8 = new Uint8Array(await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: fromBase64(backup.cipher.iv) }, key, fromBase64(backup.cipher.ciphertext)
    ));
  } catch {
    throw new Error('Could not decrypt identity backup. Check the backup password.');
  }
  try {
    const privateKey = await crypto.subtle.importKey('pkcs8', pkcs8, { name: 'Ed25519' }, false, ['sign']);
    const identity = {
      did: backup.did,
      method: backup.method,
      publicKey: backup.publicKey,
      privateKey,
      backup,
      createdAt: backup.createdAt || new Date().toISOString()
    };
    // Confirm that the restored private key corresponds to the backup public key.
    const probe = encoder.encode('SecureDrive DID backup key-pair check');
    const signature = await crypto.subtle.sign({ name: 'Ed25519' }, privateKey, probe);
    const publicKey = await crypto.subtle.importKey('raw', publicRaw, { name: 'Ed25519' }, false, ['verify']);
    const valid = await crypto.subtle.verify({ name: 'Ed25519' }, publicKey, signature, probe);
    if (!valid) throw new Error('Backup private key does not match its DID.');
    await storeIdentity(identity);
    return { did: identity.did, method: identity.method, publicKey: identity.publicKey, createdAt: identity.createdAt };
  } finally {
    pkcs8.fill(0);
  }
}

export async function downloadIdentityBackup() {
  const backup = await createEncryptedIdentityBackup();
  const blob = new Blob([JSON.stringify(backup, null, 2)], { type: 'application/json' });
  const url = URL.createObjectURL(blob);
  const link = document.createElement('a');
  link.href = url;
  link.download = 'securedrive-identity-backup.json';
  document.body.appendChild(link);
  link.click();
  link.remove();
  URL.revokeObjectURL(url);
  return backup.did;
}

export function parseIdentityBackupFile(file) {
  return file.text().then(text => {
    try { return JSON.parse(text); }
    catch { throw new Error('The selected file is not a valid identity backup.'); }
  });
}
