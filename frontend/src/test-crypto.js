import {
  deriveKeyFromPassword,
  generateMasterKey,
  wrapMasterKey,
  unwrapMasterKey,
  encryptFile,
  decryptFile
} from './crypto.js';

async function testFullFlow() {
  console.log("Starting crypto test...");

  // Simulate signup
  const password   = "mypassword123";
  const derivedKey = await deriveKeyFromPassword(password);
  const masterKey  = await generateMasterKey();
  const { wrappedMasterKey, masterKeyIV } = await wrapMasterKey(masterKey, derivedKey);

  console.log("✅ Signup: Master Key generated and wrapped");
  console.log("wrappedMasterKey:", wrappedMasterKey); // this goes to MongoDB
  console.log("masterKeyIV:", masterKeyIV);           // this goes to MongoDB

  // Simulate login — reconstruct Master Key from stored values
  const derivedKey2  = await deriveKeyFromPassword(password);
  const masterKey2   = await unwrapMasterKey(wrappedMasterKey, masterKeyIV, derivedKey2);
  console.log("✅ Login: Master Key unwrapped successfully");

  // Simulate file encrypt → decrypt
  const originalText   = "Hello SecureDrive!";
  const originalBuffer = new TextEncoder().encode(originalText).buffer;

  const { encryptedFile, wrappedCEK, fileIV, cekIV } = await encryptFile(originalBuffer, masterKey2);
  console.log("✅ File encrypted — size:", encryptedFile.byteLength, "bytes");

  const decryptedBuffer = await decryptFile(encryptedFile, wrappedCEK, fileIV, cekIV, masterKey2);
  const decryptedText   = new TextDecoder().decode(decryptedBuffer);

  console.log("✅ File decrypted:", decryptedText);
  console.log(decryptedText === originalText ? "🎉 PERFECT MATCH" : "❌ MISMATCH");
}

testFullFlow().catch(console.error);