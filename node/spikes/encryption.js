const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const x509 = require('@fidm/x509');
const ECKey = require('ec-key');

const EC_ALGO = 'P-256';
const AES_ALGO = "aes-256-gcm";
const AES_IV_LEN = 16;
const AES_GCM_TAG_LEN = 16;
const UNCOMPRESSED_PUBLIC_KEY_SIZE = 65;
const CONTENT_ENCODING = 'base64';

function aesEncrypt(key, plainText) {
  const iv = crypto.randomBytes(AES_IV_LEN);
  const cipher = crypto.createCipheriv(AES_ALGO, key, iv);
  const encrypted = Buffer.concat([cipher.update(plainText), cipher.final()]);
  const tag = cipher.getAuthTag();
  return Buffer.concat([iv, tag, encrypted]);
}

function aesDecrypt(key, cipherText) {
  const nonce = cipherText.slice(0, AES_IV_LEN);
  const tag = cipherText.slice(AES_IV_LEN, AES_IV_LEN + AES_GCM_TAG_LEN);
  const ciphered = cipherText.slice(AES_IV_LEN + AES_GCM_TAG_LEN);
  const decipher = crypto.createDecipheriv(AES_ALGO, key, nonce);
  decipher.setAuthTag(tag);
  return Buffer.concat([decipher.update(ciphered), decipher.final()]);
}

function encrypt(senderPublicKey, msg) {
  const ephemeralKey = ECKey.createECKey(EC_ALGO);
  const sharedSecret = ephemeralKey.computeSecret(senderPublicKey);
  const encrypted = aesEncrypt(sharedSecret, msg);
  return Buffer.concat([
    ephemeralKey.publicCodePoint,
    encrypted,
  ]).toString(CONTENT_ENCODING);
}

function decrypt(recvPrvKeyPem, msg) {
  const decodedMsg = Buffer.from(msg, CONTENT_ENCODING);
  const recvPrvKey = new ECKey(recvPrvKeyPem, 'pem');
  const senderPubKey = decodedMsg.slice(0, UNCOMPRESSED_PUBLIC_KEY_SIZE);
  const encrypted = decodedMsg.slice(UNCOMPRESSED_PUBLIC_KEY_SIZE);
  const sharedSecret = recvPrvKey.computeSecret(senderPubKey);
  return aesDecrypt(sharedSecret, encrypted).toString();
}

function main() {
  const privateKeyBuffer = fs.readFileSync(path.join(__dirname, '..', '..', 'materials', 'key.pem'));
  const certBuffer = fs.readFileSync(path.join(__dirname, '..', '..', 'materials', 'cert.pem'));
  const cert = x509.Certificate.fromPEM(certBuffer);
  const publicKeyBuffer = cert.publicKey.keyRaw;
  const original = 'hello world ~~~~~~~~~~~~~~~~~~~~~~';
  console.log("Original:  " + original);
  const encryptedB64 = encrypt(publicKeyBuffer, original);
  console.log("Encrypted: " + encryptedB64);
  const decrypted = decrypt(privateKeyBuffer, encryptedB64);
  console.log("Decrypted: " + decrypted);
}

function verifyJava() {
  const privateKeyBuffer = fs.readFileSync(path.join(__dirname, '..', '..', 'materials', 'key.pem'));
  const encryptedB64 = 'BJuDHleDqzjelz2hoZ1bOktMOZIRfCwljIFzYkg5t8zZOC5gQygOZHofI7Ms6MpNrDrHPP9oOUkEBFk1z9mSAadsdIlaRMt+/zcu04xe40JG8dEvEUsritL6wGU4EMv/6iIi06Cy8mEPxKq8mdU+ZewNI1nDl9OmK94lTJhhyisDWCo=';
  console.log("Encrypted: " + encryptedB64);
  const decrypted = decrypt(privateKeyBuffer, encryptedB64);
  console.log("Decrypted: " + decrypted);
  console.log("Original:  " + "hello world ~~~~~~~~~~~~~~~~~~~~~~");
}

main();
verifyJava();
