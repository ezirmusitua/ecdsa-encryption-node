/**
 * @constant kSecKeyAlgorithmECIESEncryptionStandardX963SHA256AESGCM
 * @desc Legacy ECIES encryption or decryption, 
 *  use kSecKeyAlgorithmECIESEncryptionStandardVariableIVX963SHA256AESGCM in new code.
 *  [x] Encryption is done using AES-GCM with key negotiated by kSecKeyAlgorithmECDHKeyExchangeStandardX963SHA256.
 *  [x] AES Key size is 128bit for EC keys <=256bit and 256bit for bigger EC keys.  
 *  [x] Ephemeral public key data is used as sharedInfo for KDF.
 *  AES-GCM uses 16 bytes long TAG and all-zero 16 bytes long IV (initialization vector).
 **/

const crypto = require("crypto");
const fs = require("fs");
const path = require("path");
const x509 = require("@fidm/x509");
const ECKey = require("ec-key");
const { x963kdf } = require("./x963kdf");

const CONTENT_ENCODING = "base64";
const EC_ALGO = "P-256";
const KDF_DIGEST_ALGO = "sha256";
const UNCOMPRESSED_PUBLIC_KEY_BYTE_LEN = 65;
const AES_KEY_BIT_LEN = 128;
const AES_ALGO = `aes-${AES_KEY_BIT_LEN}-gcm`;
const AES_KEY_LEN = AES_KEY_BIT_LEN / 8; // 32
const AES_IV_LEN = 16;
const AES_GCM_TAG_LEN = 16;
const KDF_KEY_LEN = AES_KEY_LEN + AES_IV_LEN;


function aesEncrypt(key, iv, plainText) {
  const cipher = crypto.createCipheriv(AES_ALGO, key, iv);
  const encrypted = Buffer.concat([cipher.update(plainText), cipher.final()]);
  const tag = cipher.getAuthTag();
  return Buffer.concat([encrypted, tag]);
}

function aesDecrypt(key, iv, cipherText) {
  const ciphered = cipherText.slice(0, -AES_GCM_TAG_LEN);
  const tag = cipherText.slice(-AES_GCM_TAG_LEN);
  const decipher = crypto.createDecipheriv(AES_ALGO, key, iv);
  decipher.setAuthTag(tag);
  return Buffer.concat([decipher.update(ciphered), decipher.final()]);
}

function encrypt(senderPublicKey, msg) {
  // generate ephemeral key pair and sharedSecret
  const ephemeralKey = ECKey.createECKey(EC_ALGO);
  const ephemeralPublicKey = ephemeralKey.publicCodePoint;
  console.log('\n\t\tencrypt sender public key: ', senderPublicKey.toString('base64'));
  console.log('\n\t\tencrypt ephemeral public key: ', ephemeralPublicKey.toString('base64'));
  const sharedSecret = ephemeralKey.computeSecret(senderPublicKey);
  // derive aes & mac key using kdf algorithm
  const derivedKey = x963kdf(sharedSecret, KDF_DIGEST_ALGO, KDF_KEY_LEN, ephemeralPublicKey);
  const aesKey = derivedKey.slice(0, AES_KEY_LEN);
  const aesIV = derivedKey.slice(-AES_IV_LEN);
  console.debug('\n\t\taesKey: ', aesKey.toString('base64'));
  console.debug('\n\t\taesIV: ', aesIV.toString('base64'));
  // encrypt with aes-key using AES
  const encrypted = aesEncrypt(aesKey, aesIV, msg);
  return Buffer.concat([ephemeralPublicKey, encrypted]).toString(
    CONTENT_ENCODING
  );
}

function decrypt(recvPrvKeyPem, msg) {
  const decodedMsg = Buffer.from(msg, CONTENT_ENCODING);
  const recvPrvKey = new ECKey(recvPrvKeyPem, "pem");
  const ephemeralPublicKey = decodedMsg.slice(0, UNCOMPRESSED_PUBLIC_KEY_BYTE_LEN);

  console.debug('\n\t\tdecrypt ephemeral public key: ', ephemeralPublicKey.toString('hex'));
  console.debug('\n\t\tdecrypt ephemeral public key: ', ephemeralPublicKey.toString('base64'));

  const sharedSecret = recvPrvKey.computeSecret(ephemeralPublicKey);
  const derivedKey = x963kdf(sharedSecret, KDF_DIGEST_ALGO, KDF_KEY_LEN, ephemeralPublicKey);
  const aesKey = derivedKey.slice(0, AES_KEY_LEN);
  const aesIV = derivedKey.slice(-AES_IV_LEN);
  const encrypted = decodedMsg.slice(UNCOMPRESSED_PUBLIC_KEY_BYTE_LEN);
  console.debug('\n\t\taesKey: ', aesKey.toString('base64'));
  console.debug('\n\t\taesIV: ', aesIV.toString('base64'));
  console.debug('\n\t\tMessage: ', encrypted);
  return aesDecrypt(aesKey, aesIV, encrypted).toString();
}

function main() {
  const privateKeyBuffer = fs.readFileSync(
    path.join(__dirname, "..", "..", "materials", "key.pem")
  );
  const certBuffer = fs.readFileSync(
    path.join(__dirname, "..", "..", "materials", "cert.pem")
  );
  const cert = x509.Certificate.fromPEM(certBuffer);
  const publicKeyBuffer = cert.publicKey.keyRaw;
  const original = "hello world";
  console.info("ECIES Encryption")
  console.info("\n\tOriginal:  " + original);
  const encryptedB64 = encrypt(publicKeyBuffer, original, {});
  console.info("\n\tEncrypted: " + encryptedB64);
  console.info("\n\nECIES Encryption")
  const decrypted = decrypt(privateKeyBuffer, encryptedB64, {});
  console.info("\n\tDecrypted: " + decrypted);
}


function verifyJava() {
  const privateKeyBuffer = fs.readFileSync(
    path.join(__dirname, "..", "..", "materials", "key.pem")
  );
  const encryptedB64 =
    "BJuDHleDqzjelz2hoZ1bOktMOZIRfCwljIFzYkg5t8zZOC5gQygOZHofI7Ms6MpNrDrHPP9oOUkEBFk1z9mSAadsdIlaRMt+/zcu04xe40JG8dEvEUsritL6wGU4EMv/6iIi06Cy8mEPxKq8mdU+ZewNI1nDl9OmK94lTJhhyisDWCo=";
  console.log("Encrypted: " + encryptedB64);
  const decrypted = decrypt(privateKeyBuffer, encryptedB64);
  console.log("Decrypted: " + decrypted);
  console.log("Original:  " + "hello world ~~~~~~~~~~~~~~~~~~~~~~");
}

function verifySwiftBlueECC() {
  const encryptedB64 =
  "BL9U1upIvSJq5N3meR1tootTuIg5jimasAs4PVVPyJFYLomTkm1peq4zDfvaaWVJD2MQNF/DMzf6m/kUmgqFRtmRbd+ifn00kpQfRZQ7B3yQZjq2q7Z95F9t7ZY=";
  const privateKeyBuffer = fs.readFileSync(
    path.join(__dirname, "..", "..", "materials", "key.pem")
  );
  console.log("Encrypted: " + encryptedB64);
  const decrypted = decrypt(privateKeyBuffer, encryptedB64);
  console.log("Decrypted: " + decrypted);
  console.log("Original:  " + "hello world ~~~~~~~~~~~~~~~~~~~~~~");
}

function verifyJavascript(encrypted) {
  const encryptedB64 = encrypted;
  const privateKeyBuffer = fs.readFileSync(
    path.join(__dirname, "..", "..", "materials", "key.pem")
  );
  console.log("Encrypted: " + encryptedB64);
  const decrypted = decrypt(privateKeyBuffer, encryptedB64);
  console.log("Decrypted: " + decrypted);
  console.log("Original:  " + "hello world");
}

// main();
verifyJavascript(
  "BPUIgat55VKDORTxM0dgoMHF2As+d+DgQMkQCYLolUkOptlEmuWgyThZMpKBSlt9TDdSyGZBauHtlexd9T+p6IRip435lZzqcb1hkKcNTeKnjS0sCcMzmJFORxg="
);
