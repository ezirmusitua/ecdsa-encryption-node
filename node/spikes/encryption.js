const crypto = require("crypto");
const fs = require("fs");
const path = require("path");
const x509 = require("@fidm/x509");
const ECKey = require("ec-key");
const {x963kdf} = require('./x963kdf');

/**
 * ## ECIES 流程
 *
 * ### Encryption
 *
 *   1. generate ephemeral-public-key and ephemeral-private-key
 *     {ephemeral-public-key, ephemeral-private-key} = KeyPair.generate()
 *   2. generate shared-secret from ephemeral-private-key & user-public-key by using ECDH algorithm
 *     shared-secret = ECDH(ephemeral-private-key, user-public-key)
 *   3. generate aes-key & mac-key using `kdf` algorithm
 *     {aes-key, mac-key} = kdf(shared-secret)
 *   4. encrypt message with aes-key using `AES` algorithm
 *     encrypted = AES.encrypt(aes-key, message)
 *   5. calculate encrypted message's mac value using `hmac` algorithm
 *     mac = hmac(encrypted, mac-key)
 *   6. generate output by concating ephemeral-public-key, encrypted, and mac value
 *     output = concat(ephemeral-public-key, encrypted, mac)
 *
 * ### Decryption
 *
 *   1. split output to get ephemeral-publick-key, encrypted and mac value
 *     {ephemeral-public-key, encrypted, mac} = split(output)
 *   2. generate shared secret from ephemeral-public-key & user-private-key by using ECDH algorithm
 *     shared-secret = ECDH(user-private-key, ephemeral-public-key)
 *   3. generate aes-key & mac-key using `kdf` algorithm
 *     {aes-key, mac-key} = kdf(shared-secret)
 *   4. calculate encrypted message's mac value using `hmac` algorithm
 *     nmac = hmac(encrypted, mac-key)
 *   5. decrypt encrypted data if mac value matched
 *     if nmac === mac: AES.decrypt(aes-key, encrypted)
 */

/**
 * @constant kSecKeyAlgorithmECIESEncryptionStandardX963SHA256AESGCM
    Legacy ECIES encryption or decryption, 
    use kSecKeyAlgorithmECIESEncryptionStandardVariableIVX963SHA256AESGCM in new code.
    Encryption is done using AES-GCM with key negotiated by kSecKeyAlgorithmECDHKeyExchangeStandardX963SHA256.
    AES Key size is 128bit for EC keys <=256bit and 256bit for bigger EC keys. 
    Ephemeral public key data is used as sharedInfo for KDF.
    AES-GCM uses 16 bytes long TAG and all-zero 16 bytes long IV (initialization vector).
 */

const CONTENT_ENCODING = "base64";
const EC_ALGO = "P-256";
const KDF_ALGO = 'x963kdf';
const KDF_DIGEST_ALGO = 'sha256';
const HMAC_ALGO = 'sha256';
const HMAC_DIGEST_BYTE_LEN = 32;
// const PBKDF2_IV_BYTE_LEN = 16;
const PBKDF2_IV_BYTE_LEN = 0;
const HMAC_IV_BYTE_LENGTH = 16;
// const AES_IV_LEN = 0;
const AES_IV_LEN = 16;
const AES_GCM_TAG_LEN = 16;
const UNCOMPRESSED_PUBLIC_KEY_BYTE_LEN = 65;

function decideAESGCMAlgo() {
  // if (pubKey.length * 8 > 256) return "aes-128-gcm";
  // return "aes-128-gcm";
  return 'aes-128-gcm';
}

function decideKDFKeyLen() {
  // if (pubKey.length * 8 > 256) return (128 / 8) + HMAC_IV_BYTE_LENGTH;
  // return (128 / 8) + HMAC_IV_BYTE_LENGTH;
  return 16;
}

function kdf() {
  if (KDF_ALGO === 'x963kdf') {

  } else {
    return x963kdf(sharedSecret, KDF_DIGEST_ALGO, decideKDFKeyLen(), "");
  }
}

function aesEncrypt(key, plainText, aesAlgo) {
  // const iv = crypto.randomBytes(AES_IV_LEN);
  const iv = Buffer.from(Array.from({length: AES_IV_LEN}).map(() => 0));
  const cipher = crypto.createCipheriv(aesAlgo, key, iv);
  const encrypted = Buffer.concat([cipher.update(plainText), cipher.final()]);
  const tag = cipher.getAuthTag();
  return Buffer.concat([encrypted, tag]);
}

function aesDecrypt(key, cipherText, aesAlgo) {
  // const iv = cipherText.slice(0, AES_IV_LEN);
  const iv = Buffer.from(Array.from({length: AES_IV_LEN}).map(() => 0));
  const ciphered = cipherText.slice(0, -AES_GCM_TAG_LEN);
  const tag = cipherText.slice(-AES_GCM_TAG_LEN);
  const decipher = crypto.createDecipheriv(aesAlgo, key, iv);
  decipher.setAuthTag(tag);
  return Buffer.concat([decipher.update(ciphered), decipher.final()]);
}

function encrypt(senderPublicKey, msg) {
  // generate ephemeral key pair
  const ephemeralKey = ECKey.createECKey(EC_ALGO);

  // generate shared secret
  const sharedSecret = ephemeralKey.computeSecret(senderPublicKey);

  // derive aes & mac key using kdf algorithm
  // const pbkdfIV = crypto.randomBytes(PBKDF2_IV_BYTE_LEN);
  // const fullKey = crypto.pbkdf2Sync(
  //   sharedSecret,
  //   pbkdfIV,
  //   PBKDF2_ITER_COUNT,
  //   decidePBKDF2KeyLen(senderPublicKey),
  //   PBKDF2_DIGEST_ALGO
  // );

  const derivedKey = x963kdf(sharedSecret, KDF_DIGEST_ALGO, decideKDFKeyLen(senderPublicKey), "");
  const aesKey = derivedKey.slice(0, -HMAC_IV_BYTE_LENGTH);
  // const macKey = fullKey.slice(-HMAC_IV_BYTE_LENGTH);
  // encrypt with aes-key using AES
  const encrypted = aesEncrypt(aesKey, msg, decideAESGCMAlgo(senderPublicKey));
  // calculate mac value
  // const mac = crypto.createHmac(HMAC_ALGO, macKey).update(pbkdfIV).update(encrypted).digest();
  // const mac = crypto.createHmac(HMAC_ALGO, macKey).update(pbkdfIV).update(encrypted).digest();

  // const mac = crypto.createHmac(HMAC_ALGO, macKey).update(encrypted).digest();

  // return Buffer.concat([pbkdfIV, ephemeralKey.publicCodePoint, encrypted, mac]).toString(
  //   CONTENT_ENCODING
  // );
  return Buffer.concat([ephemeralKey.publicCodePoint, encrypted]).toString(
    CONTENT_ENCODING
  );
}

function decrypt(recvPrvKeyPem, msg) {
  const decodedMsg = Buffer.from(msg, CONTENT_ENCODING);
  const recvPrvKey = new ECKey(recvPrvKeyPem, "pem");
  const pbkdfIV = decodedMsg.slice(0, PBKDF2_IV_BYTE_LEN);
  const senderPublicKey = decodedMsg.slice(PBKDF2_IV_BYTE_LEN, PBKDF2_IV_BYTE_LEN + UNCOMPRESSED_PUBLIC_KEY_BYTE_LEN);
  // const encrypted = decodedMsg.slice(PBKDF2_IV_BYTE_LEN + UNCOMPRESSED_PUBLIC_KEY_BYTE_LEN, -HMAC_DIGEST_BYTE_LEN);

  const encrypted = decodedMsg.slice(PBKDF2_IV_BYTE_LEN + UNCOMPRESSED_PUBLIC_KEY_BYTE_LEN);

  // const mac = decodedMsg.slice(-HMAC_DIGEST_BYTE_LEN);
  
  const sharedSecret = recvPrvKey.computeSecret(senderPublicKey);

  // derive aes & mac key using kdf algorithm
  // const fullKey = crypto.pbkdf2Sync(
  //   sharedSecret,
  //   pbkdfIV,
  //   PBKDF2_ITER_COUNT,
  //   decidePBKDF2KeyLen(senderPublicKey),
  //   PBKDF2_DIGEST_ALGO
  // );
  const fullKey = x963kdf(sharedSecret, KDF_DIGEST_ALGO, decideKDFKeyLen(senderPublicKey), "");
  const macKey = fullKey.slice(-HMAC_IV_BYTE_LENGTH);
  const aesKey = fullKey.slice(0, -HMAC_IV_BYTE_LENGTH);
  // const currentMac = crypto.createHmac(HMAC_ALGO, macKey).update(pbkdfIV).update(encrypted).digest();

  // const currentMac = crypto.createHmac(HMAC_ALGO, macKey).update(encrypted).digest();
  // if (currentMac.toString() !== mac.toString()) throw new Error("Can no decrypt, invalid mac");

  return aesDecrypt(aesKey, encrypted, decideAESGCMAlgo(senderPublicKey)).toString();
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
  console.debug(publicKeyBuffer.length);
  const original = "hello world";
  console.log("Original:  " + original);
  const encryptedB64 = encrypt(publicKeyBuffer, original);
  console.log("\n\nEncrypted: " + encryptedB64);
  const decrypted = decrypt(privateKeyBuffer, encryptedB64);
  console.log("\n\nDecrypted: " + decrypted);
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

main();
// verifyJava();
