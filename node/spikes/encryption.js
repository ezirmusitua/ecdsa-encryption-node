const crypto = require("crypto");
const fs = require("fs");
const path = require("path");
const x509 = require("@fidm/x509");
const ECKey = require("ec-key");
const { x963kdf } = require("./x963kdf");

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



const CONTENT_ENCODING = "base64";
const EC_ALGO = "P-256";
const KDF_ALGO = "x963kdf";
const KDF_DIGEST_ALGO = "sha256";
const HMAC_ALGO = "sha256";
const HMAC_DIGEST_BYTE_LEN = 32;
const PBKDF2_IV_BYTE_LEN = 16;
const HMAC_IV_BYTE_LENGTH = 16;
const AES_IV_LEN = 16;
const AES_GCM_TAG_LEN = 16;
const UNCOMPRESSED_PUBLIC_KEY_BYTE_LEN = 65;

function decideAESGCMAlgo() {
  // if (pubKey.length * 8 > 256) return "aes-128-gcm";
  // return "aes-128-gcm";
  return "aes-128-gcm";
}

function decideKDFKeyLen(hmacIvLen = 0) {
  // if (pubKey.length * 8 > 256) return (128 / 8) + HMAC_IV_BYTE_LENGTH;
  // return (128 / 8) + HMAC_IV_BYTE_LENGTH;
  return 16 + hmacIvLen;
}

function kdf(
  algo,
  secret,
  keyLen,
  {
    digestAlgo = KDF_DIGEST_ALGO,
    sharedInfo = "",
    iv = new Buffer([]),
    iterCount = 1024
  }
) {
  if (algo === "x963kdf")
    return x963kdf(secret, digestAlgo, keyLen, sharedInfo);
  return crypto.pbkdf2Sync(secret, iv, iterCount, keyLen, digestAlgo);
}

function aesEncrypt(key, plainText, aesAlgo, iv) {
  // const iv = Buffer.from(Array.from({ length: AES_IV_LEN }).map(() => 0));
  console.debug(iv);
  const cipher = crypto.createCipheriv(aesAlgo, key, iv);
  const encrypted = Buffer.concat([cipher.update(plainText), cipher.final()]);
  const tag = cipher.getAuthTag();
  return Buffer.concat([encrypted, tag]);
}

function aesDecrypt(key, cipherText, aesAlgo, iv) {
  // const iv = cipherText.slice(0, AES_IV_LEN);
  // const iv = Buffer.from(Array.from({ length: AES_IV_LEN }).map(() => 0));
  const ciphered = cipherText.slice(0, -AES_GCM_TAG_LEN);
  const tag = cipherText.slice(-AES_GCM_TAG_LEN);
  const decipher = crypto.createDecipheriv(aesAlgo, key, iv);
  decipher.setAuthTag(tag);
  return Buffer.concat([decipher.update(ciphered), decipher.final()]);
}

function encrypt(
  senderPublicKey,
  msg,
  { kdfAlgo = "x963kdf", hmac = false, hmacIvLen = HMAC_IV_BYTE_LENGTH }
) {
  // generate ephemeral key pair and sharedSecret
  const ephemeralKey = ECKey.createECKey(EC_ALGO);
  const sharedSecret = ephemeralKey.computeSecret(senderPublicKey);
  // derive aes & mac key using kdf algorithm
  if (hmac) {
    const pbkdfIV = crypto.randomBytes(PBKDF2_IV_BYTE_LEN);
    const derivedKey = kdf(
      KDF_ALGO,
      sharedSecret,
      decideKDFKeyLen(senderPublicKey, hmacIvLen),
      KDF_DIGEST_ALGO,
      { iv: pbkdfIV }
    );
    const macKey = derivedKey.slice(-hmacIvLen);
    const macHandler = crypto.createHmac(HMAC_ALGO, macKey);
    const aesKey = derivedKey.slice(0, -hmacIvLen);
    // encrypt with aes-key using AES
    const encrypted = aesEncrypt(
      aesKey,
      msg,
      decideAESGCMAlgo(senderPublicKey)
    );
    macHandler.update(pbkdfIV ? kdfAlgo !== "x963kdf" : new Buffer([]));
    const mac = macHandler.update(encrypted).digest();
    return Buffer.concat([
      pbkdfIV ? kdfAlgo !== "x963kdf" : new Buffer([]),
      ephemeralKey.publicCodePoint,
      encrypted,
      mac
    ]).toString(CONTENT_ENCODING);
  } else {
    const derivedKey = kdf(
      KDF_ALGO,
      sharedSecret,
      decideKDFKeyLen(senderPublicKey, hmacIvLen),
      KDF_DIGEST_ALGO
    );
    const aesKey = derivedKey.slice(0, -hmacIvLen);
    // encrypt with aes-key using AES
    const encrypted = aesEncrypt(
      aesKey,
      msg,
      decideAESGCMAlgo(senderPublicKey)
    );
    return Buffer.concat([ephemeralKey.publicCodePoint, encrypted]).toString(
      CONTENT_ENCODING
    );
  }
}

function decrypt(
  recvPrvKeyPem,
  msg,
  { kdfAlgo = "x963kdf", hmac = false, hmacIvLen = HMAC_IV_BYTE_LENGTH }
) {
  const decodedMsg = Buffer.from(msg, CONTENT_ENCODING);
  const recvPrvKey = new ECKey(recvPrvKeyPem, "pem");
  const isPBKDF = kdfAlgo === "x963kdf";
  const pbkdfIVLen = isPBKDF ? PBKDF2_IV_BYTE_LEN : 0;
  const pbkdfIV = decodedMsg.slice(pbkdfIVLen, PBKDF2_IV_BYTE_LEN);
  const senderPublicKey = decodedMsg.slice(
    pbkdfIVLen,
    pbkdfIVLen + UNCOMPRESSED_PUBLIC_KEY_BYTE_LEN
  );
  const macLen = hmac ? HMAC_DIGEST_BYTE_LEN : 0;
  const encrypted = decodedMsg.slice(
    pbkdfIVLen + UNCOMPRESSED_PUBLIC_KEY_BYTE_LEN,
    -macLen
  );
  const encrypted = decodedMsg.slice(
    pbkdfIVLen + UNCOMPRESSED_PUBLIC_KEY_BYTE_LEN
  );
  const mac = decodedMsg.slice(-HMAC_DIGEST_BYTE_LEN);
  const sharedSecret = recvPrvKey.computeSecret(senderPublicKey);
  const derivedKey = kdf(
    KDF_ALGO,
    sharedSecret,
    decideKDFKeyLen(senderPublicKey, hmacIvLen),
    KDF_DIGEST_ALGO,
    { iv: pbkdfIV }
  );
  const aesKey = fullKey.slice(0, -HMAC_IV_BYTE_LENGTH);
  if (hmac) {
    const macKey = fullKey.slice(-HMAC_IV_BYTE_LENGTH);
    const currentMac = crypto.createHmac(HMAC_ALGO, macKey).update(pbkdfIV).update(encrypted).digest();
    if (currentMac.toString() !== mac.toString()) throw new Error("Can no decrypt, invalid mac");
  }
  return aesDecrypt(
    aesKey,
    encrypted,
    decideAESGCMAlgo(senderPublicKey)
  ).toString();
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
  console.info("Original:  " + original);
  const encryptedB64 = encrypt(publicKeyBuffer, original, {});
  console.info("\n\nEncrypted: " + encryptedB64);
  const decrypted = decrypt(privateKeyBuffer, encryptedB64, {});
  console.info("\n\nDecrypted: " + decrypted);
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
