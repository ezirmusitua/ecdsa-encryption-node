const { ECIES, EC_ALGOS } = require("./ecies");
const { X963KDF } = require("./kdf");
const { AES_GCM } = require("./aes");

const AES_GCM_IV_BYTES_LEN = 16;
const KDF_HASH_ALGO = "sha256";

class InputHandler {
  constructor(pubBytesLen) {
    this.pubBytesLen = pubBytesLen;
  }
  formatInput(i, enc = "utf8") {
    if (i instanceof Buffer) return i;
    return Buffer.from(i, enc);
  }
  getMessage(i) {
    return this.formatInput(i);
  }
  getEphemeralPublicKey(i) {
    return this.formatInput(i, "base64").slice(0, this.pubBytesLen);
  }
  getEncrypted(i) {
    return this.formatInput(i, "base64").slice(this.pubBytesLen);
  }
}

class OutputHandler {
  constructor() {}
  concat(eciesInstance) {
    if (eciesInstance.aesHandler.ciphertext) return eciesInstance.aesHandler.plaintext.toString();
    const publicCodePoint = eciesInstance.ecdh.publicCodePoint;
    const encrypted = eciesInstance.aesHandler.ciphertext;
    const tag = eciesInstance.aesHandler.tag;
    return Buffer.concat([publicCodePoint, encrypted, tag]).toString("base64");
  }
}

function createECIESInstance(ecAlgo, aesKeyBytesLen, pubBytesLen) {
  const kdfHandler = new X963KDF(KDF_HASH_ALGO);
  const aesHandler = new AES_GCM(aesKeyBytesLen, AES_GCM_IV_BYTES_LEN);
  const ecies = new ECIES(
    ecAlgo,
    aesKeyBytesLen,
    AES_GCM_IV_BYTES_LEN
  );
  return ecies
    .setInputHandler(new InputHandler(pubBytesLen))
    .setKdf(kdfHandler)
    .setAesHandler(aesHandler)
    .setOutputHandler(new OutputHandler());
}

function kSecKeyAlgorithmECIESEncryptionCofactorX963SHA256AESGCM(ecAlgo) {
  let pubBytesLen = 65;
  let aesKeyBytesLen = 16;
  const formattedEcAlgo = EC_ALGOS[ecAlgo];
  if (["secp256k1", "prime256v1"].indexOf(formattedEcAlgo) === -1) {
    aesKeyBytesLen = 32;
    // TODO: Update public key bytes length
    // pubBytesLen = ??;
  }

  return {
    encrypt(pubKey, message) {
      const ecies = createECIESInstance(formattedEcAlgo, aesKeyBytesLen, pubBytesLen);
      return ecies
        .setPlaintext(message)
        .computeSecret(pubKey)
        .deriveKey(ecies.ecdh.publicCodePoint)
        .encrypt()
        .output();
    },
    decrypt(prvKey, ciphertext) {
      const ecies = createECIESInstance(formattedEcAlgo, aesKeyBytesLen, pubBytesLen);
      return ecies
        .setCiphertext(ciphertext)
        .computeSecret(null, prvKey)
        .deriveKey(ecies.inputHandler.getEphemeralPublicKey(ciphertext))
        .decrypt()
        .output();
    }
  };
}

module.exports = kSecKeyAlgorithmECIESEncryptionCofactorX963SHA256AESGCM;
