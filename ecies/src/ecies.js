const ECKey = require("ec-key");

const EC_ALGOS = {
  secp256r1: "prime256v1",
  prime256v1: "prime256v1",
  "P-256": "prime256v1",
  secp256k1: "secp256k1",
  "P-256K": "secp256k1",
  "P-384": "secp384r1",
  secp384r1: "secp384r1",
  "P-521": "secp521r1",
  secp521r1: "secp521r1"
};

class ECIES {
  constructor(ecAlgo, aesKeyBytesLen, aesIvBytesLen) {
    this._ecAlgo = ecAlgo;
    if (!this._ecAlgo) {
      throw new Error("Invalid EC Curve Name: " + ecAlgo);
    }
    this._aesKeyBLen = aesKeyBytesLen;
    this._aesIvBLen = aesIvBytesLen;
    this._keyBLength = this._aesKeyBLen + this._aesIvBLen;

    this._plaintext = null;
    this._sharedSecret = null;
    this._derivedKey = null;
    this._ciphertext = null;

    this.ecdh = null;
    this.kdfHandler = null;
    this.aesHandler = null;
    this.outputHandler = null;
  }

  setInputHandler(inputHandler) {
    this.inputHandler = inputHandler;
    return this;
  }

  setKdf(kdfHandler) {
    this._kdfHandler = kdfHandler;
    return this;
  }

  setAesHandler(aesHandler) {
    this.aesHandler = aesHandler;
    return this;
  }

  setOutputHandler(outputHandler) {
    this.outputHandler = outputHandler;
    return this;
  }

  setPlaintext(plaintext) {
    this._plaintext = plaintext;
    return this;
  }

  setCiphertext(ciphertext) {
    this._ciphertext = ciphertext;
    return this;
  }

  computeSecret(userPubKey, userPrivateKey) {
    if (!userPubKey && !userPrivateKey) {
      throw new Error(
        "Must Pass User Public Or Private Key To Generate SharedSecret"
      );
    }
    if (userPubKey) {
      this.ecdh = ECKey.createECKey(this._ecAlgo);
      this._sharedSecret = this.ecdh.computeSecret(userPubKey);
      return this;
    }
    this.ecdh = new ECKey(userPrivateKey, "pem");
    if (!this.inputHandler) {
      throw new Error("Set Input Handler Before Compute Shared Secret");
    }
    if (!this._ciphertext) {
      throw new Error("Set Cipher Text Before Compute Shared Secret");
    }
    const ephemeralPublicKey = this.inputHandler.getEphemeralPublicKey(
      this._ciphertext
    );
    this._sharedSecret = this.ecdh.computeSecret(ephemeralPublicKey);
    return this;
  }

  deriveKey(sharedInfo) {
    if (!this._kdfHandler) {
      throw new Error("Set KDF Handler Before Derive Key");
    }
    this._derivedKey = this._kdfHandler.derive(
      this._sharedSecret,
      this._keyBLength,
      sharedInfo || new Buffer([])
    );
    return this;
  }

  encrypt() {
    if (!this.aesHandler) {
      throw new Error("Set AES Encryption Handler Before Encrypt");
    }
    const aesKey = this._derivedKey.slice(0, this._aesKeyBLen);
    const aesIv = this._derivedKey.slice(-this._aesIvBLen);
    const message = this.inputHandler.getMessage(this._plaintext);
    this.aesHandler.encrypt(aesKey, aesIv, message);
    return this;
  }

  decrypt() {
    if (!this.aesHandler) {
      throw new Error("Set Symmertric Encryption Handler Before Decrypt");
    }
    const aesKey = this._derivedKey.slice(0, this._aesKeyBLen);
    const aesIv = this._derivedKey.slice(-this._aesIvBLen);
    const encrypted = this.inputHandler.getEncrypted(this._ciphertext);
    this.aesHandler.decrypt(aesKey, aesIv, encrypted);
    return this;
  }

  outputEnc() {
    return this.outputHandler.buildEnc(this);
  }

  outputDec() {
    return this.outputHandler.buildDec(this);
  }
}

module.exports = {
  EC_ALGOS,
  ECIES
};
