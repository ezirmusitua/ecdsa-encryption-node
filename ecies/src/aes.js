const AES_GCM_TAG_LEN = 16;

const crypto = require("crypto");

class GCM {
  constructor(keyBytesLen = 16, tagBytesLen = 16) {
    this.tagBlen = tagBytesLen;
    this.keyBLen = keyBytesLen;
    this.algo = `aes-${keyBytesLen * 8}-gcm`;
    this.plaintext = null;
    this.ciphertext = null;
    this.tag = null;
    this._completed = false;
  }

  encrypt(key, iv, plaintext) {
    if (this._completed) return this;
    const cipher = crypto.createCipheriv(this.algo, key, iv);
    this.plaintext = Buffer.from(plaintext);
    this.ciphertext = Buffer.concat([
      cipher.update(this.plaintext),
      cipher.final()
    ]);
    this.tag = cipher.getAuthTag();
    return this;
  }

  decrypt(key, iv, ciphertext) {
    if (this._completed) return this;
    this.ciphertext = Buffer(ciphertext);
    const ciphered = this.ciphertext.slice(0, -this.tagBlen);
    this.tag = this.ciphertext.slice(-this.tagBlen);
    const decipher = crypto.createDecipheriv(this.algo, key, iv);
    decipher.setAuthTag(this.tag);
    this.plaintext = Buffer.concat([
      decipher.update(ciphered),
      decipher.final()
    ]);
    return this;
  }
}

module.exports = { AES_GCM: GCM };
