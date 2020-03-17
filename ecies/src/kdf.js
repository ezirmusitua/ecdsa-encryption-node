const crypto = require("crypto");

function intTo32BE(i) {
  const buf = new Buffer([0, 0, 0, 0]);
  buf.writeInt32BE(i);
  return buf;
}

class X963KDF {
  constructor(hashAlgo) {
    this.hashAlgo = hashAlgo;
  }

  derive(key, byteLength, sharedInfo) {
    let output = new Buffer([]);
    let outputlen = 0;
    let counter = 1;
    while (byteLength > outputlen) {
      const hasher = crypto
        .createHash(this.hashAlgo)
        .update(key)
        .update(intTo32BE(counter));
      if (sharedInfo) {
        hasher.update(sharedInfo);
      }
      const hashResult = hasher.digest();
      outputlen += hashResult.length;
      output = Buffer.concat([output, hashResult]);
      counter += 1;
    }
    return output.slice(0, byteLength);
  }
}

module.exports = { X963KDF };
