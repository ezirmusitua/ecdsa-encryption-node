const crypto = require("crypto");

const ENCODING = 'hex';

function main() {
  const message = "This is the secret i want to encrypt";
  const key = crypto.randomBytes(32);
  const aesKey = key.slice(0, 16);
  const aesIV = key.slice(16);
  console.log(aesIV, aesIV.length);
  const cipher = crypto.createCipheriv("aes-128-gcm", aesKey, aesIV);
  const encrypted = Buffer.concat([cipher.update(message), cipher.final()]);
  const authTag = cipher.getAuthTag();
  console.log(
    "\n\tMessage: ",
    message,
    "\n\tAES Key: ",
    aesKey.toString(ENCODING),
    "\n\tAES ALGO: ", "aes-128-gcm",
    "\n\tAES IV: ",
    aesIV.toString(ENCODING),
    "\n\tEncrypted: ",
    encrypted.toString(ENCODING),
    "\n\tAuth Tag: ",
    authTag.toString(ENCODING),
    "\n\tFull: ", Buffer.concat([encrypted, authTag]).toString(ENCODING),
    "\n"
  );
  return { aesKey, aesIV, encrypted, authTag };
}

main();

// Message:  This is the secret i want to encrypt
// AES Key:  QyPjEOeJnILvjHHBhzj4bMogzTJk5UpaQGGWuhIx6dw=
// AES ALGO:  aes-256-gcm
// AES IV:  8W67lx4lOaxqKJQA1ucSkQ==
// Encrypted:  8gVFUvx/zTPpyHh5fOwM9Gia4WV1tZmg5JtcTYJAYgBBb+t6
// Auth Tag:  ALG6KoIPCgw+Do7KNB83Gg==