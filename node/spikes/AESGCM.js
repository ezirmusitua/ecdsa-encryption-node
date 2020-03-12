const crypto = require("crypto");

function main() {
  const message = "This is the secret i want to encrypt";
  const key = crypto.randomBytes(48);
  const aesKey = key.slice(0, 32);
  const aesIV = key.slice(32);
  console.log(aesIV, aesIV.length);
  const cipher = crypto.createCipheriv("aes-256-gcm", aesKey, aesIV);
  const encrypted = Buffer.concat([cipher.update(message), cipher.final()]);
  const authTag = cipher.getAuthTag();
  console.log(
    "\n\tMessage: ",
    message,
    "\n\tAES Key: ",
    aesKey.toString("base64"),
    "\n\tAES ALGO: ", "aes-256-gcm",
    "\n\tAES IV: ",
    aesIV.toString("base64"),
    "\n\tEncrypted: ",
    encrypted.toString("base64"),
    "\n\tAuth Tag: ",
    authTag.toString("base64"),
    "\n\tFull: ", Buffer.concat([encrypted, authTag]).toString('base64'),
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