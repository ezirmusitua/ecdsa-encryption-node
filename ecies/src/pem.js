const x509 = require("@fidm/x509");

function readPublicKeyFromCertPem(pemContent) {
  const buffer = Buffer.from(pemContent);
  const cert = x509.Certificate.fromPEM(buffer);
  return cert.publicKey.keyRaw;
}

function readPrivateKeyFromKeyPem(pemContent) {
  return Buffer.from(pemContent);
}

module.exports = { readPrivateKeyFromKeyPem, readPublicKeyFromCertPem };
