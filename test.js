const {
  readPublicKeyFromCertPem,
  readPrivateKeyFromKeyPem,
  kSecKeyAlgorithmECIESEncryptionCofactorX963SHA256AESGCM
} = require("./lib");

const TestCertPem = `-----BEGIN CERTIFICATE-----
MIICGjCCAcCgAwIBAgIQdTf6GFMTws3FQ1u6RQmy4TAKBggqhkjOPQQDAjBpMQsw
CQYDVQQGEwJVUzETMBEGA1UECBMKQ2FsaWZvcm5pYTEWMBQGA1UEBxMNU2FuIEZy
YW5jaXNjbzEUMBIGA1UEChMLZXhhbXBsZS5jb20xFzAVBgNVBAMTDmNhLmV4YW1w
bGUuY29tMB4XDTIwMDEyNTIzMjYwMFoXDTMwMDEyMjIzMjYwMFowZjELMAkGA1UE
BhMCVVMxEzARBgNVBAgTCkNhbGlmb3JuaWExFjAUBgNVBAcTDVNhbiBGcmFuY2lz
Y28xDjAMBgNVBAsTBWFkbWluMRowGAYDVQQDDBFBZG1pbkBleGFtcGxlLmNvbTBZ
MBMGByqGSM49AgEGCCqGSM49AwEHA0IABK70Yu5TA5ELRaqN2uN3muA2IG5Vr0Tb
w48tmcIzIpOr6qwwaX5ZZPC/MoK+jKi7FoqycMPsL7/QwiEu+mpVDpSjTTBLMA4G
A1UdDwEB/wQEAwIHgDAMBgNVHRMBAf8EAjAAMCsGA1UdIwQkMCKAIFJJyNm/gnkm
ityYTqH0Nrtmidq8OuWvM87T4x2LS2rdMAoGCCqGSM49BAMCA0gAMEUCIQCAup+Y
O1kToiYf1dEH1t8AeGElnXVBBHxQWb/3lBWquwIgTOPdbW5gH/6p/dFkpzTnO77S
cz2spXvDf8pnilIsEOU=
-----END CERTIFICATE-----`;

const TestKeyPem = `-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgW/BFvJ4pe7aE5HAo
h8lWvcGx2ZCcNTk3n/VtP1xkLi2hRANCAASu9GLuUwORC0Wqjdrjd5rgNiBuVa9E
28OPLZnCMyKTq+qsMGl+WWTwvzKCvoyouxaKsnDD7C+/0MIhLvpqVQ6U
-----END PRIVATE KEY-----`;

function testEnc() {
  const pubKey = readPublicKeyFromCertPem(TestCertPem);
  const prvKey = readPrivateKeyFromKeyPem(TestKeyPem);
  const ecies = kSecKeyAlgorithmECIESEncryptionCofactorX963SHA256AESGCM(
    "prime256v1"
  );
  const message = "おはよう世界, Good Morning World";
  console.log("Message: ", message);
  const encResult = ecies.encrypt(pubKey, message);
  console.log("Enc Result: ", encResult);
}

function testDec() {
  const prvKey = readPrivateKeyFromKeyPem(TestKeyPem);
  const ecies = kSecKeyAlgorithmECIESEncryptionCofactorX963SHA256AESGCM(
    "prime256v1"
  );
  const ciphertext = "BNH4/UtvkP3dFO4jx/Mx/vhAB2GMU2UynnsC8Myv6Aj532/iixDUBBOek1rxCq3a/6AijvQuVWjG91d3Cy8Oy1/azaRdYxOLrF+53wHbNgkX3vna8Purst6TwC4TVjwAxPhMBSpZM5EUf9tLcK7kfi8LHzXaULU=";
  console.log("Enc Result: ", ciphertext);
  const decResult = ecies.decrypt(prvKey, ciphertext);
  console.log("Dec Result: ", decResult);
}

console.log("\n\n");

testEnc();

console.log("\n\n");

testDec();

console.log("\n\n");
