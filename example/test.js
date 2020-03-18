const {
  readPublicKeyFromCertPem,
  readPrivateKeyFromKeyPem,
  kSecKeyAlgorithmECIESEncryptionCofactorX963SHA256AESGCM
} = require("ecies");

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
  console.log("Test ECIES Encryption: ")
  const pubKey = readPublicKeyFromCertPem(TestCertPem);
  const ecies = kSecKeyAlgorithmECIESEncryptionCofactorX963SHA256AESGCM(
    "prime256v1"
  );
  const message = "おはよう世界, Good Morning World";
  console.log("\tEnc Input : ")
  const encResult = ecies.encrypt(pubKey, message);
  console.log("\tEnc Output: ", encResult);
}

function testDec() {
  console.log("\n\nTest ECIES Decryption")
  const prvKey = readPrivateKeyFromKeyPem(TestKeyPem);
  const ecies = kSecKeyAlgorithmECIESEncryptionCofactorX963SHA256AESGCM(
    "prime256v1"
  );
  const ciphertext = "BDP6ONnhoao6Q8A1beSoqXgPU1XTjsv38a9JSbFOoVOhcO6dTxk/PJpm1DelcDV1+wU9AXp4xeSY+S6Dn/9dq/07fWJjiH53KIskrvZJ0+8KmoKsZxNzfpTgW5M2p1OG/Jv6qU2SKejNPwMazvJTN6VNiHW7Yz8="
  console.log("\tDec Input : ", ciphertext);const decResult = ecies.decrypt(prvKey, ciphertext);
  console.log("\tDec Output: ", decResult);
}

console.log(" = ".repeat(10) + "\n\n");

testEnc();

console.log("\n\n" + ".-.".repeat(10));

testDec();

console.log("\n\n" + " = ".repeat(10));
