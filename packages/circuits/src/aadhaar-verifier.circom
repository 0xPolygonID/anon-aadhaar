pragma circom 2.1.9;

include "./aadhaar-qr-verifier.circom";

component main { public [nullifierSeed, signalHash, expirationDate, templateRoot] } = AadhaarQRVerifier(121, 17, 512 * 3, 10, 10);
