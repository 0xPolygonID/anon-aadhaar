pragma circom 2.1.9;

include "circomlib/circuits/poseidon.circom";
include "./helpers/signature.circom";
include "./helpers/extractor.circom";
include "./helpers/nullifier.circom";
include "./claimRootBuilder.circom";
include "./claimV0Builder.circom";

/// @title AadhaarQRVerifier
/// @notice This circuit verifies the Aadhaar QR data using RSA signature
/// @param n RSA pubic key size per chunk
/// @param k Number of chunks the RSA public key is split into
/// @param maxDataLength Maximum length of the data
/// @input qrDataPadded QR data without the signature; assumes elements to be bytes; remaining space is padded with 0
/// @input qrDataPaddedLength Length of padded QR data
/// @input delimiterIndices Indices of delimiters (255) in the QR text data. 18 delimiters including photo
/// @input signature RSA signature
/// @input pubKey RSA public key (of the government)
/// @input nullifierSeed A random value used as an input to compute the nullifier; for example: applicationId, actionId
/// @input public signalHash Any message to commit to (to make it part of the proof)
/// @output pubkeyHash Poseidon hash of the RSA public key (after merging nearby chunks)
/// @output nullifier A unique value derived from nullifierSeed and Aadhaar data to nullify the proof/user
/// @output timestamp Timestamp of when the data was signed - extracted and converted to Unix timestamp
/// @output ageAbove18 Boolean flag indicating age is above 18; 0 if not revealed
/// @output gender Gender 70(F) or 77(M); 0 if not revealed
/// @output pinCode Pin code of the address as int; 0 if not revealed
/// @output state State packed as int (reverse order); 0 if not revealed
template AadhaarQRVerifier(n, k, maxDataLength, nLevels, smtChanges) {
    signal input qrDataPadded[maxDataLength];
    signal input qrDataPaddedLength;
    signal input delimiterIndices[18];
    signal input signature[k];
    signal input pubKey[k];

    // Public inputs
    signal input nullifierSeed;
    signal input signalHash;
    signal input templateRoot;
    signal input issuer;

    // Iden3 credentials input
    signal input revocationNonce;
    signal input credentialStatusID;
    signal input credentialSubjectID;
    signal input userID;
    signal input expirationTime;

    // Iden3 merkle tree root inputs
    signal input siblings[smtChanges][nLevels];

    signal output pubkeyHash;
    signal output nullifier;
    signal output hashIndex;
    signal output hashValue;
    signal output issuanceDate;
    signal output expirationDate;

    // keys to update
    var keysToUpdate[smtChanges] = [
        13319952139078733522750695554630631933458346585087910879123048180112892347049, // birthday
        10164804319113601592709052825465566543798059716079261081106678069863727363127, // gender
        1044934786333234750726995748708908396493389234902509278003344567776685904786, // pinCode
        18399736510711010434057702561154623084154073746787114033062223519394499254431, // state
        18652354674254268839450839640508993614932212252620036777561285260846450401086, // revocationNonce
        11896622783611378286548274235251973588039499084629981048616800443645803129554, // credentialStatus.id
        4792130079462681165428511201253235850015648352883240577315026477780493110675, // credentialSubject.id
        13483382060079230067188057675928039600565406666878111320562435194759310415773, // expirationDate
        8713837106709436881047310678745516714551061952618778897121563913918335939585, // issuanceDate
        5940025296598751562822259677636111513267244048295724788691376971035167813215 // issuer
    ];

    // Assert `qrDataPaddedLength` fits in `ceil(log2(maxDataLength))`
    component n2bHeaderLength = Num2Bits(log2Ceil(maxDataLength));
    n2bHeaderLength.in <== qrDataPaddedLength;


    // Verify the RSA signature
    component signatureVerifier = SignatureVerifier(n, k, maxDataLength);
    signatureVerifier.qrDataPadded <== qrDataPadded;
    signatureVerifier.qrDataPaddedLength <== qrDataPaddedLength;
    signatureVerifier.pubKey <== pubKey;
    signatureVerifier.signature <== signature;
    pubkeyHash <== signatureVerifier.pubkeyHash;


    // Assert data between qrDataPaddedLength and maxDataLength is zero
    AssertZeroPadding(maxDataLength)(qrDataPadded, qrDataPaddedLength);
    

    // Extract data from QR and compute nullifiers
    component qrDataExtractor = QRDataExtractor(maxDataLength);
    qrDataExtractor.data <== qrDataPadded;
    qrDataExtractor.qrDataPaddedLength <== qrDataPaddedLength;
    qrDataExtractor.delimiterIndices <== delimiterIndices;


    // use the time of signing as the date of issue
    issuanceDate <== qrDataExtractor.timestamp;
    expirationDate <== issuanceDate + expirationTime;
    /*
        expirationDate and issuanceDate represent the timestamp in seconds. 
        The Merkalization library works with timestamps in nanoseconds. 
        We need to multiply expirationDate and issuanceDate by 1,000,000,000 to get the timestamp in nanoseconds
    */
    // we need to keep the same sequence as update keys
    var valuesToUpdate[smtChanges] = [
        qrDataExtractor.dateInteger, // birthday
        qrDataExtractor.gender, // gender
        qrDataExtractor.pinCode, // pinCode
        qrDataExtractor.state, // state
        revocationNonce, // revocationNonce
        credentialStatusID, // credentialStatus.id
        credentialSubjectID, // credentialSubject.id
        expirationDate * 1000000000, // expirationDate
        issuanceDate * 1000000000, // issuanceDate
        issuer // issuer
    ];

    signal claimRoot;
    component c = ClaimRootBuilder(nLevels, smtChanges);
    c.templateRoot <== templateRoot;
    c.siblings <== siblings;
    c.keys <== keysToUpdate;
    c.values <== valuesToUpdate;
    claimRoot <== c.newRoot;

    // Calculate nullifier
    signal photo[photoPackSize()] <== qrDataExtractor.photo;
    nullifier <== Nullifier()(nullifierSeed, photo);

    
    // Dummy square to prevent signal tampering (in rare cases where non-constrained inputs are ignored)
    signal signalHashSquare <== signalHash * signalHash;

    // The value was calculated using the go-iden3-core library
    var i0 = 14444367388179446711342280945679493732379;
    component hI = Poseidon(4);
    hI.inputs[0] <== i0;
    hI.inputs[1] <== userID;
    hI.inputs[2] <== claimRoot;
    hI.inputs[3] <== 0;

    component V0Calc = V0Calculator();
    V0Calc.revocation <== revocationNonce;
    V0Calc.expiration <== expirationDate;

    component hV = Poseidon(4);
    hV.inputs[0] <== V0Calc.out;
    hV.inputs[1] <== 0;
    hV.inputs[2] <== 0;
    hV.inputs[3] <== 0;

    hashIndex <== hI.out;
    hashValue <== hV.out;
}
