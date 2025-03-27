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
        11718818292802126417463134214212976082628052906423225153106612749610200183413, // credentialSubject.dateOfBirth
        396948171793807448670779079530437970230319997763427297159364741404168161086, // credentialSubject.firstName
        1540185022550171417964535586735569210235830901649938832989137234790618138161, // credentialSubject.fullName
        8773407965838008861275811595321738876343347548748386392157545551632667424559, // credentialSubject.gender
        11665818515976908772146086926627988937767272157525043131077389782866401822622, // credentialSubject.govermentIdentifier
        20378936560477526294120993552723258097975107008215368308010022877877877266947, // credentialSubject.governmentIdentifierType
        18652354674254268839450839640508993614932212252620036777561285260846450401086, // credentialStatus.revocationNonce
        2114546039662959054024607258894575760077918479747771271201277979047211711479, // credentialSubject.addresses
        11896622783611378286548274235251973588039499084629981048616800443645803129554, // credentialStatus.id
        4792130079462681165428511201253235850015648352883240577315026477780493110675, // credentialSubject.id
        13483382060079230067188057675928039600565406666878111320562435194759310415773, // expirationDate.id
        8713837106709436881047310678745516714551061952618778897121563913918335939585, // issuanceDate.id
        5940025296598751562822259677636111513267244048295724788691376971035167813215 // issuer.id
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

    /* // For debugging
    log(qrDataExtractor.dob);
    log(qrDataExtractor.name);
    log(qrDataExtractor.name);
    log(qrDataExtractor.gender);
    log(qrDataExtractor.referenceID);
    log("9625374645547036629006936456349235401907107363945660607867283679088689283602");
    log(revocationNonce);
    log(qrDataExtractor.address);
    log(credentialStatusID);
    log(credentialSubjectID);
    log(expirationDate * 1000000000);
    log(issuanceDate * 1000000000);
    log(issuer);
    */

    /*
        expirationDate and issuanceDate represent the timestamp in seconds. 
        The Merkalization library works with timestamps in nanoseconds. 
        We need to multiply expirationDate and issuanceDate by 1,000,000,000 to get the timestamp in nanoseconds
    */
    // we need to keep the same sequence as update keys
    var valuesToUpdate[smtChanges] = [
        qrDataExtractor.dob, // birthday
        qrDataExtractor.name, // firstName
        qrDataExtractor.name, // fullName
        qrDataExtractor.gender, // gender
        qrDataExtractor.referenceID, // govermentIdentifier
        9625374645547036629006936456349235401907107363945660607867283679088689283602, // govermentIdentifierType poseidon16("other")
        revocationNonce, // revocationNonce
        qrDataExtractor.address, // address
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
    var i0 = 14477845612645806574444905890781353993111;
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
