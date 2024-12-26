pragma circom 2.1.9;

include "circomlib/circuits/bitify.circom";
include "circomlib/circuits/poseidon.circom";
include "circomlib/circuits/smt/smtprocessor.circom";
include "./helpers/signature.circom";
include "./helpers/extractor.circom";
include "./helpers/nullifier.circom";


template ClaimRootBuilder(nLevels) {
    signal input oldRoot;
    signal input siblings[10][nLevels];
    signal input keys[10];
    signal input values[10];

    signal output newRoot;

    signal intermediate[11];
    intermediate[0] <== oldRoot;
    
    component smt[10];
    for(var i = 0; i < 10; i++){
        smt[i] = SMTProcessor(nLevels);
        smt[i].oldRoot <== intermediate[i];
        smt[i].siblings <== siblings[i];
        smt[i].oldKey <== keys[i];
        smt[i].oldValue <== 0;
        smt[i].isOld0 <== 0;
        smt[i].newKey <== keys[i];
        smt[i].newValue <== values[i];
        smt[i].fnc <== [0, 1];
        intermediate[i+1] <== smt[i].newRoot;
    }

    newRoot <== smt[9].newRoot;
}

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
/// @input revealAgeAbove18 Flag to reveal age is above 18
/// @input revealGender Flag to reveal extracted gender
/// @input revealPinCode Flag to reveal extracted pin code
/// @input revealState Flag to reveal extracted state
/// @input nullifierSeed A random value used as an input to compute the nullifier; for example: applicationId, actionId
/// @input public signalHash Any message to commit to (to make it part of the proof)
/// @output pubkeyHash Poseidon hash of the RSA public key (after merging nearby chunks)
/// @output nullifier A unique value derived from nullifierSeed and Aadhaar data to nullify the proof/user
/// @output timestamp Timestamp of when the data was signed - extracted and converted to Unix timestamp
/// @output ageAbove18 Boolean flag indicating age is above 18; 0 if not revealed
/// @output gender Gender 70(F) or 77(M); 0 if not revealed
/// @output pinCode Pin code of the address as int; 0 if not revealed
/// @output state State packed as int (reverse order); 0 if not revealed
template AadhaarQRVerifier(n, k, maxDataLength, nLevels) {
    signal input qrDataPadded[maxDataLength];
    signal input qrDataPaddedLength;
    signal input delimiterIndices[18];
    signal input signature[k];
    signal input pubKey[k];
    signal input revealAgeAbove18;
    signal input revealGender;
    signal input revealPinCode;
    signal input revealState;

    // Public inputs
    signal input nullifierSeed;
    signal input signalHash;

    // Iden3 credentials input
    signal input revocationNonce;
    signal input credentialStatusID;
    signal input credentialSubjectID;
    signal input issuanceDate;
    signal input issuer;

    // Iden3 merkle tree root inputs
    signal input oldRoot;
    signal input siblings[10][nLevels];

    signal output pubkeyHash;
    signal output nullifier;
    signal output timestamp;
    signal output ageAbove18;
    signal output gender;
    signal output pinCode;
    signal output state;
    signal output claimRoot;

    // keys to update
    var keysToUpdate[10] = [
        10647195490133279025507176104314518051617223585635435645675479671394436328629, // ageAbove18
        5213439259676021610106577921037707268541764175155543794420152605023181390139, // birthday
        1479963091211635594734723538545884456894938414357497418097512533895772796527, // gender
        19238944412824247341353086074402759833940010832364197352719874011476854540013, // pinCode
        14522734804373614041942549305708452359006179872334741006179415532376146140639, // state
        1763085948543522232029667616550496120517967703023484347613954302553484294902, // revocationNonce
        11896622783611378286548274235251973588039499084629981048616800443645803129554, // credentialStatus.id
        4792130079462681165428511201253235850015648352883240577315026477780493110675, // credentialSubject.id
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

    // Reveal extracted data
    revealAgeAbove18 * (revealAgeAbove18 - 1) === 0;
    revealGender * (revealGender - 1) === 0;
    revealPinCode * (revealPinCode - 1) === 0;
    revealState * (revealState - 1) === 0;

    timestamp <== qrDataExtractor.timestamp;
    ageAbove18 <== revealAgeAbove18 * qrDataExtractor.ageAbove18; // Note: 0 does not necessarily mean age is below 18
    gender <== revealGender * qrDataExtractor.gender;
    pinCode <== revealPinCode * qrDataExtractor.pinCode;
    state <== revealState * qrDataExtractor.state;

    // we need to keep the same siqunce as update keys
    var valuesToUpdate[10] = [
        ageAbove18, // ageAbove18
        qrDataExtractor.dateInteger, // birthday
        gender, // gender
        pinCode, // pinCode
        state, // state
        revocationNonce, // revocationNonce
        credentialStatusID, // credentialStatus.id
        credentialSubjectID, // credentialSubject.id
        issuanceDate, // issuanceDate
        issuer // issuer
    ];

    component c = ClaimRootBuilder(10);
    c.oldRoot <== oldRoot;
    c.siblings <== siblings;
    c.keys <== keysToUpdate;
    c.values <== valuesToUpdate;
    claimRoot <== c.newRoot;

    // Calculate nullifier
    signal photo[photoPackSize()] <== qrDataExtractor.photo;
    nullifier <== Nullifier()(nullifierSeed, photo);

    
    // Dummy square to prevent signal tampering (in rare cases where non-constrained inputs are ignored)
    signal signalHashSquare <== signalHash * signalHash;
}
