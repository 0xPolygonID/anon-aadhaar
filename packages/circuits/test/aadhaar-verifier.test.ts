/* eslint-disable @typescript-eslint/no-explicit-any */
// eslint-disable-next-line @typescript-eslint/no-var-requires
const circom_tester = require('circom_tester/wasm/tester')

import path from 'path'
import { sha256Pad } from '@zk-email/helpers/dist/sha-utils'
import {
  bigIntToChunkedBytes,
  bufferToHex,
  Uint8ArrayToCharArray,
} from '@zk-email/helpers/dist/binary-format'
import {
  convertBigIntToByteArray,
  decompressByteArray,
  splitToWords,
  extractPhoto,
} from '@anon-aadhaar/core'
import fs from 'fs'
import crypto from 'crypto'
import assert from 'assert'
import { buildPoseidon } from 'circomlibjs'
import { testQRData } from '../assets/dataInput.json'
import { bytesToIntChunks, padArrayWithZeros } from './util'
// eslint-disable-next-line @typescript-eslint/no-var-requires
require('dotenv').config()
import { newMemEmptyTrie } from 'circomlibjs'

let testAadhaar = true
let QRData: string = testQRData
if (process.env.REAL_DATA === 'true') {
  testAadhaar = false
  if (typeof process.env.AADHAAR_QR_DATA === 'string') {
    QRData = process.env.AADHAAR_QR_DATA
  } else {
    throw Error('You must set .env var AADHAAR_QR_DATA when using real data.')
  }
}

const getCertificate = (_isTest: boolean) => {
  return _isTest ? 'testPublicKey.pem' : 'uidai_offline_publickey_26022021.cer'
}

async function prepareTestData() {
  const qrDataBytes = convertBigIntToByteArray(BigInt(QRData))
  const decodedData = decompressByteArray(qrDataBytes)

  const signatureBytes = decodedData.slice(
    decodedData.length - 256,
    decodedData.length,
  )

  const signedData = decodedData.slice(0, decodedData.length - 256)

  const [qrDataPadded, qrDataPaddedLen] = sha256Pad(signedData, 512 * 3)

  const delimiterIndices: number[] = []
  for (let i = 0; i < qrDataPadded.length; i++) {
    if (qrDataPadded[i] === 255) {
      delimiterIndices.push(i)
    }
    if (delimiterIndices.length === 18) {
      break
    }
  }

  const signature = BigInt(
    '0x' + bufferToHex(Buffer.from(signatureBytes)).toString(),
  )

  const pkPem = fs.readFileSync(
    path.join(__dirname, '../assets', getCertificate(testAadhaar)),
  )
  const pk = crypto.createPublicKey(pkPem)

  const pubKey = BigInt(
    '0x' +
      bufferToHex(
        Buffer.from(pk.export({ format: 'jwk' }).n as string, 'base64url'),
      ),
  )

  const treeLevels = 10;
  const tree = await newMemEmptyTrie();
  // key-value pairs to build the credential template
  const template = [
    "4809579517396073186705705159186899409599314609122482090560534255195823961763", "3751782318016764902460517383636219429745087389162942693670855676890817944684", // credentialSubjectType
    "1876843462791870928827702802899567513539510253808198232854545117818238902280", "6863952743872184967730390635778205663409140607467436963978966043239919204962", // credentialSchemaType
    "12891444986491254085560597052395677934694594587847693550621945641098238258096", "1173248646377539879946536107369421994820880702773342056419798525241229208349", // credentialStatusType
    "14122086068848155444790679436566779517121339700977110548919573157521629996400", "8932896889521641034417268999369968324098807262074941120983759052810017489370", // typeID1
    "18943208076435454904128050626016920086499867123501959273334294100443438004188", "3751782318016764902460517383636219429745087389162942693670855676890817944684", // typeDI2
    "2282658739689398501857830040602888548545380116161185117921371325237897538551", "7267241749008249664184827982574396251114082060252725574405923105367928296171", // credentialSchemaID
    "13319952139078733522750695554630631933458346585087910879123048180112892347049", "0", // birthday
    "10164804319113601592709052825465566543798059716079261081106678069863727363127", "0", // gender
    "1044934786333234750726995748708908396493389234902509278003344567776685904786", "0", // pinCode
    "18399736510711010434057702561154623084154073746787114033062223519394499254431", "0", // state
    "18652354674254268839450839640508993614932212252620036777561285260846450401086", "0", // revocationNonce
    "11896622783611378286548274235251973588039499084629981048616800443645803129554", "0", // credentialStatus.id
    "4792130079462681165428511201253235850015648352883240577315026477780493110675", "0", // credentialSubject.id
    "13483382060079230067188057675928039600565406666878111320562435194759310415773", "0", // expirationDate
    "8713837106709436881047310678745516714551061952618778897121563913918335939585", "0", // issuanceDate
    "5940025296598751562822259677636111513267244048295724788691376971035167813215", "0" // issuer
  ];
  for (let i=0; i<template.length; i+=2) {
    const key = tree.F.e(template[i]);
    const value = tree.F.e(template[i+1]);
    await tree.insert(key, value);
  }
  const templateRoot = tree.F.toObject(tree.root);

  const updateTemplate = [
    "13319952139078733522750695554630631933458346585087910879123048180112892347049", 19840101, // birthday
    "10164804319113601592709052825465566543798059716079261081106678069863727363127", 77, // gender
    "1044934786333234750726995748708908396493389234902509278003344567776685904786", 110051, // pinCode
    "18399736510711010434057702561154623084154073746787114033062223519394499254431", 452723500356, // state
    "18652354674254268839450839640508993614932212252620036777561285260846450401086", 0, // revocationNonce
    "11896622783611378286548274235251973588039499084629981048616800443645803129554", "8639584887809663629106058915819143598372772994078727421962823642907007232233", // credentialStatus.id
    "4792130079462681165428511201253235850015648352883240577315026477780493110675", "18026946060490633582346941999242407265442400633018823452652749104672360129751", // credentialSubject.id
    "13483382060079230067188057675928039600565406666878111320562435194759310415773", "1567799640000000000", // expirationDate
    "8713837106709436881047310678745516714551061952618778897121563913918335939585", "1552023000000000000", // issuanceDate
    "5940025296598751562822259677636111513267244048295724788691376971035167813215", "12146166192964646439780403715116050536535442384123009131510511003232108502337" // issuer
  ]
  const siblings = [[]];
  for (let i=0; i<updateTemplate.length; i+=2) {
    const key = tree.F.e(updateTemplate[i]);
    const value = tree.F.e(updateTemplate[i+1]);
    const res = await tree.update(key, value);
    for (let i=0; i<res.siblings.length; i++) res.siblings[i] = tree.F.toObject(res.siblings[i]);
    while (res.siblings.length<treeLevels) res.siblings.push(0);
    siblings.push(res.siblings);
  }

  const inputs = {
    qrDataPadded: Uint8ArrayToCharArray(qrDataPadded),
    qrDataPaddedLength: qrDataPaddedLen,
    delimiterIndices: delimiterIndices,
    signature: splitToWords(signature, BigInt(121), BigInt(17)),
    pubKey: splitToWords(pubKey, BigInt(121), BigInt(17)),
    nullifierSeed: 12345678,
    signalHash: 1001,
    
    revocationNonce: 0,
    credentialStatusID: "8639584887809663629106058915819143598372772994078727421962823642907007232233",
    credentialSubjectID: "18026946060490633582346941999242407265442400633018823452652749104672360129751",
    userID: "23747161200420134456844951198264139815921171975208487354806063665905574145",
    issuer: "12146166192964646439780403715116050536535442384123009131510511003232108502337",
    expirationTime: "15776640",

    templateRoot: templateRoot,
    siblings: siblings
  }

  return {
    inputs,
    qrDataPadded,
    signedData,
    decodedData,
    pubKey,
    qrDataPaddedLen,
  }
}

describe('AadhaarVerifier', function () {
  this.timeout(0)

  let circuit: any

  this.beforeAll(async () => {
    const pathToCircuit = path.join(
      __dirname,
      '../src',
      'aadhaar-verifier.circom',
    )
    circuit = await circom_tester(pathToCircuit, {
      recompile: true,
      // output: path.join(__dirname, '../build'),
      include: [
        path.join(__dirname, '../node_modules'),
        path.join(__dirname, '../../../node_modules'),
      ],
    })
  })

  it('should generate witness for circuit with Sha256RSA signature', async () => {
    const { inputs } = await prepareTestData()

    await circuit.calculateWitness(inputs)
  })

  it('should output hash of pubkey', async () => {
    const { inputs, pubKey } = await prepareTestData()

    const witness = await circuit.calculateWitness(inputs)

    // Calculate the Poseidon hash with pubkey chunked to 9*242 like in circuit
    const poseidon = await buildPoseidon()
    const pubkeyChunked = bigIntToChunkedBytes(pubKey, 242, 9)
    const hash = poseidon(pubkeyChunked)

    assert(witness[1] === BigInt(poseidon.F.toObject(hash)))
  })

  it('should compute nullifier correctly', async () => {
    const nullifierSeed = 12345678

    const { inputs, qrDataPadded, qrDataPaddedLen } = await prepareTestData()
    inputs.nullifierSeed = nullifierSeed

    const witness = await circuit.calculateWitness(inputs)

    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const poseidon: any = await buildPoseidon()

    const { bytes: photoBytes } = extractPhoto(
      Array.from(qrDataPadded),
      qrDataPaddedLen,
    )
    const photoBytesPacked = padArrayWithZeros(
      bytesToIntChunks(new Uint8Array(photoBytes), 31),
      32,
    )

    const first16 = poseidon([...photoBytesPacked.slice(0, 16)])
    const last16 = poseidon([...photoBytesPacked.slice(16, 32)])
    const nullifier = poseidon([nullifierSeed, first16, last16])

    assert(witness[2] == BigInt(poseidon.F.toString(nullifier)))
  })

  it('should output extracted data if reveal is true', async () => {
    /*
    Credential example:
    {
      "@context": [
        "https://www.w3.org/2018/credentials/v1",
        "https://schema.iden3.io/core/jsonld/iden3proofs.jsonld",
        "ipfs://QmYcmkJeSDcaTSDfVkMMh7Xay83dJeEc9HDy2Mh8J7gLJA"
      ],
      "type": [
        "VerifiableCredential",
        "AnonAadhaar"
      ],
      "issuanceDate": "2019-03-08T05:30:00Z",
      "expirationDate": "2019-09-06T19:54:00Z",
      "credentialSubject": {
        "birthday": 19840101,
        "gender": 77,
        "id": "did:iden3:privado:main:2Scn2RfosbkQDMQzQM5nCz3Nk5GnbzZCWzGCd3tc2G",
        "pinCode": 110051,
        "state": 452723500356,
        "type": "AnonAadhaar"
      },
      "credentialStatus": {
        "id": "did:iden3:privado:main:2Scn2RfosbkQDMQzQM5nCz3Nk5GnbzZCWzGCd3tc2G/credentialStatus?revocationNonce=1051565438&contractAddress=80001:0x2fCE183c7Fbc4EbB5DB3B0F5a63e0e02AE9a85d2&state=a1abdb9f44c7b649eb4d21b59ef34bd38e054aa3e500987575a14fc92c49f42c",
        "revocationNonce": 0,
      "type": "Iden3OnchainSparseMerkleTreeProof2023"
      },
      "issuer": "did:iden3:privado:main:2Si3eZUE6XetYsmU5dyUK2Cvaxr1EEe65vdv2BML4L",
      "credentialSchema": {
        "id": "ipfs://QmeTNnum9CThm6f7eBSxWuDQBTZC7EQrawr3AD6UJw38GM",
        "type": "JsonSchema2023"
      }
    }
    */
    const { inputs } = await prepareTestData()
    
    const witness = await circuit.calculateWitness(inputs)
    await circuit.checkConstraints(witness);
    // compare the results with the results of the go-core library
    assert(witness[3] === BigInt("4495749602680683476365464685207358157516802663665444189094863568693702095171"));
    assert(witness[4] === BigInt("18008128381428548624282039899106504460765785745693349906422544723715663713055"));
    // compare issuanceDate is equal to date from the QR code
    assert(
      new Date(Number(witness[5]) * 1000).getTime() ===
        new Date('2019-03-08T05:30:00Z').getTime(),
    );
    assert(
      new Date(Number(witness[6]) * 1000).getTime() ===
        new Date('2019-09-06T19:54:00Z').getTime(),
    );
    // compare expirationDate is issuedDate + 6 months(~15776640 seconds)
    const diff = witness[6] - witness[5];
    assert(BigInt(diff) === BigInt(15776640));
    // compare templateRoot
    assert(witness[9] === BigInt("3760048933127269188109079349507397743444241277603345236696660118069105661581"));
    // compare issuer
    assert(witness[10] === BigInt("12146166192964646439780403715116050536535442384123009131510511003232108502337"))
  })
})
