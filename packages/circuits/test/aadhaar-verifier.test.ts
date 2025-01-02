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

  const tree = await newMemEmptyTrie();
  const leafs = [
    "4809579517396073186705705159186899409599314609122482090560534255195823961763", "2038038677412689124034084719683107814279606773706261227437666149072023632255",
    "1876843462791870928827702802899567513539510253808198232854545117818238902280", "6863952743872184967730390635778205663409140607467436963978966043239919204962",
    "12891444986491254085560597052395677934694594587847693550621945641098238258096", "870222225577550446142292957325790690140780476504858538425256779240825462837",
    "14122086068848155444790679436566779517121339700977110548919573157521629996400", "8932896889521641034417268999369968324098807262074941120983759052810017489370",
    "18943208076435454904128050626016920086499867123501959273334294100443438004188", "2038038677412689124034084719683107814279606773706261227437666149072023632255",
    "2282658739689398501857830040602888548545380116161185117921371325237897538551", "9033719693259832177439488944502349301386207418184651337843275979338597322540",
    "10647195490133279025507176104314518051617223585635435645675479671394436328629", "0",  // ageAbove18
    "5213439259676021610106577921037707268541764175155543794420152605023181390139", "0", // birthday
    "1479963091211635594734723538545884456894938414357497418097512533895772796527", "0", // gender
    "19238944412824247341353086074402759833940010832364197352719874011476854540013", "0", // pinCode
    "14522734804373614041942549305708452359006179872334741006179415532376146140639", "0", // state
    "1763085948543522232029667616550496120517967703023484347613954302553484294902", "0", // revocationNonce
    "11896622783611378286548274235251973588039499084629981048616800443645803129554", "0", // credentialStatus.id
    "4792130079462681165428511201253235850015648352883240577315026477780493110675", "0", // credentialSubject.id
    "8713837106709436881047310678745516714551061952618778897121563913918335939585", "0", // issuanceDate
    "5940025296598751562822259677636111513267244048295724788691376971035167813215", "0" // issuer
  ];
  for (let i=0; i<leafs.length; i+=2) {
    const key = tree.F.e(leafs[i]);
    const value = tree.F.e(leafs[i+1]);
    await tree.insert(key, value);
  }
  const templateRoot = tree.F.toObject(tree.root);

  const constLefasUpdate = [
    // "10647195490133279025507176104314518051617223585635435645675479671394436328629", 1,  // ageAbove18
    "5213439259676021610106577921037707268541764175155543794420152605023181390139", 19840101, // birthday
    "1479963091211635594734723538545884456894938414357497418097512533895772796527", 77, // gender
    "19238944412824247341353086074402759833940010832364197352719874011476854540013", 110051, // pinCode
    "14522734804373614041942549305708452359006179872334741006179415532376146140639", 452723500356, // state
    "1763085948543522232029667616550496120517967703023484347613954302553484294902", 954548273, // revocationNonce
    "11896622783611378286548274235251973588039499084629981048616800443645803129554", "1018201307016207665766251269200564043201648522038849723333336008159229499355", // credentialStatus.id
    "4792130079462681165428511201253235850015648352883240577315026477780493110675", "18026946060490633582346941999242407265442400633018823452652749104672360129751", // credentialSubject.id
    "8713837106709436881047310678745516714551061952618778897121563913918335939585", "1734987189512228532", // issuanceDate
    "5940025296598751562822259677636111513267244048295724788691376971035167813215", "12146166192964646439780403715116050536535442384123009131510511003232108502337" // issuer
  ]
  const siblings = [[]];
  for (let i=0; i<constLefasUpdate.length; i+=2) {
    const key = tree.F.e(constLefasUpdate[i]);
    const value = tree.F.e(constLefasUpdate[i+1]);
    const res = await tree.update(key, value);
    for (let i=0; i<res.siblings.length; i++) res.siblings[i] = tree.F.toObject(res.siblings[i]);
    while (res.siblings.length<10) res.siblings.push(0);
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
    
    revocationNonce: 954548273,
    credentialStatusID: "1018201307016207665766251269200564043201648522038849723333336008159229499355",
    credentialSubjectID: "18026946060490633582346941999242407265442400633018823452652749104672360129751",
    issuanceDate: "1734987189512228532",
    issuer: "12146166192964646439780403715116050536535442384123009131510511003232108502337",

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
    const { inputs } = await prepareTestData()

    const witness = await circuit.calculateWitness(inputs)
    await circuit.checkConstraints(witness);
    assert(witness[3] === BigInt("440354795020186637131786307576016381968603262412779561544441506727441642641"));
  })
})
