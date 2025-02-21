/* eslint-disable @typescript-eslint/no-explicit-any */
import path from 'path'
// eslint-disable-next-line @typescript-eslint/no-var-requires
const circom_tester = require('circom_tester/wasm/tester')
import { sha256Pad } from '@zk-email/helpers/dist/sha-utils'
import { Uint8ArrayToCharArray } from '@zk-email/helpers/dist/binary-format'
import {
  convertBigIntToByteArray,
  decompressByteArray,
} from '@anon-aadhaar/core'
import assert from 'assert'
import { testQRData as QRData } from '../assets/dataInput.json'

describe('Extractor', function () {
  this.timeout(0)

  let circuit: any

  this.beforeAll(async () => {
    circuit = await circom_tester(
      path.join(__dirname, './', 'circuits', 'extractor-test.circom'),
      {
        recompile: true,
        include: [
          path.join(__dirname, '../node_modules'),
          path.join(__dirname, '../../../node_modules'),
        ],
      },
    )
  })

  it('should extract data', async () => {
    const QRDataBytes = convertBigIntToByteArray(BigInt(QRData))
    const QRDataDecode = decompressByteArray(QRDataBytes)

    const signedData = QRDataDecode.slice(0, QRDataDecode.length - 256)

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

    const witness: any[] = await circuit.calculateWitness({
      data: Uint8ArrayToCharArray(qrDataPadded),
      qrDataPaddedLength: qrDataPaddedLen,
      delimiterIndices: delimiterIndices,
    })

    // Timestamp of signing
    assert(
      new Date(Number(witness[1]) * 1000).getTime() ===
        new Date('2019-03-08T05:30:00.000Z').getTime(),
    )

    // Gender
    assert(witness[2] === 4366613503740245542741816499068547859478657796760861141829344679607332353738n,
    "Hash of gender is not equal to golang Poseidon implementaion")

    // Name
    assert(witness[3] === 9055566139599481731330446254307216178665393900469433627295807637695545779753n, 
      "Hash of name is not equal to golang Poseidon implementaion")

    // // referenceID
    assert(witness[4] === 269720190308114407437n, 
      "referenceID is not eqaul to expected value")

    // address
    assert(witness[5] === 2727536908092799094274850447014528629459829531793846928656959765346782168490n,
      "Hash of address is not equal to golang Poseidon implementaion")

    // Date of birth on integer format
    assert(Number(witness[6]) === 19840101)

    // Photo
    // Reconstruction of the photo bytes from packed ints and compare each byte

    // TODO(illia-korotia): we use a new function to convert bytes to bigints inside the circuits.
    
    // const photo = extractPhoto(Array.from(qrDataPadded), qrDataPaddedLen)
    // const photoWitness = bigIntChunksToByteArray(witness.slice(8, 8 + 32))

    // assert(photoWitness.length === photo.bytes.length)
    // for (let i = 0; i < photoWitness.length; i++) {
    //   assert(photoWitness[i] === photo.bytes[i])
    // }
  })
})
