import React, { useEffect, useState, Dispatch, SetStateAction } from 'react'
import styled from 'styled-components'
import { FileInput } from './FileInput'
import { ProveButton } from './ProveButton'
import { ScanQR } from './ScanQR'
import { uploadQRpng, verifySignature } from '../util'
import { AadhaarQRValidation } from '../interface'
import { ErrorToast } from './ErrorToast'
import { BrowserView, MobileView } from 'react-device-detect'
import { Logo } from './LogInWithAnonAadhaar'

interface ModalProps {
  isOpen: boolean
  onClose: () => void
  errorMessage: string | null
  setErrorMessage: Dispatch<SetStateAction<string | null>>
  logo: string
  qrStatus: AadhaarQRValidation | null
  setQrStatus: Dispatch<SetStateAction<AadhaarQRValidation | null>>
}

export const ProveModal: React.FC<ModalProps> = ({
  isOpen,
  onClose,
  errorMessage,
  setErrorMessage,
  logo,
  qrStatus,
  setQrStatus,
}) => {
  const [qrData, setQrData] = useState<string | null>(null)
  const [provingEnabled, setProvingEnabled] = useState<boolean>(false)

  useEffect(() => {
    if (qrData) {
      verifySignature(qrData)
        .then(verified => {
          verified
            ? setQrStatus(AadhaarQRValidation.SIGNATURE_VERIFIED)
            : setQrStatus(AadhaarQRValidation.ERROR_PARSING_QR)
        })
        .catch(error => {
          setQrStatus(AadhaarQRValidation.ERROR_PARSING_QR)
          console.error(error)
        })
    }
  }, [qrData])

  useEffect(() => {
    if (qrStatus === AadhaarQRValidation.SIGNATURE_VERIFIED) {
      setProvingEnabled(true)
    } else {
      setProvingEnabled(false)
    }
  }, [qrStatus, qrData])

  return isOpen ? (
    <ModalOverlay onClick={onClose}>
      <BrowserView>
        <ModalContent onClick={e => e.stopPropagation()}>
          {errorMessage !== null && (
            <ErrorToast
              message={errorMessage}
              setErrorMessage={setErrorMessage}
            />
          )}
          <TitleSection>
            <Title>
              <Logo src={logo} />
              Prove your Identity
            </Title>
            <Disclaimer>
              Anon Aadhaar securely verifies your document by confirming its
              government signature. This process happens entirely on your device
              for privacy. Please note, slower internet speeds may affect
              verification time.
            </Disclaimer>
          </TitleSection>

          <UploadSection>
            <UploadFile>
              <Label>Upload your Aadhaar secure QRCode</Label>
              <FileInput
                onChange={async e => {
                  const { qrValue } = await uploadQRpng(e, setQrStatus)
                  setQrData(qrValue)
                }}
                id={'handlePdfChange'}
              />
              <DocumentResult>{qrStatus}</DocumentResult>
            </UploadFile>
          </UploadSection>

          <ProveButton
            // pdfData={pdfData}
            pdfData={Buffer.from([])}
            provingEnabled={provingEnabled}
            setErrorMessage={setErrorMessage}
          />
        </ModalContent>
      </BrowserView>
      <MobileView>
        <ModalContent onClick={e => e.stopPropagation()}>
          {errorMessage !== null && (
            <ErrorToast
              message={errorMessage}
              setErrorMessage={setErrorMessage}
            />
          )}
          <TitleSection>
            <Title>
              <Logo src={logo} />
              Prove your Identity
            </Title>
            <Disclaimer>
              Anon Aadhaar securely verifies your document by confirming its
              government signature. This process happens entirely on your device
              for privacy. Please note, slower internet speeds may affect
              verification time.
            </Disclaimer>
          </TitleSection>

          <UploadSection>
            <UploadFile>
              <Label>Upload your Masked Aadhaar PDF</Label>
              <ScanQR setQrData={setQrData} setQrStatus={setQrStatus} />
              <DocumentResult>{qrStatus}</DocumentResult>
            </UploadFile>
          </UploadSection>

          <ProveButton
            // pdfData={pdfData}
            pdfData={Buffer.from([])}
            provingEnabled={provingEnabled}
            setErrorMessage={setErrorMessage}
          />
        </ModalContent>
      </MobileView>
    </ModalOverlay>
  ) : null
}

const ModalOverlay = styled.div`
  position: fixed;
  top: 0;
  left: 0;
  width: 100%;
  height: 100%;
  background-color: rgba(0, 0, 0, 0.2);
  display: flex;
  align-items: center;
  justify-content: center;
  z-index: 9999;
`

const ModalContent = styled.div`
  position: fixed;
  display: flex;
  flex-direction: column;
  top: 50%;
  left: 50%;
  transform: translate(-50%, -50%);
  background-color: #ffffff;
  border-radius: 1rem;
  box-shadow: 0 4px 10px rgba(0, 0, 0, 0.1);
  justify-content: space-between;

  @media (max-width: 425px) {
    /* For screens <= 425px (e.g., mobile devices) */
    width: 100%;
    height: 67%;
    max-width: 100%;
    max-height: 100%;
  }

  @media (min-width: 426px) {
    /* For screens > 426px (e.g., desktop) */
    min-height: 400px;
    max-width: 400px;
    width: 80%;
  }
`

const UploadFile = styled.div`
  margin-top: 30px;
  margin-bottom: 30px;
`

const DocumentResult = styled.div`
  color: #111827;
  position: absolute;
  font-size: 0.875rem;
  margin-top: 4px;
`

const TitleSection = styled.div`
  color: #111827;
  flex-shrink: 0;
  row-gap: 1rem;
  margin-left: auto;
  margin-right: auto;
  margin: 1rem 1rem 0;
  display: flex;
  flex-flow: column;
`

const Title = styled.h3`
  display: flex;
  flex-shrink: 0;
  margin-left: auto;
  margin-right: auto;
  font-size: medium;
  font-weight: bold;
`

const Disclaimer = styled.p`
  color: #6d6d6d;
  margin-top: 0.3rem;
  font-size: small;
  font-weight: normal;
`

const UploadSection = styled.div`
  margin: 0 1rem 0;
  row-gap: 1rem;
  max-width: 100%;
`

const Label = styled.div`
  font-size: medium;
  text-align: left;
  font-weight: 500;
  color: #111827;
`
