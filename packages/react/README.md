# @anon-aadhaar/react

anon-aadhaar-react is a React component library to embed the [anon-aadhaar](https://github.com/privacy-scaling-explorations/anon-aadhaar) protocol in your project, and let you verify that a user has a regular Aadhaar ID, by generating ZKProofs in the client.

## 🛠️ Installation

Install anon-aadhaar-react with npm

```bash
  npm install @anon-aadhaar/react
```

Install anon-aadhaar-react with yarn

```bash
  yarn add @anon-aadhaar/react
```

## 📜 Usage/Examples

### `<AnonAadhaarProvider>`

`AnonAadhaarProvider` for the `AnonAadhaarContext`. It manages the authentication state, login requests, and communication with the proving component. This provider initializes the authentication state from local storage on page load and handles updates to the state when login requests are made and when new proofs are received.

```ts
import { AnonAadhaarProvider } from '@anon-aadhaar/react'

export default function App({ Component, pageProps }: AppProps) {
  return (
    // Add the Anon Aadhaar Provider at the root of your app
    <AnonAadhaarProvider>
      <Component {...pageProps} />
    </AnonAadhaarProvider>
  )
}
```

| Parameter                   | Description                                                                   | Default Value |
| --------------------------- | ----------------------------------------------------------------------------- | ------------- |
| `_useTestAadhaar`           | Optional. A boolean flag to determine the usage of test or real Aadhaar data. | `false`       |
| `_fetchArtifactsFromServer` | Optional. A boolean flag to specify the source of zk-SNARK artifacts.         | `true`        |

---

### `useAnonAadhaar()`

`useAnonAadhaar()` is a custom React hook that facilitates access to the Anon Aadhaar authentication state and a method to initiate login requests. This hook is specifically designed for use in components nested within `AnonAadhaarProvider`.

The hook returns an array containing:

1. `AnonAadhaarState`: An object representing the current authentication state, which includes:
   - `status`: Indicates the current authentication status, which can be:
     - `"logged-out"`: The user is not logged in.
     - `"logging-in"`: The login process is underway.
     - `"logged-in"`: The user is successfully logged in.
   - When `status` is `"logged-in"`, `AnonAadhaarState` also includes:
     - `serializedAnonAadhaarProof`: The serialized proof of the Anon Aadhaar authentication.
     - `anonAadhaarProof`: The actual Anon Aadhaar proof object.
2. `startReq`: A function to trigger the login process.

```tsx
const [AnonAadhaar] = useAnonAadhaar()

useEffect(() => {
  console.log('Country Identity status: ', AnonAadhaar.status)
}, [AnonAadhaar])
```

---

### `<LogInWithAnonAadhaar />`

```tsx
<LogInWithAnonAadhaar />
```

`LogInWithAnonAadhaar` provides a user interface for logging in and logging out using the AnonAadhaarContext.

---

### `verifySignature`

**Description**: `verifySignature` is a function that authenticates digital signatures on Aadhaar data. It operates by converting string data into a byte array and then decompressing it to extract the signature and the signed data. A public key, fetched from UIDAI's server, is used to verify the authenticity of the signature.

**Usage**:

```ts
const isValidSignature = await verifySignature(qrData, useTestAadhaar)
```

**Parameters**:

- `qrData`: A string representation of the Aadhaar QR code data to be verified.
- `useTestAadhaar`: Boolean flag to toggle between test and real Aadhaar data.

**Returns**: A promise resolving to a boolean indicating the validity of the signature.

---

### `proveAndSerialize`

**Description**: The `proveAndSerialize` function generates SNARK proofs using the Anon Aadhaar proving system. It takes `AnonAadhaarArgs` as input and returns a promise with the generated proof (`AnonAadhaarCore`) and its serialized form.

**Usage**:

```ts
const { anonAadhaarProof, serialized } =
  await proveAndSerialize(anonAadhaarArgs)
```

**Parameters**:

- `anonAadhaarArgs`: Arguments required to generate the `anonAadhaarProof`.

**Returns**: A promise that resolves to an object containing the generated anonAadhaarProof and its serialized form.

---

### `processAadhaarArgs`

**Description**: `processAadhaarArgs` processes QR data to create arguments needed for proof generation in the Anon Aadhaar system.

**Usage**:

```ts
const anonAadhaarArgs = await processAadhaarArgs(qrData, useTestAadhaar)
```

**Parameters**:

- `qrData`: A string representation of the Aadhaar QR code data to be verified.
- `useTestAadhaar`: Boolean flag to toggle between test and real Aadhaar data.

**Returns**: A promise resolving to the `AnonAadhaarArgs` object, which contains parameters needed for proof generation.