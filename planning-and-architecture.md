# Secure Webmail Application: Planning, Architecture, & Integration Guide

## 1. Overview & Tech Stack
This application is a **Full-Stack Secure Webmail Client** built with:
- **Frontend**: React 18, Vite, Tailwind CSS, TypeScript, `lucide-react` for icons.
- **Backend**: Express.js (Node.js), TypeScript.
- **Internal APIs**: WebCrypto API (for client-side encryption), JMAP (JSON Meta Application Protocol) for modern mailbox syncing.
- **Routing & Networking**: Proxied via Express middleware to solve CORS and mask upstream server connections.

## 2. Server Architecture & Logic (`server.ts`)
The Express backend acts as a mediator for API interactions, a scheduler, and a volatile datastore for secure operations. Here are the core responsibilities:

### A. API Key Management (For Secure Mail Auth)
- The app stores active integration API Keys in an **in-memory Map `apiKeys`**.
- **Endpoints**:
  - `GET /api/keys`: Fetch all active keys (for Settings UI).
  - `POST /api/keys`: Generate a new secure key (Format: `sk_<random_bytes>`).
  - `DELETE /api/keys/:id`: Revoke access.
- **Logic**: These are used by external software (like mobile apps) to connect to the backend securely without exposing the primary webmail user credentials.

### B. Secure Message Storage
- The app handles **burn-after-reading** or **time-expiring** secure messages via the `/api/v1/secure-message` and `/api/secure-store` endpoints.
- **Logic**:
  1. Receives an already-encrypted payload from the client `(encryptedPayload, iv, salt, expiration, viewOnce)`. The backend **never** sees the private decryption key or password.
  2. An independent process timer (`setInterval` every 60 seconds) sweeps the `secureStore` Map and deletes expired items.
  3. Generates a random `UUID` and stores the object.
  4. **Retrieval**: `GET /api/secure-retrieve/:id`. If `viewOnce` is `true`, it is deleted immediately from memory after being read once.

### C. JMAP Network Proxy layer
- Standard JMAP connections can suffer from CORS or complex `https`/`wss` upgrade issues depending on the provider.
- Core JMAP calls are sent to `/api/jmap/api`, which includes the upstream `apiUrl`, `username`, and `password` payload.
- Behind the scenes, the Express server injects `Basic Auth`, forces strict `https://` protocols, executes the `fetch`, and bounces the response back to the UI.
- A manual `ws` implementation proxies WebSockets to receive live pushes from the server mail agent.

### D. Scheduled Emails
- Keeps an active queue in memory: `scheduledJobs`.
- Runs a sweeping `setInterval` loop every 30 seconds to evaluate if `now >= executeAt`. If true, automatically formats and executes a JMAP `/api/jmap/api` dispatch payload to send the drafted message.

---

## 3. Frontend Architecture (`src/App.tsx`)
A monolithic Single Page Application structure designed for fluidity and instant transitions.

### A. Settings UI Module
The settings screen manages all user states:
- Uses a local state `isSettingsSection` routing parameter (`'api'`, `'general'`, `'compose'`, `'vacation'`, etc.).
- Inside `isSettingsSection === 'api'`, the UI hits `POST /api/keys` to request key generation. Upon receiving a response, it presents the key to the user safely in the UI, warning them it will only be shown once.

### B. Secure Mail Creation
- Within the composer, the user chooses "Secure Email".
- The email is run through JavaScript's `crypto.subtle` API. It uses AES-GCM to encrypt the message body with a randomly generated local passphrase.
- The cipher, IV, and salt are transferred to `/api/v1/secure-message` along with expiration instructions (`1week`, `burn` after reading).
- The returned `url` is then packaged into a standard plain-text email that says *"You received a secure message, click here to view it"* leaving all contents secure.

---

## 4. Step-by-Step Logic Outline For "Secure Message" 

1. **Sender initiates**: An external mobile app or web client prepares a message `Hello Secret`.
2. **Local Encryption**: It generates a strong random symmetric key and encrypts the payload (`AES-GCM`).
3. **API Authorization**: It attaches an `Authorization: Bearer sk_your_api_key_here` header.
4. **Backend Intake**: Express accepts the POST request at `/api/v1/secure-message`, checks `apiKeys` map, verifies the token, and creates UUID `1234-abcd`. It pushes payload to memory.
5. **URL generation**: The server formulates the absolute URL based on the request host (e.g., `https://webmail.com/secure/1234-abcd`) and replies with this URL.
6. **Recipient retrieval**: Recipient goes to `/secure/1234-abcd`. The React router notices the URL path.
7. **Decryption UI**: It asks the recipient for the decryption passphrase. 
8. **Network fetch & Wipe**: When initiated, React fetches `/api/secure-retrieve/1234-abcd`. Express responds with the encrypted JSON and deletes it from memory if `viewOnce` was set.
9. **Final decryption**: React decrypts the blob in local memory and renders to the screen.

---

## 5. Integrating Secure Mail API with External Mobile Apps (Android / iOS)

If you are building an Android (Kotlin/Java) or flutter App, here is exactly how to integrate this backend workflow:

### Step 1: Provide Key Input UI
Allow your mobile user to go into your web application Settings -> `API & Integrations` -> Generate a Key, and then Copy/Paste this `sk_...` key into the App's local secure storage (`EncryptedSharedPreferences`).

### Step 2: Implement Local Encryption (Kotlin Example)
You must encrypt the message on the device **before** sending it to the server. Generate an AES-GCM payload in Kotlin.

```kotlin
// Simplified example Android encryption for WebCrypto compatibility 
fun encryptMessage(message: String, passwordStr: String): Map<String, String> {
    val passBytes = passwordStr.toByteArray()
    
    // WebCrypto uses PBKDF2 to derive the key from the password String. 
    // You should derive the secret key from the password, IV, and salt securely.
    // Using javax.crypto packages:
    val salt = ByteArray(16).apply { SecureRandom().nextBytes(this) }
    val iv = ByteArray(12).apply { SecureRandom().nextBytes(this) }
    
    // (Omitted: Standard PBKDF2 key derivation and AES/GCM/NoPadding Cipher init)
    
    // Output should be Hex or Base64 Encoded to match what the Web expects
    return mapOf(
        "encryptedPayload" to Base64.encodeToString(cipherText, Base64.NO_WRAP),
        "iv" to Base64.encodeToString(iv, Base64.NO_WRAP),
        "salt" to Base64.encodeToString(salt, Base64.NO_WRAP)
    )
}
```

### Step 3: API Request
Execute a POST request to your deployed web backend. Do not send the plain text or password.

```kotlin
val url = URL("https://your-domain.com/api/v1/secure-message")
val urlConnection = url.openConnection() as HttpURLConnection
urlConnection.requestMethod = "POST"
urlConnection.setRequestProperty("Content-Type", "application/json")
urlConnection.setRequestProperty("Authorization", "Bearer sk_abcd1234") // the Key

val jsonInputString = """
{
  "encryptedPayload": "base64_payload",
  "iv": "base64_iv",
  "salt": "base64_salt",
  "viewOnce": true,
  "expiration": "burn"
}
"""

urlConnection.outputStream.use { os ->
    val input = jsonInputString.toByteArray(Charsets.UTF_8)
    os.write(input, 0, input.size)
}

// Parse Response
val responseCode = urlConnection.responseCode
// On success, returns: { url: "...", id: "...", expiresAt: ... }
```

### Step 4: Share URL
Once the Android app gets the `url` from the JSON response, you can directly share that URL via standard Android intents (`Intent.ACTION_SEND`) to WhatsApp, SMS, or regular email. 
The recipient will open their mobile browser to the web URL, enter the shared passphrase, and read the securely destroyed message.
