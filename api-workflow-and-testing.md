# Secure API Workflow & Terminal Testing Guide

This document explains the end-to-end flow of exactly what happens when you send a secure message with a specific subject, body, and expiration time, followed by a guide on how you can test this entire API system directly from your terminal.

---

## Part 1: How the API Handles "Subject: Sunil", "Body: Sunil right", "Time: 5min"

Let's walk through the lifecycle of this specific message from the moment it is created until it is viewed by the recipient.

### 1. Preparation by the Sender (The App/Mobile Client)
The backend does **not** encrypt the data. The external app (like Android/iOS or web frontend) must secure it before it ever touches the network.
- **Input**: The user types Subject: `"Sunil"`, Body: `"Sunil right"`, Expiration: `5min`.
- **Encryption**: The app asks the user for a secret password/passphrase (e.g., `"mySecret123"`).
- **Result**: The app generates a cryptographically secure payload using AES-GCM. 
  - `"Sunil right"` becomes an unreadable `encryptedPayload` (e.g., `U2FsdGVkX19...`).
  - The encryption algorithm also produces an `iv` (Initialization Vector) and a `salt`.
- *Note*: The Subject (`"Sunil"`) is usually kept as plain text in the regular email because it acts as the gateway email, but the body is encrypted.

### 2. Sending to the Backend Server
The app sends an HTTP POST request to the API endpoint `/api/v1/secure-message`:
- **Headers**: It includes the generated API Key: `Authorization: Bearer sk_your_api_key`
- **Body**: 
  ```json
  {
    "encryptedPayload": "U2FsdGVkX19...",
    "iv": "abc890...",
    "salt": "xyz123...",
    "expiration": "5min",
    "viewOnce": true
  }
  ```

### 3. Backend Processing (Node.js/Express)
1. **Verification**: The Server checks if the API key in the `Authorization` header matches one generated in the UI. If valid, the request proceeds.
2. **Storage**: The server creates a unique, random ID (e.g., `550e8400-e29b-41d4-a716-446655440000`).
3. **Expiration Math**: Because you chose `5min`, the server calculates the exact deletion time: `Current Time + 5 Minutes`.
4. **Memory Insertion**: It places the payload, IV, salt, and the deletion time into the RAM `secureStore` memory bank.
5. **Response Return**: The server responds to the app with the complete URL: 
   `{"url": "https://your-app.com/secure/550e8400...", "expiresAt": 17163821000}`.

### 4. Sending the Standard Email
The App takes the URL returning from the API and sends a regular email locally using standard JMAP to the recipient.
- **Subject**: "Sunil"
- **Email Body**: "You have received a secure message. It expires in 5 minutes. Click here to read it: `https://your-app.com/secure/550e8400...`"

### 5. Final Stage: The Recipient's Browser Process
1. The recipient opens the email and clicks the link.
2. They arrive at the React Frontend (`/secure/550e8400...`).
3. The React app reads the ID from the URL and silently hits the backend: `GET /api/secure-retrieve/550e8400...`.
4. **The Backend Wipe**: Because the message is configured as `viewOnce = true` (or the 5 minutes elapsed), the backend transmits the encrypted payload to the browser and **instantly deletes it** from Node.js memory. If the user refreshes, the message is permanently gone.
5. **Decryption UI**: The React UI renders a lock screen and says "Enter Password".
6. The user types `"mySecret123"`. The browser uses `crypto.subtle` inside the device's RAM to reverse the encryption.
7. `"Sunil right"` appears plainly on their screen.

---

## Part 2: Testing the API in the Terminal

You can test this entire backend flow using the standard `curl` command inside your terminal (MacOS/Linux) or Command Prompt (Windows).

### Step 1: Generate a new API Key
First, you need to create an API key to authenticate your mock application.

Run this in your terminal:
```bash
curl -X POST http://localhost:3000/api/keys \
  -H "Content-Type: application/json" \
  -d '{"name": "My Terminal App"}'
```
**Expected Output:**
```json
{"id": "c1f7b8...", "key": "sk_432f9a910...", "name": "My Terminal App", "createdAt": 1716000000}
```
*Copy the `sk_...` key from the response. You will need it for the next step.*

### Step 2: Send a Secure Message Payload
Now, you will behave exactly like the Android App transmitting the encrypted payload, and you will set the time limit to `5min`.

Replace `<YOUR_SK_KEY>` with the key you just generated:

```bash
curl -X POST http://localhost:3000/api/v1/secure-message \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer <YOUR_SK_KEY>" \
  -d '{
    "encryptedPayload": "fake_encrypted_base64_sunil_right", 
    "iv": "fake_iv", 
    "salt": "fake_salt", 
    "expiration": "5min", 
    "viewOnce": true
  }'
```
**Expected Output:**
```json
{"url": "http://localhost:3000/secure/9fa1b54a-...", "id": "9fa1b54a-...", "expiresAt": 1716383637152}
```
*Notice it gave you an ID and a URL. Copy the `id` from this response.*

### Step 3: Retrieve the Secure Message
Now, act as the recipient's browser. Fetch the message back from the server using the `id`.

Replace `<THE_ID>` with the `id` generated in Step 2:

```bash
curl http://localhost:3000/api/secure-retrieve/<THE_ID>
```
**Expected Output:**
```json
{
  "encryptedPayload": "fake_encrypted_base64_sunil_right",
  "iv": "fake_iv",
  "salt": "fake_salt",
  "expiresAt": 1716383637152,
  "viewOnce": true
}
```

### Step 4: Verify the "View Once" (Burn After Reading) Feature
Since we submitted the payload in Step 2 with `"viewOnce": true` (conceptually), our backend is instructed to destroy it in memory immediately after it is served once. 

Run the exact same command from Step 3 again:
```bash
curl http://localhost:3000/api/secure-retrieve/<THE_ID>
```
**Expected Output:**
```json
{"error": "Message not found or expired"}
```
It instantly vanishes! You have successfully tested the Secure Vault API flow directly from the terminal without writing any frontend code.
