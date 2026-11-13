import crypto from 'crypto';

async function generateSecurePayload(password, subject, body, expiration = "1week", viewOnce = false) {
  // 1. Generate secure random IV and Salt
  const salt = crypto.randomBytes(16);
  const iv = crypto.randomBytes(12);

  // 2. Derive the 256-bit key from the password (PBKDF2)
  const keyMaterial = await crypto.subtle.importKey(
    "raw", 
    new TextEncoder().encode(password), 
    { name: "PBKDF2" }, 
    false, 
    ["deriveKey"]
  );
  
  const key = await crypto.subtle.deriveKey(
    { name: "PBKDF2", salt, iterations: 100000, hash: "SHA-256" },
    keyMaterial, 
    { name: "AES-GCM", length: 256 }, 
    false, 
    ["encrypt"]
  );

  // 3. Prepare the JSON data explicitly mapping subject and body
  const payloadStr = JSON.stringify({ subject, body, attachments: [] });

  // 4. Encrypt it using AES-GCM
  const encrypted = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv }, 
    key, 
    new TextEncoder().encode(payloadStr)
  );

  // 5. Build the final request body
  const requestBody = {
    encryptedPayload: Buffer.from(encrypted).toString('base64'),
    iv: Buffer.from(iv).toString('base64'),
    salt: Buffer.from(salt).toString('base64'),
    expiration, 
    viewOnce
  };

  console.log("JSON Payload: \n");
  console.log(JSON.stringify(requestBody, null, 2));
}

const args = process.argv.slice(2);
if (args.length < 3) {
  console.log("Usage: node generate-secure-payload.js <password> <subject> <body> [expiration] [viewOnce]");
} else {
  generateSecurePayload(args[0], args[1], args[2], args[3] || "1week", args[4] === "true");
}
