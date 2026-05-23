# Complete Application Architecture & Code Analysis

This document provides an exhaustive, step-by-step breakdown of how the entire Secure Webmail Application is built, detailing the logic behind both the full server-side backend (Node.js/Express) and the client-side frontend (React).

---

## 1. High-Level Philosophy & Tech Stack
This application is designed as a **Privacy-First, Self-Hosted capable Webmail Client**. 
- **Frontend Stack**: React 18, TypeScript, Tailwind CSS, Vite, `lucide-react` for iconography.
- **Backend Stack**: Node.js, Express, TypeScript, `express-ws`.
- **Communication Protocol**: JMAP (JSON Meta Application Protocol) is used instead of legacy IMAP/SMTP. JMAP is highly efficient, utilizing a single JSON endpoint for all mail, calendar, and contact syncing.
- **Core Design Rule**: The server acts strictly as an **ephemeral gateway/proxy** and orchestrator. It possesses no persistent database (like Postgres or MongoDB) by design, preventing database leaks of sensitive user credentials or emails.

---

## 2. Server-Side Architecture (`server.ts`)

The Express server handles the routing, bridging, and background orchestrations that a browser cannot effectively perform on its own.

### A. The JMAP Proxy System
**Why a proxy?** Web browsers block cross-origin requests (CORS). A user might log in to a JMAP provider (like Fastmail) that doesn't allow direct API calls from `your-deployed-app.com`. 
- **The Solution**: The React client routes all JMAP requests to the local Express server paths (`/api/jmap/*`).
- **How it works**:
  - `POST /api/jmap/api`: Interprets the payload, extracts the `Authorization: Basic ...` headers, and uses the `fetch` API on the backend to forward the exact JSON payload to the upstream JMAP provider. It then pipes the provider's response back to the React UI.
  - `POST /api/jmap/upload` & `GET /api/jmap/download/*`: Handles binary streams for sending/receiving email attachments.
  - `ws /api/jmap/ws`: A WebSocket bridging endpoint implemented using `express-ws`. It establishes a persistent TCP connection to the upstream JMAP server allowing the provider to push real-time events (e.g., "New Email Arrived in Inbox"). The Express server relays this WebSocket frame directly to the browser.

### B. Feature: Secure Message Engine (Burn-After-Reading)
The backend acts as a volatile secure vault for storing encrypted message payloads.
- **Data Structure**: Uses a standard JavaScript `Map()` called `secureStore` existing only in RAM.
- **Write Endpoint (`POST /api/secure-store`)**: Accepts `{ encryptedPayload, iv, salt, expiration, viewOnce }`. Generates a random `UUID` and stores the object.
- **Read Endpoint (`GET /api/secure-retrieve/:id`)**: Looks up the `UUID`. If the `viewOnce` flag is true, it immediately deletes the item from memory after sending the response.
- **Garbage Collection (Sweeper)**: A background worker (`setInterval`) runs every 60 seconds, sweeping the `Map()` and forcefully deleting any secure message payload where `Date.now() > expiresAt`.

### C. Feature: Scheduled Email Job Engine
Since browsers can be closed, "Send Later" functionality must reside on the server.
- **Data Structure**: Uses an in-memory `Map()` called `scheduledJobs` containing the email payload, JMAP credentials, and an `executeAt` timestamp.
- **Endpoints**: `/api/jobs/schedule` to submit a future email, `/api/jobs` to list them, and `DELETE /api/jobs/:id` to cancel them.
- **Execution Worker**: A Node.js `setInterval` fires every 30 seconds. It evaluates: `if (Date.now() >= executeAt)`. If true, it formats the JMAP HTTP payload, executing the send remotely via the upstream server. Once successfully sent, the job is cleared.

### D. Feature: API Keys Management (External Integrations)
This module caters to external clients (like Android/iOS apps) interacting with our backend.
- **Logic**: Keeps an `apiKeys` Map in memory.
- UI hits `POST /api/keys` to generate a `sk_...` key.
- A mobile app can then POST to `/api/v1/secure-message` with `Authorization: Bearer <sk_key>` to drop an encrypted payload into the secure store directly, bypassing the need for a full JMAP password lifecycle.

---

## 3. Client-Side Architecture (`src/App.tsx`, `src/lib/*`)

The frontend is a monolithic Single Page Application (SPA), emphasizing instantaneous state updates over constant page loads.

### A. JMAP Protocol Client (`src/lib/jmap-client.ts`)
This class provides object-oriented wrappers over raw JMAP JSON strings.
- Handles capability discovery (Mail, Contacts, Calendars).
- Exposes methods like `getEmails`, `submitEmail`, `getMailboxes`.
- Features strict payload packaging, ensuring that emails with embedded base64 HTML and attachments adhere precisely to JMAP mult-part guidelines.
- Always points to the `/api/jmap/api` proxy rather than the real server.

### B. Client-side State & Navigation Management
- **Hooks & Context**: Uses standard React hooks (`useState`, `useEffect`, `useRef`) comprehensively within `App.tsx`. 
- **Persisted User Preferences**: Leverages browser `localStorage` as a synchronous key-value store to save hundreds of user parameters immediately on toggle (e.g., Dark Mode preferences, Compose Format `html|plain`, "Empty Trash on Exit" settings).
- **Navigation Pattern**: The main view relies on the `activeApp` state (`'mail' | 'calendar' | 'contacts' | 'settings'`) to dynamically render distinct mega-panels.

### C. Mail Interface & Viewer
- **Left Sidebar**: Fetches mailboxes recursively.
- **List View**: Executes `"Email/query"` to obtain sorted `ids`, then executes `"Email/get"` sequentially for those IDs to get previews and subject lines.
- **Email Viewer (`HtmlEmailViewer`)**:
  - Extremely sensitive regarding security (XSS). Opening email HTML in the DOM is dangerous.
  - **Sanitization**: Code runs HTML through `DOMPurify` to mathematically strip arbitrary `<script/>` tags and `onload=` handlers.
  - **Isolation**: Inserts the purified HTML directly inside a headless `<iframe>` Document context, walling off CSS styling and Javascript leaks between the UI and the email contents.

### D. End-to-End Encryption (Secure Mail)
- Integrates the Web `crypto.subtle` API natively (`src/lib/crypto.ts`).
- **Encryption Process**: When a user authors a "Secure Message":
  1. The UI prompts for a local passphrase.
  2. PBKDF2 generates a stable CryptoKey from the passphrase.
  3. AES-GCM mathematically transforms the composed text body into ciphertext.
  4. The ciphertext is sent to the Node backend (`/api/secure-store`).
  5. The standard outgoing JMAP Email simply reads: `"I have sent you a secure message: https://app.../secure/xxxx"`. The plain text is eradicated locally.
- **Decryption Process**: A recipient follows the link, the React Router intercepts the `/secure/:id` path, grabs the encrypted blob from the Node server, prompts the user for the password, and decrypts the UI locally.

### E. Calendar Interface
- Fully implements local date math (leap years, offset grids, day mapping).
- Iterates over JMAP Calendar objects, rendering Month, Week, and Agenda Views.
- Utilizes overlapping collision detection logic to paint absolute bounding boxes for conflicting events.

### F. Settings & Toggles
A massive configuration panel handling everything from API keys to UI layout states. Changes made here map back immediately through `localStorage` and trigger React re-renders globally (e.g., toggling `Plain Text Only` mode completely hides the Rich Text formatting bar everywhere).

---

## 4. UI/UX Identity & Styling Strategy
- **Tailwind System**: Class-driven styling avoids sprawling `.css` files, keeping structural layouts combined with visual aesthetics locally aligned.
- **Design Metaphor**: Uses dark, high-contrast, modern "Glassmorphism" where applicable. Heavy usage of `dark:bg-slate-900`, `dark:border-slate-800` alongside vibrant Indigo/Purple accent hues.
- **Micro-interactivity**: Standardizes on `group-hover` and `opacity-0 hover:opacity-100` strategies for action buttons (like Delete/Star icons that only appear when actively focusing on an email).

## 5. Deployment Characteristics
- Built for Serverless environments (like Google Cloud Run).
- `package.json` configures a unified build pipeline: `vite build` bundles the client to `/dist`, and `esbuild` statically compiles the entire Express backend to `dist/server.cjs` keeping cold-starts lightning fast while circumventing legacy CommonJS/ESM module boundaries.
