# Stalwart JMAP Webmail Client

<div align="center">

![License](https://img.shields.io/badge/license-MIT-blue.svg)
![TypeScript](https://img.shields.io/badge/TypeScript-5.8-blue?logo=typescript)
![React](https://img.shields.io/badge/React-19-61dafb?logo=react)
![Tailwind CSS](https://img.shields.io/badge/TailwindCSS-v4-38bdf8?logo=tailwindcss)
![Vite](https://img.shields.io/badge/Vite-6-646cff?logo=vite)
![JMAP](https://img.shields.io/badge/JMAP-RFC%208620%20%7C%208621-green)
![Security](https://img.shields.io/badge/Security-Hardened-success)

**A modern, secure, and full-featured webmail, calendar, and contacts client for [Stalwart Mail Server](https://stalw.art) and RFC-compliant JMAP providers.**

</div>

---

## Table of Contents
- [Overview](#overview)
- [Key Features](#key-features)
  - [Email Client](#email-client)
  - [Calendar](#calendar)
  - [Contacts & Address Book](#contacts--address-book)
  - [Sieve Mail Filtering](#sieve-mail-filtering)
  - [Secure Ephemeral Messaging](#secure-ephemeral-messaging)
  - [Scheduled & Delayed Send](#scheduled--delayed-send)
- [Security Architecture & Hardening](#security-architecture--hardened)
- [JMAP Protocol Specifications](#jmap-protocol-specifications)
- [Getting Started](#getting-started)
  - [Prerequisites](#prerequisites)
  - [Environment Variables](#environment-variables)
  - [Installation](#installation)
  - [Running the App](#running-the-app)
- [Building for Production](#building-for-production)
- [Docker Deployment](#docker-deployment)
- [License](#license)

---

## Overview

The **Stalwart JMAP Webmail Client** is a responsive, single-page webmail interface built from the ground up using **React 19**, **TypeScript**, and **Tailwind CSS v4**. It communicates directly with downstream mail servers using the modern **JMAP (JSON Meta Application Protocol)** standard (RFC 8620 and RFC 8621), offering real-time push updates over WebSockets, low latency, and a desktop-class user experience.

---

## Key Features

### Email Client
- **Full Folder & Role Support**: Inbox, Drafts, Sent, Trash, Spam, Archive, Reports, and custom mailboxes.
- **Rich Message Viewer**: Safe HTML rendering via sandboxed iframes and strict DOMPurify sanitization.
- **Smart Dark Mode**: Automatic background and contrast inversion for dark mode email reading.
- **Tagging & Flagging**: Native support for `$seen`, `$flagged`, `$draft`, and color-coded labels (`$label:red`, `$label:blue`, etc.).
- **Conversation Threading**: Seamless `inReplyTo` and `references` threading according to RFC 5322.
- **Draft Synchronization**: Atomic draft management adhering to RFC 8621 immutable property specifications.
- **Attachment Previews**: In-client previews for images and documents with memory-managed Blob object URLs.

### Calendar
- **Interactive Views**: Month, Week, and Day grid layouts with live time markers.
- **JSCalendar Integration**: RFC 8984 event models with attendees, time zones, recurrence rules, and virtual meeting links.
- **iCal Import / Export**: Proxy-safe synchronization with external `.ics` calendar feeds.

### Contacts & Address Book
- **JSContact / vCard Support**: Manage contact cards, avatars, email addresses, phone numbers, and organizations.
- **Contact Avatars**: Auto-generated initials and photo uploads.
- **Quick Address Autocomplete**: Instant recipient suggestions when composing emails.

### Sieve Mail Filtering
- **Dynamic Sieve Script Generation**: Visual UI to configure rules based on sender, recipient, subject, headers, message size, and spam score.
- **Automated Categorization**: Instant sorting for Promotions, Social, Updates, and Reports.
- **Injection-Proof Compilation**: Strict escaping of Sieve string literals (`\`, `"`, and control characters).

### Secure Ephemeral Messaging
- **Client-Side Encryption**: 256-bit AES-GCM encryption with PBKDF2 (100,000 iterations) key derivation.
- **Burn-After-Reading**: One-time view links that shred message payloads immediately upon retrieval.
- **Configurable Expiry**: 5 minutes, 1 hour, 1 day, or 1 week TTL.

### Scheduled & Delayed Send
- **Undo Send**: Configurable 5s to 30s countdown window to cancel immediate sends.
- **Scheduled Send**: Schedule email dispatch for a future timestamp with background dispatching.

---

## Security Architecture & Hardening

The application is thoroughly security-audited and hardened across frontend and backend boundaries:

1. **Strict TLS Verification**: All outbound HTTPS connections to JMAP and iCal endpoints enforce valid TLS certificates by default. Optional relaxation for self-signed development servers is gated strictly behind explicit environment variables.
2. **SSRF Protection**: All backend proxy endpoints (`/api/ical`, `/api/jmap/*`, `/api/ws-proxy`) block internal loopback (`127.0.0.1`, `localhost`), link-local (`169.254.169.254`), and cloud metadata IP ranges.
3. **Attachment Sandbox & XSS Protection**: SVG and HTML attachments are barred from opening as top-level same-origin documents, forcing download or safe rendering within isolated elements.
4. **Content Security Policy (CSP)**: Enforced via HTTP headers and meta tags to restrict unauthorized script execution and object embedding.
5. **Memory Capacity Guards**: In-memory stores (`secureStore`, `scheduledJobs`, `apiKeys`) enforce strict size caps (maximum 1,000 items) to prevent Out-Of-Memory (OOM) denial-of-service vectors.
6. **Administrative Protection**: Remote maintenance and developer endpoints are protected with Bearer token authentication.

---

## JMAP Protocol Specifications

| RFC / Spec | Scope | Implementation |
|---|---|---|
| **RFC 8620** | JMAP Core Protocol | Session discovery (`/.well-known/jmap`), request batching, capability negotiation, and error handling. |
| **RFC 8621** | JMAP Mail | Mailbox CRUD, `Thread/get` conversation threads, `Email/changes` delta sync, Tantivy server-side `FilterCondition` search, native `sendAt` scheduled send, and atomic submission cleanup. |
| **RFC 8887** | JMAP over WebSocket | Real-time push notifications (`@type: "StateChange"`) with zero-flicker incremental delta updates. |
| **RFC 8984** | JSCalendar Model | Full `@type: "Event"` data model with IANA time zones, duration, status, recurrence rules, and participant models. |
| **RFC 9670** | JMAP for Calendars | Calendar management, `expandRecurrences` server expansion, recurrence overrides, and 1-click meeting RSVP scheduling. |
| **RFC 9425** | JMAP for Quotas | Account and domain storage limits tracking with live sidebar quota visualizer. |
| **RFC 9404** | JMAP Blob Management | Blob upload/download proxying and streaming. |
| **RFC 9661** | JMAP for Sieve Scripts | Sieve script compilation, upload as blobs, and active script management. |
| **RFC 9553 / 9610** | JSContact & Address Books | ContactCard CRUD, multi-address book support, and vCard 3.0/4.0 interoperability. |
| **RFC 5322** | Internet Message Format | Multi-recipient headers, threading (`Message-ID`, `In-Reply-To`, `References`). |

---

## Getting Started

### Prerequisites
- **Node.js**: v18.0.0 or higher
- **npm**: v9.0.0 or higher
- Access to a **Stalwart Mail Server** or any JMAP-compatible server (e.g., Cyrus IMAP, Fastmail).

### Environment Variables

Create a `.env` file in the project root based on `.env.example`:

```bash
# Server Port
PORT=3000

# Administrative API Key (Required for /api/admin/* and /api/keys)
ADMIN_API_KEY="your-strong-random-admin-secret"

# Allowed CORS Origins (Comma-separated, leave blank for same-origin)
ALLOWED_ORIGINS="http://localhost:3000,https://mail.yourdomain.com"

# Development Flags (DO NOT enable in production)
ALLOW_INSECURE_TLS=false
ALLOW_PRIVATE_NETWORK=false

# Optional Gemini API Key (if AI assistance features are enabled)
GEMINI_API_KEY=""
```

### Installation

```bash
# Clone the repository
git clone https://github.com/your-username/jmap-webmail-client.git
cd jmap-webmail-client

# Install dependencies
npm install
```

### Running the App

```bash
# Start backend server and Vite dev server together
npm run dev
```

Open your browser at:
```
http://localhost:3000
```

---

## Building for Production

```bash
# Compile frontend and bundle server
npm run build

# Start the production runner
npm start
```

The production bundle outputs to the `dist/` directory.

---

## Docker Deployment

You can build and deploy the application using the included runner:

```dockerfile
FROM node:20-alpine
WORKDIR /app

COPY package*.json ./
RUN npm ci --only=production

COPY . .
RUN npm run build

EXPOSE 3000
ENV NODE_ENV=production
CMD ["node", "runner.js"]
```

```bash
# Build Docker image
docker build -t jmap-webmail-client .

# Run container
docker run -d -p 3000:3000 --env-file .env --name webmail jmap-webmail-client
```

---

## License

This project is open-source and available under the [MIT License](LICENSE).
