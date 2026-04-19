import express from "express";
import { createServer as createViteServer } from "vite";
import path from "path";
import crypto from "crypto";

async function startServer() {
  const app = express();
  const PORT = 3000;

  app.use(express.json({ limit: '50mb' }));

  // Secure Message Store (In-Memory)
  interface SecureMessage {
    encryptedPayload: string;
    iv: string;
    salt: string;
    expiresAt: number;
    viewOnce: boolean;
  }
  const secureStore = new Map<string, SecureMessage>();

  // Cleanup task every 60 seconds
  setInterval(() => {
    const now = Date.now();
    for (const [id, msg] of secureStore.entries()) {
      if (now > msg.expiresAt) {
        secureStore.delete(id);
      }
    }
  }, 60000);

  app.post("/api/secure-store", (req, res) => {
    const { encryptedPayload, iv, salt, expiration, viewOnce } = req.body;
    const id = crypto.randomUUID();
    
    let ttl = 24 * 60 * 60 * 1000; // Default 1 day
    if (expiration === '5min') ttl = 5 * 60 * 1000;
    else if (expiration === '1hour') ttl = 60 * 60 * 1000;
    else if (expiration === '1week') ttl = 7 * 24 * 60 * 60 * 1000;
    else if (expiration === 'burn') ttl = 30 * 24 * 60 * 60 * 1000; // 30 days max for burn

    secureStore.set(id, {
      encryptedPayload,
      iv,
      salt,
      expiresAt: Date.now() + ttl,
      viewOnce: viewOnce || expiration === 'burn'
    });

    res.json({ id });
  });

  app.get("/api/secure-retrieve/:id", (req, res) => {
    const { id } = req.params;
    const msg = secureStore.get(id);

    if (!msg) {
      return res.status(404).json({ error: "Message not found or expired" });
    }

    if (msg.viewOnce) {
      secureStore.delete(id);
    }

    res.json({
      encryptedPayload: msg.encryptedPayload,
      iv: msg.iv,
      salt: msg.salt
    });
  });

  // JMAP Authentication / Session Discovery
  app.post("/api/jmap/session", async (req, res) => {
    const { serverUrl, username, password, capabilities } = req.body;
    try {
      const auth = Buffer.from(`${username}:${password}`).toString('base64');
      let cleanUrl = serverUrl.replace(/\/$/, '');
      if (cleanUrl.startsWith('http://')) {
        cleanUrl = cleanUrl.replace(/^http:\/\//, 'https://');
      }
      const sessionUrl = `${cleanUrl}/.well-known/jmap`;
      
      const response = await fetch(sessionUrl, {
        method: 'GET',
        headers: { 
          Authorization: `Basic ${auth}`,
          'Accept': 'application/json'
        }
      });
      
      if (!response.ok) {
        throw new Error(`Auth failed with status ${response.status}`);
      }
      
      const data = await response.json();
      res.json(data);
    } catch (e: any) {
      res.status(401).json({ error: e.message });
    }
  });

  // JMAP API Proxy
  app.post("/api/jmap/api", async (req, res) => {
    const { serverUrl, apiUrl, username, password, payload } = req.body;

    try {
      const auth = Buffer.from(`${username}:${password}`).toString('base64');
      
      let finalApiUrl = apiUrl;
      if (apiUrl && apiUrl.startsWith('/')) {
        const urlObj = new URL(serverUrl);
        finalApiUrl = `${urlObj.protocol}//${urlObj.host}${apiUrl}`;
      } else if (apiUrl && !apiUrl.startsWith('http')) {
        finalApiUrl = `${serverUrl.replace(/\/$/, '')}/${apiUrl.replace(/^\//, '')}`;
      }

      if (finalApiUrl.startsWith('http://')) {
        finalApiUrl = finalApiUrl.replace(/^http:\/\//, 'https://');
      }

      const response = await fetch(finalApiUrl, {
        method: 'POST',
        headers: {
          'Authorization': `Basic ${auth}`,
          'Content-Type': 'application/json',
          'Accept': 'application/json'
        },
        body: JSON.stringify(payload)
      });
      
      if (!response.ok) {
        const text = await response.text();
        throw new Error(`API request failed with status ${response.status}: ${text}`);
      }
      
      const data = await response.json();
      res.json(data);
    } catch (e: any) {
      console.error("JMAP API Error:", e.message);
      res.status(500).json({ error: e.message });
    }
  });

  // Vite middleware for development
  if (process.env.NODE_ENV !== "production") {
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: "spa",
    });
    app.use(vite.middlewares);
  } else {
    const distPath = path.join(process.cwd(), "dist");
    app.use(express.static(distPath));
    app.get("*", (req, res) => {
      res.sendFile(path.join(distPath, "index.html"));
    });
  }

  app.listen(PORT, "0.0.0.0", () => {
    console.log(`Server running on http://localhost:${PORT}`);
  });
}

startServer();
