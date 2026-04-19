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

  // Scheduled Email Store (In-Memory Volatile)
  interface ScheduledJob {
    executeAt: number;
    draftId: string;
    identityId: string;
    accountId: string;
    apiUrl: string;
    serverUrl: string;
    authHeader: string;
    sentMailboxId: string;
  }
  const scheduledJobs = new Map<string, ScheduledJob>();

  // The Dispatch Cron Job
  setInterval(async () => {
    const now = Date.now();
    for (const [jobId, job] of scheduledJobs.entries()) {
      if (now >= job.executeAt) {
        scheduledJobs.delete(jobId);
        
        try {
      // THE FIX: Reconstruct the relative URL into an absolute URL and force HTTPS
      let finalApiUrl = job.apiUrl;
      if (finalApiUrl && finalApiUrl.startsWith('/')) {
        try {
          const urlObj = new URL(job.serverUrl);
          const protocol = urlObj.protocol === 'http:' ? 'https:' : urlObj.protocol;
          finalApiUrl = `${protocol}//${urlObj.host}${finalApiUrl}`;
        } catch (e) {
          let base = job.serverUrl.replace(/\/$/, '');
          if (!base.startsWith('http')) base = `https://${base}`;
          finalApiUrl = `${base}/${finalApiUrl.replace(/^\//, '')}`;
        }
      } else if (finalApiUrl && !finalApiUrl.startsWith('http')) {
        let base = job.serverUrl.replace(/\/$/, '');
        if (!base.startsWith('http')) base = `https://${base}`;
        finalApiUrl = `${base}/${finalApiUrl.replace(/^\//, '')}`;
      }
      
      // STRICT HTTPS UPGRADE: Prevent OpenResty 400 Errors
      let targetUrl = finalApiUrl;
      if (targetUrl) {
        if (targetUrl.includes(':443') && targetUrl.startsWith('http://')) {
          targetUrl = targetUrl.replace(/^http:\/\//i, 'https://');
        } else if (targetUrl.includes('sunilshahid.com') && targetUrl.startsWith('http://')) {
          targetUrl = targetUrl.replace(/^http:\/\//i, 'https://');
        }
      }

      const response = await fetch(targetUrl, {
            method: 'POST',
            headers: {
              'Authorization': job.authHeader,
              'Content-Type': 'application/json'
            },
            body: JSON.stringify({
              using: ["urn:ietf:params:jmap:core", "urn:ietf:params:jmap:mail", "urn:ietf:params:jmap:submission"],
              methodCalls: [
                ["Email/set", { 
                  accountId: job.accountId, 
                  update: { [job.draftId]: { "keywords/$draft": false, "keywords/$seen": true, mailboxIds: { [job.sentMailboxId]: true } } } 
                }, "0"],
                ["EmailSubmission/set", { 
                  accountId: job.accountId, 
                  create: { "1": { emailId: job.draftId, identityId: job.identityId } } 
                }, "1"]
              ]
            })
          });
          
          if (!response.ok) throw new Error(`Status ${response.status}`);
          console.log(`Successfully dispatched scheduled draft: ${job.draftId}`);
        } catch (e) {
          console.error(`Failed to dispatch scheduled email: ${e}`);
        }
      }
    }
  }, 30000);

  // Endpoint to receive scheduled jobs
  app.post("/api/schedule-send", (req, res) => {
    const { executeAt, draftId, identityId, accountId, apiUrl, serverUrl, username, password, sentMailboxId } = req.body;
    const jobId = Date.now().toString() + Math.random().toString(36);
    const authHeader = `Basic ${Buffer.from(`${username}:${password}`).toString('base64')}`;
    
    // Pass serverUrl into the queue
    scheduledJobs.set(jobId, { executeAt, draftId, identityId, accountId, apiUrl, serverUrl, authHeader, sentMailboxId });
    res.json({ success: true, jobId });
  });

  app.get("/api/scheduled-jobs", (req, res) => {
    const jobs = Array.from(scheduledJobs.values()).map(job => ({
      draftId: job.draftId,
      executeAt: job.executeAt
    }));
    res.json(jobs);
  });

  app.delete("/api/schedule-send/:draftId", (req, res) => {
    const { draftId } = req.params;
    let found = false;
    for (const [jobId, job] of scheduledJobs.entries()) {
      if (job.draftId === draftId) {
        scheduledJobs.delete(jobId);
        found = true;
      }
    }
    res.json({ success: found });
  });

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
      
      let cleanUrl = serverUrl.trim().replace(/\/$/, '');
      if (!cleanUrl.startsWith('http')) {
        cleanUrl = `https://${cleanUrl}`;
      }
      
      const sessionUrl = `${cleanUrl}/.well-known/jmap`;
      console.log(`JMAP Session Discovery: ${sessionUrl}`);
      
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
      
      let baseServerUrl = serverUrl.trim();
      if (!baseServerUrl.startsWith('http')) {
        baseServerUrl = `https://${baseServerUrl}`;
      }

      let finalApiUrl = apiUrl;
      if (apiUrl && apiUrl.startsWith('/')) {
        try {
          const urlObj = new URL(baseServerUrl);
          const protocol = urlObj.protocol === 'http:' ? 'https:' : urlObj.protocol;
          finalApiUrl = `${protocol}//${urlObj.host}${apiUrl}`;
        } catch (e) {
          finalApiUrl = `${baseServerUrl.replace(/\/$/, '')}/${apiUrl.replace(/^\//, '')}`;
        }
      } else if (apiUrl && !apiUrl.startsWith('http')) {
        finalApiUrl = `${baseServerUrl.replace(/\/$/, '')}/${apiUrl.replace(/^\//, '')}`;
      }

      // STRICT HTTPS UPGRADE: Prevent OpenResty 400 Errors
      let targetUrl = finalApiUrl;
      if (targetUrl) {
        if (targetUrl.includes(':443') && targetUrl.startsWith('http://')) {
          targetUrl = targetUrl.replace(/^http:\/\//i, 'https://');
        } else if (targetUrl.includes('sunilshahid.com') && targetUrl.startsWith('http://')) {
          targetUrl = targetUrl.replace(/^http:\/\//i, 'https://');
        }
      }

      console.log(`JMAP API Proxy: ${targetUrl}`);

      const response = await fetch(targetUrl, {
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
        console.error(`JMAP API request failed - URL: ${targetUrl}, Status: ${response.status}, Error: ${text}`);
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
