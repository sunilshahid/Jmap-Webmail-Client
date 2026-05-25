import express from "express";
import cors from "cors";
import { createServer as createViteServer } from "vite";
import path from "path";
import crypto from "crypto";
import { spawn } from "child_process";
import { WebSocketServer, WebSocket as NodeWebSocket } from "ws";
import { setGlobalDispatcher, Agent } from "undici";

// Allow self-signed certificates for downstream JMAP server connections globally for Node 18+ internal fetch
setGlobalDispatcher(new Agent({
  connect: {
    rejectUnauthorized: false
  }
}));
process.env.NODE_TLS_REJECT_UNAUTHORIZED = "0";

async function startServer() {
  let isDeveloperMode = false;
  function logDev(...args: any[]) {
    if (isDeveloperMode) {
      console.log('[DevMode]', ...args);
    }
  }

  const app = express();
  const PORT = 3000;

  app.use(cors({ origin: true, credentials: true }));
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
          logDev(`Successfully dispatched scheduled draft: ${job.draftId}`);
        } catch (e) {
          logDev(`Failed to dispatch scheduled email: ${e}`);
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

  // API Keys (In-Memory)
  interface ApiKey {
    id: string;
    key: string;
    name: string;
    createdAt: number;
  }
  const apiKeys = new Map<string, ApiKey>();

  app.get("/api/keys", (req, res) => {
    res.json(Array.from(apiKeys.values()).map(k => ({ id: k.id, name: k.name, createdAt: k.createdAt })));
  });

  app.post("/api/keys", (req, res) => {
    const { name } = req.body;
    const id = crypto.randomUUID();
    const key = "sk_" + crypto.randomBytes(24).toString('hex');
    apiKeys.set(id, { id, key, name, createdAt: Date.now() });
    res.json({ id, key, name, createdAt: Date.now() });
  });

  app.delete("/api/keys/:id", (req, res) => {
    apiKeys.delete(req.params.id);
    res.json({ success: true });
  });

  app.post("/api/v1/secure-message", (req, res) => {
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith("Bearer ")) {
      return res.status(401).json({ error: "Missing or invalid Authorization header" });
    }
    const token = authHeader.split(" ")[1];
    const isValid = Array.from(apiKeys.values()).some(k => k.key === token);
    if (!isValid) return res.status(401).json({ error: "Invalid API Key" });

    const { encryptedPayload, iv, salt, expiration, viewOnce } = req.body;
    if (!encryptedPayload || !iv || !salt) {
       return res.status(400).json({ error: "Missing required encryption fields: encryptedPayload, iv, salt" });
    }
    
    const id = crypto.randomUUID();
    let ttl = 24 * 60 * 60 * 1000;
    if (expiration === '5min') ttl = 5 * 60 * 1000;
    else if (expiration === '1hour') ttl = 60 * 60 * 1000;
    else if (expiration === '1week') ttl = 7 * 24 * 60 * 60 * 1000;
    else if (expiration === 'burn') ttl = 30 * 24 * 60 * 60 * 1000;
    else if (expiration && !isNaN(new Date(expiration).getTime())) {
      const expDate = new Date(expiration).getTime();
      const diff = expDate - Date.now();
      if (diff > 0) ttl = diff;
    }

    logDev(`[Secure Message API] Generated message ID=${id}, ttl=${ttl}ms`);

    secureStore.set(id, {
      encryptedPayload,
      iv,
      salt,
      expiresAt: Date.now() + ttl,
      viewOnce: viewOnce || expiration === 'burn'
    });

    const host = req.get('host');
    const protocol = req.headers['x-forwarded-proto'] || req.protocol;
    const url = `${protocol}://${host}/secure/${id}`;

    res.json({ url, id, expiresAt: Date.now() + ttl });
  });

  app.post("/api/secure-store", (req, res) => {
    const { encryptedPayload, iv, salt, expiration, viewOnce } = req.body;
    const id = crypto.randomUUID();
    
    let ttl = 24 * 60 * 60 * 1000; // Default 1 day
    if (expiration === '5min') ttl = 5 * 60 * 1000;
    else if (expiration === '1hour') ttl = 60 * 60 * 1000;
    else if (expiration === '1week') ttl = 7 * 24 * 60 * 60 * 1000;
    else if (expiration === 'burn') ttl = 30 * 24 * 60 * 60 * 1000; // 30 days max for burn
    else if (expiration && !isNaN(new Date(expiration).getTime())) {
      const expDate = new Date(expiration).getTime();
      const diff = expDate - Date.now();
      if (diff > 0) ttl = diff;
    }

    logDev(`[Secure Message UI] Generated message ID=${id}, ttl=${ttl}ms`);

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
      logDev(`[Secure Retrieve] Failed lookup or expired message ID=${id}`);
      return res.status(404).json({ error: "Message not found or expired" });
    }

    if (msg.viewOnce) {
      logDev(`[Secure Retrieve] Message ID=${id} marked viewOnce. Shredding payload immediately.`);
      secureStore.delete(id);
    } else {
      logDev(`[Secure Retrieve] Message ID=${id} fetched successfully.`);
    }

    res.json({
      encryptedPayload: msg.encryptedPayload,
      iv: msg.iv,
      salt: msg.salt
    });
  });

  // Admin APIs
  app.get("/api/admin/developer-mode", (req, res) => {
    res.json({ isDeveloperMode });
  });

  app.post("/api/admin/developer-mode", (req, res) => {
    isDeveloperMode = req.body.isDeveloperMode === true;
    res.json({ isDeveloperMode });
  });

  app.get("/api/admin/update", (req, res) => {
    res.writeHead(200, {
      'Content-Type': 'text/event-stream',
      'Cache-Control': 'no-cache',
      'Connection': 'keep-alive'
    });

    const sendEvent = (msg: string) => res.write(`data: ${JSON.stringify({ message: msg })}\n\n`);
    
    sendEvent("Starting Smart Update...");

    const runCommand = (cmd: string, args: string[]) => {
      return new Promise<{stdout: string, stderr: string, code: number | null}>((resolve) => {
        const child = spawn(cmd, args);
        let stdout = '';
        let stderr = '';
        child.stdout.on('data', (data) => stdout += data.toString());
        child.stderr.on('data', (data) => stderr += data.toString());
        child.on('close', (code) => resolve({ stdout, stderr, code }));
      });
    };

    (async () => {
      try {
        sendEvent("Running git pull origin main...");
        let resGit = await runCommand("git", ["pull", "origin", "main"]);
        
        if (resGit.code !== 0) {
           sendEvent(`Git pull non-zero exit: ${resGit.stderr.substring(0, 100)}... Skipping smart check.`);
        } else {
           sendEvent("Git pull successful.");
           let diff = await runCommand("git", ["diff", "HEAD@{1}", "HEAD", "--name-only"]);
           
           if (diff.stdout.includes("package.json")) {
              sendEvent("Updating dependencies...");
              await runCommand("npm", ["install"]);
           }
           
           if (diff.stdout.includes("src/")) {
              sendEvent("Rebuilding frontend...");
              await runCommand("npm", ["run", "build"]);
           }
           
           if (!diff.stdout.includes("package.json") && !diff.stdout.includes("src/")) {
              sendEvent("No major structural changes detected. Moving to restart.");
           }
        }
        
        sendEvent("Restarting server...");
        // Gracefully kill process, rely on container/PM2 to reboot it
        setTimeout(() => {
          process.exit(0);
        }, 1000);
      } catch (err: any) {
        sendEvent(`Error during update: ${err.message}`);
        res.write(`data: ${JSON.stringify({ done: true })}\n\n`);
        res.end();
      }
    })();
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
      logDev(`JMAP Session Discovery: ${sessionUrl}`);
      
      const response = await fetch(sessionUrl, {
        method: 'GET',
        headers: { 
          Authorization: `Basic ${auth}`,
          'Accept': 'application/json'
        }
      });
      
      if (!response.ok) {
        if (response.status === 401 || response.status === 403) {
          throw new Error("Authentication failed. Please check your username and password.");
        }
        let errText = await response.text();
        if (errText.includes('<html') || errText.length > 200) {
           throw new Error(`Server returned status ${response.status} ${response.statusText} (Is the JMAP server online?)`);
        }
        throw new Error(`Server returned status ${response.status}: ${errText}`);
      }
      
      const data = await response.json();
      res.json(data);
    } catch (e: any) {
      if (e.message.includes('fetch failed') || e.cause) {
         res.status(502).json({ error: `Cannot contact server at ${serverUrl}. Please check the server URL.` });
      } else {
         res.status(401).json({ error: e.message });
      }
    }
  });

  // iCal fetch proxy
  app.get("/api/ical", async (req, res) => {
    try {
      const url = req.query.url as string;
      if (!url) {
        return res.status(400).json({ error: "Missing url parameter" });
      }
      
      const response = await fetch(url, { headers: { 'User-Agent': 'Mozilla/5.0 webmail' }});
      if (!response.ok) {
        throw new Error(`Failed to fetch iCal: ${response.status} ${response.statusText}`);
      }
      const text = await response.text();
      res.set('Content-Type', 'text/calendar');
      res.send(text);
    } catch (err: any) {
      console.error('iCal fetch error:', err);
      res.status(500).json({ error: err.message });
    }
  });

  // JMAP api proxy
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

      logDev(`JMAP API Proxy: POST ${targetUrl}`);
      logDev(`[Server-Side Log] JMAP REQUEST Payload:`, JSON.stringify(payload, null, 2));

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
        let cleanedText = text;
        if (cleanedText.includes('<html') || cleanedText.length > 200) {
           cleanedText = "Server returned " + response.status + " " + response.statusText + " (Is the JMAP server online?)";
        }
        logDev(`JMAP API request failed - URL: ${targetUrl}, Status: ${response.status}`);
        throw new Error(`API request failed with status ${response.status}: ${cleanedText}`);
      }
      
      const data = await response.json();
      logDev(`[Server-Side Log] JMAP RESPONSE:`, JSON.stringify(data).substring(0, 500) + '... (truncated)');
      res.json(data);
    } catch (e: any) {
      logDev("JMAP API Error:", e.message);
      res.status(500).json({ error: e.message });
    }
  });

  // JMAP Upload Proxy
  app.post("/api/jmap/upload", express.raw({ type: '*/*', limit: '50mb' }), async (req, res) => {
    const serverUrl = req.headers['x-jmap-server-url'] as string;
    const uploadUrl = req.headers['x-jmap-upload-url'] as string;
    const username = req.headers['x-jmap-username'] as string;
    const password = req.headers['x-jmap-password'] as string;
    const contentType = req.headers['content-type'] || 'application/octet-stream';

    if (!serverUrl || !uploadUrl || !username || !password) {
      return res.status(400).json({ error: "Missing JMAP proxy headers" });
    }

    try {
      const auth = Buffer.from(`${username}:${password}`).toString('base64');
      
      let baseServerUrl = serverUrl.trim();
      if (!baseServerUrl.startsWith('http')) {
        baseServerUrl = `https://${baseServerUrl}`;
      }

      let finalUploadUrl = uploadUrl;
      if (uploadUrl.startsWith('/')) {
        try {
          const urlObj = new URL(baseServerUrl);
          const protocol = urlObj.protocol === 'http:' ? 'https:' : urlObj.protocol;
          finalUploadUrl = `${protocol}//${urlObj.host}${uploadUrl}`;
        } catch (e) {
          finalUploadUrl = `${baseServerUrl.replace(/\/$/, '')}/${uploadUrl.replace(/^\//, '')}`;
        }
      } else if (!uploadUrl.startsWith('http')) {
        finalUploadUrl = `${baseServerUrl.replace(/\/$/, '')}/${uploadUrl.replace(/^\//, '')}`;
      }

      // STRICT HTTPS UPGRADE
      if (finalUploadUrl.includes(':443') && finalUploadUrl.startsWith('http://')) {
        finalUploadUrl = finalUploadUrl.replace(/^http:\/\//i, 'https://');
      } else if (finalUploadUrl.includes('sunilshahid.com') && finalUploadUrl.startsWith('http://')) {
        finalUploadUrl = finalUploadUrl.replace(/^http:\/\//i, 'https://');
      }

      logDev(`JMAP Upload Proxy: ${finalUploadUrl}`);

      const response = await fetch(finalUploadUrl, {
        method: 'POST',
        headers: {
          'Authorization': `Basic ${auth}`,
          'Content-Type': contentType as string
        },
        body: req.body
      });

      if (!response.ok) {
        let errText = await response.text();
        if (errText.includes('<html') || errText.length > 200) {
           errText = `Server returned ${response.status} ${response.statusText} (Is the JMAP server online?)`;
        }
        logDev(`JMAP Upload failed - URL: ${finalUploadUrl}, Status: ${response.status}, Error: ${errText}`);
        throw new Error(`Upload failed with status ${response.status}: ${errText}`);
      }

      const data = await response.json();
      res.json(data);
    } catch (e: any) {
      logDev("JMAP Upload Error:", e.message);
      res.status(500).json({ error: e.message });
    }
  });

  // JMAP Download Proxy
  app.get("/api/jmap/download", async (req, res) => {
    const serverUrl = req.headers['x-jmap-server-url'] as string;
    const downloadUrl = req.headers['x-jmap-download-url'] as string;
    const username = req.headers['x-jmap-username'] as string;
    const password = req.headers['x-jmap-password'] as string;

    if (!serverUrl || !downloadUrl || !username || !password) {
      return res.status(400).json({ error: "Missing JMAP proxy headers" });
    }

    try {
      const auth = Buffer.from(`${username}:${password}`).toString('base64');
      
      let baseServerUrl = serverUrl.trim();
      if (!baseServerUrl.startsWith('http')) {
        baseServerUrl = `https://${baseServerUrl}`;
      }

      let finalDownloadUrl = downloadUrl;
      if (downloadUrl.startsWith('/')) {
        try {
          const urlObj = new URL(baseServerUrl);
          const protocol = urlObj.protocol === 'http:' ? 'https:' : urlObj.protocol;
          finalDownloadUrl = `${protocol}//${urlObj.host}${downloadUrl}`;
        } catch (e) {
          finalDownloadUrl = `${baseServerUrl.replace(/\/$/, '')}/${downloadUrl.replace(/^\//, '')}`;
        }
      } else if (!downloadUrl.startsWith('http')) {
        finalDownloadUrl = `${baseServerUrl.replace(/\/$/, '')}/${downloadUrl.replace(/^\//, '')}`;
      }

      // STRICT HTTPS UPGRADE
      if (finalDownloadUrl.includes(':443') && finalDownloadUrl.startsWith('http://')) {
        finalDownloadUrl = finalDownloadUrl.replace(/^http:\/\//i, 'https://');
      } else if (finalDownloadUrl.includes('sunilshahid.com') && finalDownloadUrl.startsWith('http://')) {
        finalDownloadUrl = finalDownloadUrl.replace(/^http:\/\//i, 'https://');
      }

      console.log(`JMAP Download Proxy: ${finalDownloadUrl}`);

      const response = await fetch(finalDownloadUrl, {
        method: 'GET',
        headers: {
          'Authorization': `Basic ${auth}`
        }
      });

      if (!response.ok) {
        logDev(`JMAP Download failed - URL: ${finalDownloadUrl}, Status: ${response.status}`);
        const text = await response.text();
        return res.status(response.status).send(text);
      }

      const contentType = response.headers.get('content-type');
      if (contentType) res.setHeader('content-type', contentType);
      
      const buffer = await response.arrayBuffer();
      res.send(Buffer.from(buffer));
    } catch (e: any) {
      logDev("JMAP Download Error:", e.message);
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

  const httpServer = app.listen(PORT, "0.0.0.0", () => {
    console.log(`Server running on http://localhost:${PORT}`);
  });

  // Setup WebSocket Proxy
  const wss = new WebSocketServer({ noServer: true });

  httpServer.on('upgrade', (request, socket, head) => {
    const urlStr = request.url || '';
    const pathname = urlStr.split('?')[0];
    if (pathname === '/api/ws-proxy') {
      wss.handleUpgrade(request, socket, head, (ws) => {
        wss.emit('connection', ws, request);
      });
    }
  });

  wss.on('connection', (ws, request) => {
    let upstreamWs: NodeWebSocket | null = null;
    
    ws.on('message', (message) => {
      try {
        const data = JSON.parse(message.toString());
        if (data.type === 'ping') {
          ws.send(JSON.stringify({ type: 'pong' }));
          
          // Optionally send a ping frame upstream to keep the backend alive
          if (upstreamWs && upstreamWs.readyState === upstreamWs.OPEN) {
            upstreamWs.ping();
          }
          return;
        }

        if (data.type === 'init') {
          let { websocketUrl, username, password } = data;
          
          if (!websocketUrl || !username || !password) {
            ws.send(JSON.stringify({ type: 'error', message: 'Missing auth or URL' }));
            return;
          }

          // Force wss if it's over https
          if (websocketUrl.includes(':443') && websocketUrl.startsWith('ws://')) {
            websocketUrl = websocketUrl.replace(/^ws:\/\//i, 'wss://');
          } else if (websocketUrl.includes('sunilshahid.com') && websocketUrl.startsWith('ws://')) {
            websocketUrl = websocketUrl.replace(/^ws:\/\//i, 'wss://');
          }

          const auth = Buffer.from(`${username}:${password}`).toString('base64');
          
          upstreamWs = new NodeWebSocket(websocketUrl, "jmap", {
            headers: {
              'Authorization': `Basic ${auth}`
            }
          });

          upstreamWs.on('open', () => {
             logDev(`Upstream WebSocket connected to ${websocketUrl}`);
             ws.send(JSON.stringify({ type: 'init_success' }));
          });

          upstreamWs.on('message', (upstreamMessage) => {
             if (ws.readyState === ws.OPEN) {
                ws.send(upstreamMessage.toString());
             }
          });

          upstreamWs.on('close', () => {
             if (ws.readyState === ws.OPEN) {
                ws.close();
             }
          });

          upstreamWs.on('error', (err) => {
             logDev('Upstream WS Error:', err);
             if (ws.readyState === ws.OPEN) {
                ws.send(JSON.stringify({ type: 'error', message: err.message }));
             }
          });
        } else {
          // If not init or ping, forward the raw message to upstream
          if (upstreamWs && upstreamWs.readyState === upstreamWs.OPEN) {
            upstreamWs.send(message.toString());
          }
        }
      } catch (e) {
        logDev("WS message error", e);
      }
    });

    ws.on('close', () => {
      if (upstreamWs) {
        upstreamWs.close();
      }
    });
  });
}

startServer();
