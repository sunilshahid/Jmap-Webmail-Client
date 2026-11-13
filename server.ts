import express from "express";
import cors from "cors";
import { createServer as createViteServer } from "vite";
import path from "path";
import crypto from "crypto";
import { spawn } from "child_process";
import { WebSocketServer, WebSocket as NodeWebSocket } from "ws";
import { setGlobalDispatcher, Agent } from "undici";

// Configure TLS dispatcher: strict certificate verification by default; opt-in only for local dev
if (process.env.ALLOW_INSECURE_TLS === "true") {
  console.warn("[Security Warning] Insecure TLS verification enabled via ALLOW_INSECURE_TLS=true.");
  setGlobalDispatcher(new Agent({
    connect: {
      rejectUnauthorized: false
    }
  }));
}

/**
 * Validates whether a target URL is safe for server-side proxying (SSRF protection).
 */
function isSafeTargetUrl(urlString: string): boolean {
  try {
    const parsed = new URL(urlString);
    if (!["http:", "https:", "ws:", "wss:"].includes(parsed.protocol)) {
      return false;
    }
    const hostname = parsed.hostname.toLowerCase();
    
    if (process.env.ALLOW_PRIVATE_NETWORK === "true") {
      return true;
    }

    // Disallow loopback, link-local, and cloud metadata
    if (
      hostname === "localhost" ||
      hostname === "127.0.0.1" ||
      hostname === "::1" ||
      hostname === "0.0.0.0" ||
      hostname.startsWith("127.") ||
      hostname === "169.254.169.254" ||
      hostname.startsWith("169.254.")
    ) {
      return false;
    }

    return true;
  } catch {
    return false;
  }
}

async function startServer() {
  let isDeveloperMode = process.env.NODE_ENV === "development";
  function logDev(...args: any[]) {
    if (isDeveloperMode) {
      console.log('[DevMode]', ...args);
    }
  }

  const app = express();
  const PORT = parseInt(process.env.PORT || "3000", 10);

  // Configure CORS
  const allowedOrigins = process.env.ALLOWED_ORIGINS
    ? process.env.ALLOWED_ORIGINS.split(",").map(o => o.trim())
    : null;

  app.use(cors({
    origin: (origin, callback) => {
      if (!origin) return callback(null, true);
      if (!allowedOrigins) return callback(null, true);
      if (allowedOrigins.includes(origin)) return callback(null, true);
      callback(new Error("CORS origin not allowed by server policy"));
    },
    credentials: true
  }));

  app.use(express.json({ limit: '20mb' }));

  // In-Memory Secure Message Store with capacity cap
  interface SecureMessage {
    encryptedPayload: string;
    iv: string;
    salt: string;
    expiresAt: number;
    viewOnce: boolean;
  }
  const MAX_STORE_ITEMS = 1000;
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

  // Scheduled Email Store
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
          let finalApiUrl = job.apiUrl;
          if (finalApiUrl && finalApiUrl.startsWith('/')) {
            try {
              const urlObj = new URL(job.serverUrl);
              finalApiUrl = `${urlObj.protocol}//${urlObj.host}${finalApiUrl}`;
            } catch {
              let base = job.serverUrl.replace(/\/$/, '');
              if (!base.startsWith('http')) base = `https://${base}`;
              finalApiUrl = `${base}/${finalApiUrl.replace(/^\//, '')}`;
            }
          } else if (finalApiUrl && !finalApiUrl.startsWith('http')) {
            let base = job.serverUrl.replace(/\/$/, '');
            if (!base.startsWith('http')) base = `https://${base}`;
            finalApiUrl = `${base}/${finalApiUrl.replace(/^\//, '')}`;
          }

          if (finalApiUrl && finalApiUrl.includes(':443') && finalApiUrl.startsWith('http://')) {
            finalApiUrl = finalApiUrl.replace(/^http:\/\//i, 'https://');
          }

          if (!isSafeTargetUrl(finalApiUrl)) {
            logDev(`[Security Warning] Blocked scheduled send to restricted target: ${finalApiUrl}`);
            continue;
          }

          const response = await fetch(finalApiUrl, {
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
                  update: { [job.draftId]: { "keywords/$draft": null, "keywords/$seen": true, mailboxIds: { [job.sentMailboxId]: true } } } 
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
    if (scheduledJobs.size >= MAX_STORE_ITEMS) {
      return res.status(503).json({ error: "Scheduled jobs capacity reached. Please try again later." });
    }

    const { executeAt, draftId, identityId, accountId, apiUrl, serverUrl, username, password, token, sentMailboxId } = req.body;
    if (!draftId || !accountId || !apiUrl || !serverUrl) {
      return res.status(400).json({ error: "Missing required scheduling parameters" });
    }

    const jobId = crypto.randomUUID();
    const authHeader = token ? `Bearer ${token}` : `Basic ${Buffer.from(`${username}:${password}`).toString('base64')}`;
    
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

  // Middleware to authenticate administrative calls
  const requireAdminAuth = (req: express.Request, res: express.Response, next: express.NextFunction) => {
    const adminKey = process.env.ADMIN_API_KEY;
    if (!adminKey) {
      return res.status(403).json({ error: "Admin operations are disabled. Set ADMIN_API_KEY in environment." });
    }
    const authHeader = req.headers.authorization;
    if (!authHeader || authHeader !== `Bearer ${adminKey}`) {
      return res.status(401).json({ error: "Unauthorized admin request" });
    }
    next();
  };

  app.get("/api/keys", requireAdminAuth, (req, res) => {
    res.json(Array.from(apiKeys.values()).map(k => ({ id: k.id, name: k.name, createdAt: k.createdAt })));
  });

  app.post("/api/keys", requireAdminAuth, (req, res) => {
    if (apiKeys.size >= MAX_STORE_ITEMS) {
      return res.status(503).json({ error: "Maximum API keys limit reached" });
    }
    const { name } = req.body;
    const id = crypto.randomUUID();
    const key = "sk_" + crypto.randomBytes(24).toString('hex');
    apiKeys.set(id, { id, key, name: name || "Default Key", createdAt: Date.now() });
    res.json({ id, key, name, createdAt: Date.now() });
  });

  app.delete("/api/keys/:id", requireAdminAuth, (req, res) => {
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
    
    if (secureStore.size >= MAX_STORE_ITEMS) {
      return res.status(503).json({ error: "Secure message store capacity reached" });
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
    if (secureStore.size >= MAX_STORE_ITEMS) {
      return res.status(503).json({ error: "Secure message store capacity reached" });
    }

    const { encryptedPayload, iv, salt, expiration, viewOnce } = req.body;
    if (!encryptedPayload || !iv || !salt) {
      return res.status(400).json({ error: "Missing required encryption fields" });
    }

    const id = crypto.randomUUID();
    let ttl = 24 * 60 * 60 * 1000; // Default 1 day
    if (expiration === '5min') ttl = 5 * 60 * 1000;
    else if (expiration === '1hour') ttl = 60 * 60 * 1000;
    else if (expiration === '1week') ttl = 7 * 24 * 60 * 60 * 1000;
    else if (expiration === 'burn') ttl = 30 * 24 * 60 * 60 * 1000;
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

    // Only burn after recipient has fetched once if viewOnce is true
    if (msg.viewOnce) {
      logDev(`[Secure Retrieve] Message ID=${id} marked viewOnce. Shredding payload.`);
      secureStore.delete(id);
    }

    res.json({
      encryptedPayload: msg.encryptedPayload,
      iv: msg.iv,
      salt: msg.salt
    });
  });

  // Admin APIs (Protected)
  app.get("/api/admin/developer-mode", (req, res) => {
    res.json({ isDeveloperMode });
  });

  app.post("/api/admin/developer-mode", requireAdminAuth, (req, res) => {
    isDeveloperMode = req.body.isDeveloperMode === true;
    res.json({ isDeveloperMode });
  });

  app.get("/api/admin/update", requireAdminAuth, (req, res) => {
    if (process.env.ENABLE_ADMIN_UPDATE !== "true") {
      return res.status(403).json({ error: "Remote update feature is disabled by policy." });
    }

    res.writeHead(200, {
      'Content-Type': 'text/event-stream',
      'Cache-Control': 'no-cache',
      'Connection': 'keep-alive'
    });

    const sendEvent = (msg: string) => res.write(`data: ${JSON.stringify({ message: msg })}\n\n`);
    sendEvent("Starting verified Smart Update...");

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
        sendEvent("Fetching updates from main branch...");
        let resGit = await runCommand("git", ["pull", "origin", "main"]);
        
        if (resGit.code !== 0) {
           sendEvent(`Git pull non-zero exit: ${resGit.stderr.substring(0, 100)}... Skipping smart check.`);
        } else {
           sendEvent("Git pull successful.");
           let diff = await runCommand("git", ["diff", "HEAD@{1}", "HEAD", "--name-only"]);
           
           if (diff.stdout.includes("package.json")) {
              sendEvent("Updating dependencies (npm ci)...");
              await runCommand("npm", ["ci"]);
           }
           
           if (diff.stdout.includes("src/")) {
              sendEvent("Rebuilding frontend...");
              await runCommand("npm", ["run", "build"]);
           }
        }
        
        sendEvent("Restarting server in 2 seconds...");
        setTimeout(() => {
          process.exit(0);
        }, 2000);
      } catch (err: any) {
        sendEvent(`Error during update: ${err.message}`);
        res.write(`data: ${JSON.stringify({ done: true })}\n\n`);
        res.end();
      }
    })();
  });

  // Helper to construct authorization header
  function getAuthHeader(username?: string, password?: string, token?: string): string {
    if (token) return `Bearer ${token}`;
    if (username && password) {
      return `Basic ${Buffer.from(`${username}:${password}`).toString('base64')}`;
    }
    return '';
  }

  // JMAP Authentication / Session Discovery
  app.post("/api/jmap/session", async (req, res) => {
    const { serverUrl, username, password, token } = req.body;
    try {
      let cleanUrl = (serverUrl || "").trim().replace(/\/$/, '');
      if (!cleanUrl.startsWith('http')) {
        cleanUrl = `https://${cleanUrl}`;
      }
      
      const sessionUrl = `${cleanUrl}/.well-known/jmap`;
      if (!isSafeTargetUrl(sessionUrl)) {
        return res.status(400).json({ error: "Invalid or restricted server URL" });
      }

      logDev(`JMAP Session Discovery: ${sessionUrl}`);
      const authHeader = getAuthHeader(username, password, token);
      
      const response = await fetch(sessionUrl, {
        method: 'GET',
        headers: { 
          ...(authHeader ? { Authorization: authHeader } : {}),
          'Accept': 'application/json'
        }
      });
      
      if (!response.ok) {
        if (response.status === 401 || response.status === 403) {
          return res.status(response.status).json({ error: "Authentication failed. Please verify credentials." });
        }
        const errText = await response.text();
        return res.status(response.status).json({ error: `Server returned status ${response.status}: ${errText.substring(0, 300)}` });
      }
      
      const data = await response.json();
      res.json(data);
    } catch (e: any) {
      res.status(502).json({ error: `Cannot contact server at ${serverUrl}: ${e.message}` });
    }
  });

  // iCal fetch proxy (SSRF protected)
  app.get("/api/ical", async (req, res) => {
    try {
      const url = req.query.url as string;
      if (!url) {
        return res.status(400).json({ error: "Missing url parameter" });
      }
      if (!isSafeTargetUrl(url)) {
        return res.status(400).json({ error: "Invalid or restricted iCal URL target" });
      }
      
      const response = await fetch(url, { headers: { 'User-Agent': 'Mozilla/5.0 webmail' }});
      if (!response.ok) {
        return res.status(response.status).json({ error: `Failed to fetch iCal: ${response.statusText}` });
      }
      const text = await response.text();
      res.set('Content-Type', 'text/calendar');
      res.send(text);
    } catch (err: any) {
      res.status(500).json({ error: err.message });
    }
  });

  // JMAP api proxy (SSRF protected)
  app.post("/api/jmap/api", async (req, res) => {
    const { serverUrl, apiUrl, username, password, token, payload } = req.body;

    try {
      const authHeader = getAuthHeader(username, password, token);
      
      let baseServerUrl = (serverUrl || "").trim();
      if (!baseServerUrl.startsWith('http')) {
        baseServerUrl = `https://${baseServerUrl}`;
      }

      let finalApiUrl = apiUrl;
      if (apiUrl && apiUrl.startsWith('/')) {
        try {
          const urlObj = new URL(baseServerUrl);
          finalApiUrl = `${urlObj.protocol}//${urlObj.host}${apiUrl}`;
        } catch {
          finalApiUrl = `${baseServerUrl.replace(/\/$/, '')}/${apiUrl.replace(/^\//, '')}`;
        }
      } else if (apiUrl && !apiUrl.startsWith('http')) {
        finalApiUrl = `${baseServerUrl.replace(/\/$/, '')}/${apiUrl.replace(/^\//, '')}`;
      }

      if (finalApiUrl && finalApiUrl.includes(':443') && finalApiUrl.startsWith('http://')) {
        finalApiUrl = finalApiUrl.replace(/^http:\/\//i, 'https://');
      }

      if (!isSafeTargetUrl(finalApiUrl)) {
        return res.status(400).json({ error: "Invalid or restricted JMAP target URL" });
      }

      const response = await fetch(finalApiUrl, {
        method: 'POST',
        headers: {
          ...(authHeader ? { 'Authorization': authHeader } : {}),
          'Content-Type': 'application/json',
          'Accept': 'application/json'
        },
        body: JSON.stringify(payload)
      });
      
      if (!response.ok) {
        const text = await response.text();
        return res.status(response.status).send(text);
      }
      
      const data = await response.json();
      res.json(data);
    } catch (e: any) {
      res.status(502).json({ error: e.message });
    }
  });

  // JMAP Upload Proxy (SSRF protected)
  app.post("/api/jmap/upload", express.raw({ type: '*/*', limit: '50mb' }), async (req, res) => {
    const serverUrl = req.headers['x-jmap-server-url'] as string;
    const uploadUrl = req.headers['x-jmap-upload-url'] as string;
    const username = req.headers['x-jmap-username'] as string;
    const password = req.headers['x-jmap-password'] as string;
    const token = req.headers['x-jmap-token'] as string;
    const contentType = req.headers['content-type'] || 'application/octet-stream';

    if (!serverUrl || !uploadUrl || (!token && (!username || !password))) {
      return res.status(400).json({ error: "Missing JMAP proxy headers or credentials" });
    }

    try {
      const authHeader = getAuthHeader(username, password, token);
      let baseServerUrl = serverUrl.trim();
      if (!baseServerUrl.startsWith('http')) {
        baseServerUrl = `https://${baseServerUrl}`;
      }

      let finalUploadUrl = uploadUrl;
      if (uploadUrl.startsWith('/')) {
        try {
          const urlObj = new URL(baseServerUrl);
          finalUploadUrl = `${urlObj.protocol}//${urlObj.host}${uploadUrl}`;
        } catch {
          finalUploadUrl = `${baseServerUrl.replace(/\/$/, '')}/${uploadUrl.replace(/^\//, '')}`;
        }
      } else if (!uploadUrl.startsWith('http')) {
        finalUploadUrl = `${baseServerUrl.replace(/\/$/, '')}/${uploadUrl.replace(/^\//, '')}`;
      }

      if (finalUploadUrl.includes(':443') && finalUploadUrl.startsWith('http://')) {
        finalUploadUrl = finalUploadUrl.replace(/^http:\/\//i, 'https://');
      }

      if (!isSafeTargetUrl(finalUploadUrl)) {
        return res.status(400).json({ error: "Invalid or restricted upload target URL" });
      }

      const response = await fetch(finalUploadUrl, {
        method: 'POST',
        headers: {
          ...(authHeader ? { 'Authorization': authHeader } : {}),
          'Content-Type': contentType as string
        },
        body: req.body
      });

      if (!response.ok) {
        const errText = await response.text();
        return res.status(response.status).send(errText);
      }

      const data = await response.json();
      res.json(data);
    } catch (e: any) {
      res.status(502).json({ error: e.message });
    }
  });

  // JMAP Download Proxy (SSRF protected)
  app.get("/api/jmap/download", async (req, res) => {
    const serverUrl = req.headers['x-jmap-server-url'] as string;
    const downloadUrl = req.headers['x-jmap-download-url'] as string;
    const username = req.headers['x-jmap-username'] as string;
    const password = req.headers['x-jmap-password'] as string;
    const token = req.headers['x-jmap-token'] as string;

    if (!serverUrl || !downloadUrl || (!token && (!username || !password))) {
      return res.status(400).json({ error: "Missing JMAP proxy headers or credentials" });
    }

    try {
      const authHeader = getAuthHeader(username, password, token);
      let baseServerUrl = serverUrl.trim();
      if (!baseServerUrl.startsWith('http')) {
        baseServerUrl = `https://${baseServerUrl}`;
      }

      let finalDownloadUrl = downloadUrl;
      if (downloadUrl.startsWith('/')) {
        try {
          const urlObj = new URL(baseServerUrl);
          finalDownloadUrl = `${urlObj.protocol}//${urlObj.host}${downloadUrl}`;
        } catch {
          finalDownloadUrl = `${baseServerUrl.replace(/\/$/, '')}/${downloadUrl.replace(/^\//, '')}`;
        }
      } else if (!downloadUrl.startsWith('http')) {
        finalDownloadUrl = `${baseServerUrl.replace(/\/$/, '')}/${downloadUrl.replace(/^\//, '')}`;
      }

      if (finalDownloadUrl.includes(':443') && finalDownloadUrl.startsWith('http://')) {
        finalDownloadUrl = finalDownloadUrl.replace(/^http:\/\//i, 'https://');
      }

      if (!isSafeTargetUrl(finalDownloadUrl)) {
        return res.status(400).json({ error: "Invalid or restricted download target URL" });
      }

      const response = await fetch(finalDownloadUrl, {
        method: 'GET',
        headers: {
          ...(authHeader ? { 'Authorization': authHeader } : {})
        }
      });

      if (!response.ok) {
        const text = await response.text();
        return res.status(response.status).send(text);
      }

      const contentType = response.headers.get('content-type');
      if (contentType) res.setHeader('content-type', contentType);
      
      const buffer = await response.arrayBuffer();
      res.send(Buffer.from(buffer));
    } catch (e: any) {
      res.status(502).json({ error: e.message });
    }
  });

  // Vite middleware for development vs static build for production
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

  wss.on('connection', (ws) => {
    let upstreamWs: NodeWebSocket | null = null;
    
    ws.on('message', (message) => {
      try {
        const data = JSON.parse(message.toString());
        if (data.type === 'ping') {
          ws.send(JSON.stringify({ type: 'pong' }));
          if (upstreamWs && upstreamWs.readyState === upstreamWs.OPEN) {
            upstreamWs.ping();
          }
          return;
        }

        if (data.type === 'init') {
          let { websocketUrl, username, password, token } = data;
          
          if (!websocketUrl || (!token && (!username || !password))) {
            ws.send(JSON.stringify({ type: 'error', message: 'Missing auth or URL' }));
            return;
          }

          if (websocketUrl.includes(':443') && websocketUrl.startsWith('ws://')) {
            websocketUrl = websocketUrl.replace(/^ws:\/\//i, 'wss://');
          }

          if (!isSafeTargetUrl(websocketUrl)) {
            ws.send(JSON.stringify({ type: 'error', message: 'Restricted WebSocket destination' }));
            return;
          }

          const authHeader = getAuthHeader(username, password, token);
          
          upstreamWs = new NodeWebSocket(websocketUrl, "jmap", {
            headers: {
              ...(authHeader ? { 'Authorization': authHeader } : {})
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
