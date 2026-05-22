import { Account, Mailbox, Email, Identity, Contact, Event, Calendar } from './types';

export class JmapClient {
  private account: Account;
  public ws: WebSocket | null = null;

  constructor(account: Account) {
    this.account = account;
  }

  /**
   * Make a JMAP API call
   * @param methodCalls Array of JMAP method calls
   * @param customCapabilities Optional array of capabilities to use for this call
   * @returns The JMAP response object
   */
  async call(methodCalls: any[], customCapabilities?: string[]): Promise<any> {
    if (!Array.isArray(methodCalls)) {
      console.error("jmapCall: methodCalls must be an array", methodCalls);
      throw new Error("methodCalls must be an array");
    }

    const defaultCapabilities = [
      "urn:ietf:params:jmap:core",
      "urn:ietf:params:jmap:mail",
      "urn:ietf:params:jmap:submission",
      "urn:ietf:params:jmap:vacationresponse",
      "urn:ietf:params:jmap:contacts",
      "urn:ietf:params:jmap:calendars",
      "urn:ietf:params:jmap:principals"
    ];

    let usingCaps = customCapabilities || (this.account.capabilities.length > 0 ? this.account.capabilities : defaultCapabilities);
    
    // Ensure required capabilities are always present
    const requiredCaps = [
      "urn:ietf:params:jmap:core",
      "urn:ietf:params:jmap:mail",
      "urn:ietf:params:jmap:submission",
      "urn:ietf:params:jmap:contacts",
      "urn:ietf:params:jmap:calendars"
    ];
    usingCaps = Array.from(new Set([...usingCaps, ...requiredCaps]));

    const payload = {
      using: usingCaps,
      methodCalls: methodCalls
    };

    const isDevMode = typeof window !== 'undefined' && localStorage.getItem("webmail_developer_mode") === "true";
    if (isDevMode) {
      console.log("JMAP REQUEST: ", {
        serverUrl: this.account.serverUrl,
        username: this.account.username,
        payload
      });
    }

    let res: Response;
    try {
      res = await fetch('/api/jmap/api', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          serverUrl: this.account.serverUrl,
          apiUrl: this.account.apiUrl,
          username: this.account.username,
          password: this.account.password,
          token: this.account.token,
          payload
        })
      });
    } catch (e: any) {
      console.error("JMAP Network Error:", e);
      throw new Error(`Network failure: ${e.message}. Please check your internet connection or server availability.`);
    }

    if (!res.ok) {
      const errText = await res.text();
      let errorMessage = "API call failed";
      try {
        const errData = JSON.parse(errText);
        errorMessage = errData.detail || errData.error || errorMessage;
      } catch (e) {
        errorMessage = errText || errorMessage;
      }
      throw new Error(errorMessage);
    }
    
    const data = await res.json();
    if (isDevMode) {
      console.log("JMAP RESPONSE: ", data);
    }
    return data;
  }

  request(methodCalls: any[], customCapabilities?: string[]): Promise<any> {
    return this.call(methodCalls, customCapabilities);
  }

  /**
   * Create a new JMAP session
   */
  static async createSession(serverUrl: string, username: string, password?: string, token?: string): Promise<Account> {
    const res = await fetch('/api/jmap/session', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ 
        serverUrl, 
        username, 
        password,
        token,
        capabilities: [
          "urn:ietf:params:jmap:core",
          "urn:ietf:params:jmap:mail",
          "urn:ietf:params:jmap:submission",
          "urn:ietf:params:jmap:contacts",
          "urn:ietf:params:jmap:calendars",
          "urn:ietf:params:jmap:principals",
          "urn:ietf:params:jmap:websocket",
          "urn:ietf:params:jmap:sieve"
        ]
      })
    });
    
    if (!res.ok) {
      throw new Error("Authentication failed. Check your credentials and server URL.");
    }
    
    const session = await res.json();

    const apiUrl = session.apiUrl;
    const primaryAccounts = session.primaryAccounts || {};
    const accountsInfo = session.accounts || {};
    
    // We will use standard JMAP capability routing 
    const accountId = primaryAccounts["urn:ietf:params:jmap:mail"] || Object.keys(accountsInfo)[0] || "p";
    const capabilities = Object.keys(session.capabilities || {});
    const uploadUrl = session.uploadUrl;
    const downloadUrl = session.downloadUrl;
    const websocketUrl = session.capabilities?.["urn:ietf:params:jmap:websocket"]?.url;
    
    return { serverUrl, username, password, token, apiUrl, accountId, uploadUrl, downloadUrl, websocketUrl, primaryAccounts, capabilities };
  }

  async uploadBlob(file: File, accountId: string): Promise<{ accountId: string, blobId: string, type: string, size: number }> {
    if (!this.account.uploadUrl && this.account.password) {
      try {
        console.warn("Upload URL missing, attempting session refresh...");
        const refreshed = await JmapClient.createSession(this.account.serverUrl, this.account.username, this.account.password);
        this.account.uploadUrl = refreshed.uploadUrl;
        this.account.downloadUrl = refreshed.downloadUrl;
        this.account.websocketUrl = refreshed.websocketUrl;
        // Also update other potential missing fields
        this.account.apiUrl = refreshed.apiUrl;
        this.account.accountId = refreshed.accountId;
      } catch (e) {
        console.error("Failed to auto-refresh session for upload", e);
      }
    }

    if (!this.account.uploadUrl) throw new Error("Upload URL not available for this session. Please log out and log in again.");
    
    const uploadUrl = this.account.uploadUrl.replace('{accountId}', accountId);
    
    console.log(`Uploading via proxy to JMAP server...`);
    
    const response = await fetch('/api/jmap/upload', {
      method: 'POST',
      headers: {
        'Content-Type': file.type || 'application/octet-stream',
        'X-JMAP-Server-Url': this.account.serverUrl,
        'X-JMAP-Upload-Url': uploadUrl,
        'X-JMAP-Username': this.account.username,
        'X-JMAP-Password': this.account.password || '',
      },
      body: file
    });

    if (!response.ok) {
      const errText = await response.text();
      throw new Error(`Upload failed (${response.status}): ${errText || response.statusText}`);
    }

    return await response.json();
  }

  async getAttachmentBlob(blobId: string, name: string, type: string): Promise<Blob> {
    if (!this.account.downloadUrl && this.account.password) {
        try {
          const refreshed = await JmapClient.createSession(this.account.serverUrl, this.account.username, this.account.password);
          this.account.downloadUrl = refreshed.downloadUrl;
          this.account.uploadUrl = refreshed.uploadUrl;
          this.account.websocketUrl = refreshed.websocketUrl;
        } catch (e) {
          console.error("Failed to auto-refresh session for download", e);
        }
    }

    if (!this.account.downloadUrl) throw new Error("Download URL not available");

    const downloadUrl = this.account.downloadUrl
      .replace('{accountId}', this.account.accountId)
      .replace('{blobId}', blobId)
      .replace('{name}', encodeURIComponent(name))
      .replace('{type}', encodeURIComponent(type));

    // Use proxy to avoid CORS
    const response = await fetch('/api/jmap/download', {
      method: 'GET',
      headers: {
        'X-JMAP-Server-Url': this.account.serverUrl,
        'X-JMAP-Download-Url': downloadUrl,
        'X-JMAP-Username': this.account.username,
        'X-JMAP-Password': this.account.password || '',
      }
    });

    if (!response.ok) {
      throw new Error(`Failed to download attachment: ${response.statusText}`);
    }

    return await response.blob();
  }

  connectWebSocket(onStateChange: (changed: any) => void): boolean {
    if (!this.account.websocketUrl) {
      console.warn("Server does not support or provide a WebSocket URL in session.");
      return false;
    }

    if (this.ws) {
      try { this.ws.close(); } catch(e){}
    }

    let isIntentionalClose = false;
    let reconnectTimer: any = null;
    let pingTimer: any = null;

    const connect = () => {
      try {
        const proto = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
        const proxyUrl = `${proto}//${window.location.host}/api/ws-proxy`;
        console.log(`Connecting to proxy WebSocket at ${proxyUrl}...`);
        
        this.ws = new window.WebSocket(proxyUrl);

        this.ws.onopen = () => {
          console.log("WebSocket proxy connected. Sending init...");
          if (this.ws) {
            this.ws.send(JSON.stringify({
              type: 'init',
              websocketUrl: this.account.websocketUrl,
              username: this.account.username,
              password: this.account.password
            }));
          }
          // Send a ping every 30 seconds to keep the connection alive
          pingTimer = setInterval(() => {
            if (this.ws && this.ws.readyState === window.WebSocket.OPEN) {
              this.ws.send(JSON.stringify({ type: 'ping' }));
            }
          }, 30000);
        };

        this.ws.onmessage = (event) => {
          try {
            const payload = JSON.parse(event.data);
            
            if (payload.type === 'init_success') {
               console.log("Backend successfully connected to JMAP WebSocket.");
               
               // Inform JMAP Server to start sending StateChanges
               if (this.ws && this.ws.readyState === window.WebSocket.OPEN) {
                 this.ws.send(JSON.stringify({ 
                   "@type": "WebSocketPushEnable", 
                   "dataTypes": null 
                 }));
               }
               return;
            }
            if (payload.type === 'error') {
               console.error("Backend WebSocket error:", payload.message);
               return;
            }
            if (payload.type === 'pong') {
               return;
            }
            
            if (payload["@type"] === "StateChange") {
              const changes = payload.changed;
              const accountId = this.account.accountId || "p";
              const currentAccountChanges = changes[accountId] || 
                                            changes[this.account.primaryAccounts?.["urn:ietf:params:jmap:mail"] || "p"] ||
                                            Object.values(changes)[0];
              if (currentAccountChanges) {
                console.log("WebSocket StateChange received!", currentAccountChanges);
                onStateChange(currentAccountChanges);
              }
            }
          } catch (err) {
            console.error("Error parsing WebSocket message:", err);
          }
        };

        this.ws.onerror = (err) => {
          console.error("Proxy WebSocket Error:", err);
        };

        this.ws.onclose = () => {
          console.log("Proxy WebSocket Closed.");
          clearInterval(pingTimer);
          this.ws = null;
          
          // Reconnect if it wasn't intentional
          if (!isIntentionalClose) {
            console.log("Reconnecting in 5 seconds...");
            reconnectTimer = setTimeout(connect, 5000);
          }
        };
      } catch (e) {
        console.error("Failed to initialize WebSocket proxy:", e);
        if (!isIntentionalClose) {
          reconnectTimer = setTimeout(connect, 5000);
        }
      }
    };

    connect();

    // Override the instance's disconnect logic so we can set the flag
    this.disconnectWebSocket = () => {
      isIntentionalClose = true;
      clearTimeout(reconnectTimer);
      clearInterval(pingTimer);
      if (this.ws) {
        try { this.ws.close(); } catch(e){}
        this.ws = null;
      }
    };

    return true;
  }

  disconnectWebSocket() {
    if (this.ws) {
      this.ws.close();
      this.ws = null;
    }
  }

  async provisionDefaultMailboxes(): Promise<void> {
    const defaultRoles = [
      { name: "Inbox", role: "inbox" },
      { name: "Drafts", role: "drafts" },
      { name: "Sent Items", role: "sent" },
      { name: "Trash", role: "trash" },
      { name: "Spam", role: "junk" },
      { name: "Templates", role: "templates" },
      { name: "Archive", role: "archive" },
      { name: "Reports", role: null },
    ];
    
    const createData: Record<string, any> = {};
    defaultRoles.forEach((box, i) => {
      createData[`box${i}`] = {
        name: box.name,
        role: box.role
      };
    });

    await this.call([
      ["Mailbox/set", { accountId: this.account.accountId, create: createData }, "0"]
    ]);
  }

  async getMailboxes(): Promise<Mailbox[]> {
    const data = await this.call([
      ["Mailbox/get", { accountId: this.account.accountId }, "0"]
    ]);
    const methodResponse = data?.methodResponses?.[0];
    if (methodResponse?.[0] === "error") {
      throw new Error(`JMAP Mailbox Error: ${methodResponse[1]?.type || 'Unknown'}`);
    }
    const list = methodResponse?.[1]?.list;
    if (!Array.isArray(list)) return [];
    return list.map((m: any) => {
      let icon = 'Folder';
      if (m.role === 'inbox') icon = 'Inbox';
      else if (m.role === 'sent') icon = 'Send';
      else if (m.role === 'drafts') icon = 'FileEdit';
      else if (m.role === 'trash') icon = 'Trash2';
      else if (m.role === 'archive') icon = 'Archive';
      else if (m.role === 'junk' || m.name === 'Junk Mail') icon = 'ShieldAlert';
      else if (m.name === 'Promotions') icon = 'Tag';
      else if (m.name === 'Social') icon = 'Users';
      else if (m.name === 'Updates') icon = 'Bell';
      else if (m.name === 'Templates') icon = 'LayoutTemplate';
      else if (m.name.toLowerCase().includes('report')) icon = 'BarChart3';

      return {
        id: m.id,
        name: m.role === 'junk' || m.name === 'Junk Mail' ? 'Spam' : m.name,
        unread: (m.role === 'sent' || m.role === 'trash') ? 0 : (m.unreadEmails || 0),
        totalEmails: m.totalEmails || 0,
        role: m.role,
        icon: icon
      };
    });
  }

  async getEmails(mailboxId: string | null, limit: number = 50, position: number = 0, keyword?: string, collapseThreads: boolean = true): Promise<Email[]> {
    const filterParams: any = {};
    if (mailboxId) {
      filterParams.inMailbox = mailboxId;
    }
    if (keyword) {
      filterParams.hasKeyword = keyword;
    }

    const data = await this.call([
      ["Email/query", {
        accountId: this.account.accountId,
        filter: Object.keys(filterParams).length > 0 ? filterParams : undefined,
        sort: [{ property: "receivedAt", isAscending: false }],
        collapseThreads: collapseThreads,
        position: position,
        limit: limit
      }, "0"],
      ["Email/get", {
        accountId: this.account.accountId,
        "#ids": {
          resultOf: "0",
          name: "Email/query",
          path: "/ids"
        },
        properties: ["id", "subject", "from", "to", "preview", "bodyValues", "htmlBody", "textBody", "receivedAt", "keywords", "headers", "header:List-Unsubscribe:asURLs", "header:List-Unsubscribe:asText", "attachments"],
        fetchTextBodyValues: true,
        fetchHTMLBodyValues: true
      }, "1"]
    ]);

    // Check if query or get failed directly
    if (data?.methodResponses?.[0]?.[0] === "error") {
       throw new Error(`JMAP Email/query Error: ${data.methodResponses[0][1]?.type || 'Unknown'}`);
    }
    if (data?.methodResponses?.[1]?.[0] === "error") {
       throw new Error(`JMAP Email/get Error: ${data.methodResponses[1][1]?.type || 'Unknown'}`);
    }

    const list = data?.methodResponses?.[1]?.[1]?.list;
    if (!Array.isArray(list)) return [];
    return list.map((e: any) => {
      let body = "";
      if (e.bodyValues) {
        const htmlPart = e.htmlBody?.[0];
        const textPart = e.textBody?.[0];
        
        if (htmlPart && e.bodyValues[htmlPart.partId]) {
          body = e.bodyValues[htmlPart.partId].value;
        } else if (textPart && e.bodyValues[textPart.partId]) {
          body = e.bodyValues[textPart.partId].value;
        }
      }

      let unsubscribeUrl: string | undefined = undefined;
      
      // Try JMAP parsed URLs first
      if (e["header:List-Unsubscribe:asURLs"] && Array.isArray(e["header:List-Unsubscribe:asURLs"]) && e["header:List-Unsubscribe:asURLs"].length > 0) {
         unsubscribeUrl = e["header:List-Unsubscribe:asURLs"][0];
      } 
      // Try JMAP raw text
      else if (e["header:List-Unsubscribe:asText"]) {
         const match = String(e["header:List-Unsubscribe:asText"]).match(/<x?(https?:\/\/[^>]+)>/i);
         if (match && match[1]) {
           unsubscribeUrl = match[1];
         }
      }
      // Fallback to headers array iteration (if server provided it)
      if (!unsubscribeUrl && Array.isArray(e.headers)) {
        const listUnsubscribeHeader = e.headers.find((h: any) => h.name.toLowerCase() === 'list-unsubscribe');
        if (listUnsubscribeHeader && listUnsubscribeHeader.value) {
           const match = listUnsubscribeHeader.value.match(/<x?(https?:\/\/[^>]+)>/i);
           if (match && match[1]) {
             unsubscribeUrl = match[1];
           } else {
             const matchDirect = listUnsubscribeHeader.value.match(/(https?:\/\/[^\s>]+)/i);
             if (matchDirect && matchDirect[1]) {
               unsubscribeUrl = matchDirect[1];
             }
           }
        }
      }

      return {
        id: e.id,
        mailboxId,
        from: e.from?.[0] || { name: "Unknown", email: "" },
        to: e.to || [],
        subject: e.subject || "No Subject",
        preview: e.preview || "No preview available",
        body: body || "No content",
        date: e.receivedAt,
        read: !!e.keywords?.["$seen"],
        starred: !!e.keywords?.["$flagged"],
        unsubscribeUrl,
        headers: e.headers,
        attachments: e.attachments,
        keywords: e.keywords
      };
    });
  }

  async getLatestEmail(mailboxId?: string): Promise<Email | null> {
    const filter = mailboxId ? { inMailbox: mailboxId } : {};
    const data = await this.call([
      ["Email/query", {
        accountId: this.account.accountId,
        filter: filter,
        sort: [{ property: "receivedAt", isAscending: false }],
        limit: 1
      }, "0"],
      ["Email/get", {
        accountId: this.account.accountId,
        "#ids": {
          resultOf: "0",
          name: "Email/query",
          path: "/ids"
        },
        properties: ["id", "subject", "from", "to", "preview", "receivedAt", "keywords"]
      }, "1"]
    ]);

    const list = data?.methodResponses?.[1]?.[1]?.list;
    if (!Array.isArray(list) || list.length === 0) return null;
    
    const e = list[0];
    return {
      id: e.id,
      mailboxId: "", // Not needed for notification
      from: e.from?.[0] || { name: "Unknown", email: "" },
      to: e.to || [],
      subject: e.subject || "No Subject",
      preview: e.preview || "No preview available",
      body: "", // not fetched
      date: e.receivedAt,
      read: !!e.keywords?.["$seen"],
      starred: !!e.keywords?.["$flagged"],
      keywords: e.keywords
    };
  }

  async getIdentities(): Promise<Identity[]> {
    const data = await this.call([
      ["Identity/get", { accountId: this.account.accountId }, "0"]
    ]);
    return data?.methodResponses?.[0]?.[1]?.list || [];
  }

  async createIdentity(name: string, email: string): Promise<Identity[]> {
    const res = await this.call([
      ["Identity/set", {
        accountId: this.account.accountId,
        create: {
          "new-identity": { name, email }
        }
      }, "0"]
    ]);
    
    if (res.methodResponses[0][1].created && res.methodResponses[0][1].created["new-identity"]) {
      return this.getIdentities();
    } else {
      throw new Error("Failed to create identity");
    }
  }

  async deleteIdentity(identityId: string): Promise<void> {
    const res = await this.call([
      ["Identity/set", { accountId: this.account.accountId, destroy: [identityId] }, "0"]
    ]);
    if (res.methodResponses?.[0]?.[1]?.notDestroyed?.[identityId]) {
      const error = res.methodResponses[0][1].notDestroyed[identityId];
      throw new Error(error.description || `Failed to delete identity: ${error.type}`);
    }
  }

  async updateEmailKeywords(emailId: string, keywordUpdates: Record<string, boolean | null>): Promise<void> {
    const updateKeywords: Record<string, boolean | null> = {};
    for (const [key, value] of Object.entries(keywordUpdates)) {
      updateKeywords[`keywords/${key}`] = value;
    }
    
    await this.call([
      ["Email/set", {
        accountId: this.account.accountId,
        update: {
          [emailId]: updateKeywords
        }
      }, "0"]
    ]);
  }

  async sendEmail(
    to: string[],
    subject: string,
    body: string,
    cc?: string[],
    bcc?: string[],
    identityId?: string,
    fromEmail?: string,
    draftId?: string,
    fromName?: string,
    attachments?: any[]
  ): Promise<void> {
    // 1. Array wrapper to prevent .map() crashes
    const toArray = Array.isArray(to) ? to : [to];
    
    const emailId = draftId || `draft-${Date.now()}`;
    const mailboxes = await this.getMailboxes();
    const sentMailbox = mailboxes.find(mb => mb.role === 'sent') || mailboxes[0];

    if (!sentMailbox) {
      throw new Error('No sent mailbox found');
    }

    // 2. Resolve Identity
    let finalIdentityId = identityId;
    if (!finalIdentityId) {
      const identityResponse = await this.call([
        ["Identity/get", { accountId: this.account.accountId }, "0"]
      ], ["urn:ietf:params:jmap:core", "urn:ietf:params:jmap:mail"]);
      
      finalIdentityId = this.account.accountId;
      if (identityResponse.methodResponses?.[0]?.[0] === "Identity/get") {
        const identities = (identityResponse.methodResponses[0][1].list || []) as { id: string; email: string }[];
        if (identities.length > 0) {
          const matchingIdentity = identities.find((id) => id.email === (fromEmail || this.account.username));
          finalIdentityId = matchingIdentity?.id || identities[0].id;
        }
      }
    }

    const methodCalls: any[] = [];

    if (draftId) {
      // 3a. Update an existing draft
      methodCalls.push(["Email/set", {
        accountId: this.account.accountId,
        update: {
          [draftId]: {
            "keywords/$draft": false,
            "keywords/$seen": true,
            mailboxIds: { [sentMailbox.id]: true },
          },
        },
      }, "0"]);
      
      // 4a. Submit the existing draft
      methodCalls.push(["EmailSubmission/set", {
        accountId: this.account.accountId,
        create: { 
          "1": { 
            emailId: draftId, 
            identityId: finalIdentityId 
          } 
        },
      }, "1"]);
    } else {
      // 3b. Create a brand new email
      methodCalls.push(["Email/set", {
        accountId: this.account.accountId,
        create: {
          [emailId]: {
            from: [{ ...(fromName ? { name: fromName } : {}), email: fromEmail || this.account.username }],
            to: toArray.map((email: string) => ({ email })),
            cc: cc ? cc.map((email: string) => ({ email })) : undefined,
            bcc: bcc ? bcc.map((email: string) => ({ email })) : undefined,
            subject,
            keywords: { "$seen": true },
            mailboxIds: { [sentMailbox.id]: true },
            bodyValues: { "1": { value: body } },
            ...(/<[a-z][\s\S]*>/i.test(body) ? { htmlBody: [{ partId: "1", type: "text/html" }] } : { textBody: [{ partId: "1", type: "text/plain" }] }),
            attachments: attachments || []
          },
        },
      }, "0"]);

      // 4b. Submit the new email using the strict Creation Reference String (THE FIX)
      methodCalls.push(["EmailSubmission/set", {
        accountId: this.account.accountId,
        create: { 
          "1": { 
            identityId: finalIdentityId,
            emailId: `#${emailId}` // String reference instead of ResultReference Object
          } 
        },
      }, "1"]);
    }

    // 5. Fire off the request
    const response = await this.call(methodCalls, ["urn:ietf:params:jmap:core", "urn:ietf:params:jmap:mail", "urn:ietf:params:jmap:submission"]);

    // 6. Strict Error Handling
    if (response.methodResponses) {
      for (const [methodName, result] of response.methodResponses) {
        if (methodName.endsWith('/error')) {
          throw new Error(result.description || `Failed to send email: ${result.type}`);
        }

        if (result.notCreated || result.notUpdated) {
          const errors = result.notCreated || result.notUpdated;
          const firstError = Object.values(errors)[0] as { description?: string; type?: string; properties?: string[] };
          
          let errorMsg = firstError?.description || firstError?.type || 'Failed to send email';
          if (firstError?.properties) {
            errorMsg += ` (Rejected Properties: ${firstError.properties.join(', ')})`;
          }
          throw new Error(errorMsg);
        }
      }
    }
  }

  async createDraft(
    to: string[],
    subject: string,
    body: string,
    cc: string[] | undefined,
    bcc: string[] | undefined,
    identityId: string,
    fromEmail: string,
    draftId: string | undefined,
    attachments: any[] | undefined,
    fromName?: string
  ): Promise<string> {
    const emailId = draftId || `draft-${Date.now()}`;
    const mailboxes = await this.getMailboxes();
    const draftsMailbox = mailboxes.find(mb => mb.role === 'drafts') || mailboxes[0];

    if (!draftsMailbox) throw new Error('No drafts mailbox found');

    const draftData: any = {
      from: [{ ...(fromName ? { name: fromName } : {}), email: fromEmail || this.account.username }],
      to: to.map(email => ({ email })),
      subject,
      keywords: { "$draft": true, "$seen": true },
      mailboxIds: { [draftsMailbox.id]: true },
      bodyValues: { "1": { value: body } },
      ...(/<[a-z][\s\S]*>/i.test(body) ? { htmlBody: [{ partId: "1", type: "text/html" }] } : { textBody: [{ partId: "1", type: "text/plain" }] }),
      attachments: attachments || []
    };

    if (cc && cc.length > 0) draftData.cc = cc.map(email => ({ email }));
    if (bcc && bcc.length > 0) draftData.bcc = bcc.map(email => ({ email }));
    if (attachments && attachments.length > 0) draftData.attachments = attachments;

    const methodCalls: [string, Record<string, unknown>, string][] = [
      ["Email/set", {
        accountId: this.account.accountId,
        [draftId ? 'update' : 'create']: {
          [emailId]: draftData,
        },
      }, "0"]
    ];

    const response = await this.request(methodCalls);
    
    const methodResponse = response.methodResponses?.[0]?.[1];
    if (draftId) {
      if (methodResponse?.updated && methodResponse.updated[emailId]) return emailId;
    } else {
      const created = methodResponse?.created;
      if (created && created[emailId]) {
          return created[emailId].id;
      }
    }
    throw new Error("Failed to handle draft on server");
  }

  async getVacationResponse(): Promise<any> {
    const res = await this.call([
      ["VacationResponse/get", {
        accountId: this.account.accountId,
        ids: null
      }, "0"]
    ], ["urn:ietf:params:jmap:vacationresponse"]);
    
    return res.methodResponses?.[0]?.[1]?.list?.[0];
  }

  async setVacationResponse(config: { isEnabled: boolean, textBody?: string, htmlBody?: string, subject?: string, fromDate?: string | null, toDate?: string | null }): Promise<void> {
    const caps = ["urn:ietf:params:jmap:core", "urn:ietf:params:jmap:vacationresponse"];
    
    // Construct strict payload. If turning off, only send isEnabled: false.
    const updatePayload: any = { isEnabled: config.isEnabled };
    if (config.isEnabled) {
      if (config.htmlBody) updatePayload.htmlBody = config.htmlBody;
      else if (config.textBody !== undefined) updatePayload.textBody = config.textBody;
      if (config.subject !== undefined) updatePayload.subject = config.subject;
      if (config.fromDate !== undefined) updatePayload.fromDate = config.fromDate ? new Date(config.fromDate).toISOString() : null;
      if (config.toDate !== undefined) updatePayload.toDate = config.toDate ? new Date(config.toDate).toISOString() : null;
    }

    await this.call([
      ["VacationResponse/set", {
        accountId: this.account.accountId,
        update: {
          "singleton": updatePayload
        }
      }, "0"]
    ], caps);
  }

  async getFilters(): Promise<any[]> {
    const data = await this.call([
      ["Filter/get", { accountId: this.account.accountId, ids: null }, "0"]
    ]);
    return data.methodResponses[0][1].list || [];
  }

  async setFilters(filters: any[]): Promise<void> {
    await this.call([
      ["Filter/set", {
        accountId: this.account.accountId,
        create: filters.filter(f => !f.id).reduce((acc, f, idx) => ({ ...acc, [`filter-${idx}`]: f }), {}),
        update: filters.filter(f => f.id).reduce((acc, f) => ({ ...acc, [f.id]: f }), {}),
        destroy: []
      }, "0"]
    ]);
  }

 
  async updateSieveScript(scriptContent: string): Promise<void> {
    const caps = ["urn:ietf:params:jmap:core", "urn:ietf:params:jmap:sieve"];
    const sieveAccountId = this.account.primaryAccounts?.["urn:ietf:params:jmap:sieve"] || this.account.accountId || "p";

    // Sieve scripts must be uploaded as blobs first
    const file = new File([scriptContent], "script.sieve", { type: "application/sieve" });
    const uploaded = await this.uploadBlob(file, sieveAccountId);
    const blobId = uploaded.blobId;

    // 1. Fetch existing Sieve scripts
    const queryData = await this.call([
      ["SieveScript/get", {
        accountId: sieveAccountId
      }, "0"]
    ], caps);

    const scripts = queryData.methodResponses?.[0]?.[1]?.list || [];
    const existingScript = scripts.find((s: any) => s.name === "Webmail Rules");

    const methodArgs: any = { accountId: sieveAccountId };

    if (existingScript) {
      // 2. Update existing script with new blobId
      methodArgs.update = {
        [existingScript.id]: {
          blobId: blobId
        }
      };
      methodArgs.onSuccessActivateScript = existingScript.id;
    } else {
      // 3. Create new script
      methodArgs.create = {
        "webmail-master-script": {
          name: "Webmail Rules",
          blobId: blobId
        }
      };
      methodArgs.onSuccessActivateScript = "#webmail-master-script";
    }

    await this.call([
      ["SieveScript/set", methodArgs, "0"]
    ], caps);
  }

  async getContacts(): Promise<Contact[]> {
    const caps = ["urn:ietf:params:jmap:core", "urn:ietf:params:jmap:contacts"];
    const contactAccountId = this.account.primaryAccounts?.["urn:ietf:params:jmap:contacts"] || this.account.accountId || "p";
    
    try {
      // Fetch all contacts using ContactCard/get without IDs as demonstrated by user
      const data = await this.call([
        ["ContactCard/get", { 
          accountId: contactAccountId
        }, "0"]
      ], caps);
      
      const list = data?.methodResponses?.[0]?.[1]?.list;
      return list || [];
    } catch (err) {
      console.error("Failed to fetch contacts", err);
      // Fallback to query/get if null IDs doesn't work on this server
      try {
        const queryData = await this.call([
          ["ContactCard/query", { accountId: contactAccountId, limit: 1000 }, "0"]
        ], caps);
        const contactIds = queryData?.methodResponses?.[0]?.[1]?.ids || [];
        if (contactIds.length === 0) return [];

        const data = await this.call([
          ["ContactCard/get", { accountId: contactAccountId, ids: contactIds }, "0"]
        ], caps);
        return data?.methodResponses?.[0]?.[1]?.list || [];
      } catch (e) {
        console.error("Fallback fetch also failed", e);
        return [];
      }
    }
  }

  async createContact(contactData: { firstName: string, lastName?: string, email: string, emailType?: string, phone?: string, phoneType?: string, notes?: string, avatarUrl?: string, organization?: string, birthday?: string }): Promise<Contact> {
    const caps = ["urn:ietf:params:jmap:core", "urn:ietf:params:jmap:contacts"];
    const contactAccountId = this.account.primaryAccounts?.["urn:ietf:params:jmap:contacts"] || this.account.accountId || "p";
    
    // First, fetch address books to find a valid addressBookId
    const abData = await this.call([
      ["AddressBook/get", { accountId: contactAccountId }, "0"]
    ], caps);
    const addressBooks = abData?.methodResponses?.[0]?.[1]?.list || [];
    const addressBookId = addressBooks.length > 0 ? addressBooks[0].id : "b";

    const { firstName, lastName, email, emailType, phone, phoneType, notes, avatarUrl, organization, birthday } = contactData;

    const contactPayload: any = {
      "@type": "Card",
      "version": "1.0",
      addressBookIds: { [addressBookId]: true },
      name: {
        components: [
          { kind: "given", value: firstName },
          ...(lastName ? [{ kind: "surname", value: lastName }] : [])
        ],
        isOrdered: true
      },
      emails: {
        "e1": { address: email, contexts: { [emailType || "private"]: true } }
      },
      ...(phone ? {
        phones: {
          "p1": { number: phone, contexts: { [phoneType || "private"]: true } }
        }
      } : {})
    };
    if (notes) {
      contactPayload.notes = notes;
    }
    if (avatarUrl) {
      contactPayload.photos = {
        "ph1": { url: avatarUrl }
      };
    }
    if (organization) {
      contactPayload.organizations = {
        "o1": { name: organization }
      };
    }
    if (birthday) {
      // birthday format YYYY-MM-DD or --MM-DD
      contactPayload.anniversaries = {
        "a1": { kind: "birth", date: birthday }
      };
    }
    if (organization) {
      contactPayload.organizations = {
        "org1": { name: organization }
      };
    }

    const res = await this.call([
      ["ContactCard/set", {
        accountId: contactAccountId,
        create: {
          "new_contact_1": contactPayload
        }
      }, "0"]
    ], caps);
    
    const createdId = res.methodResponses?.[0]?.[1]?.created?.["new_contact_1"]?.id;
    if (!createdId) throw new Error("Failed to create contact");

    const fullName = [firstName, lastName].filter(Boolean).join(" ");
    return {
      id: createdId,
      fullName: fullName,
      emails: { "e1": { address: email, contexts: { "private": true } } },
      ...(phone ? { phones: { "p1": { number: phone, contexts: { "private": true } } } } : {}),
      ...(notes ? { notes: notes } : {})
    };
  }

  async updateContact(id: string, patches: Partial<Contact>): Promise<void> {
    const caps = ["urn:ietf:params:jmap:core", "urn:ietf:params:jmap:contacts"];
    const contactAccountId = this.account.primaryAccounts?.["urn:ietf:params:jmap:contacts"] || this.account.accountId || "p";

    const response = await this.call([
      ["ContactCard/set", {
        accountId: contactAccountId,
        update: {
          [id]: patches
        }
      }, "0"]
    ], caps);

    if (response.methodResponses?.[0]?.[0] === "error") {
      const errObj = response.methodResponses[0][1];
      throw new Error(`Server returned error: ${errObj.type}`);
    }
    
    const result = response.methodResponses?.[0]?.[1];
    if (result?.notUpdated && Object.keys(result.notUpdated).length > 0) {
      throw new Error("Server rejected update.");
    }
  }

  async deleteContact(contactId: string): Promise<void> {
    await this.deleteContacts([contactId]);
  }

  async deleteContacts(contactIds: string[]): Promise<void> {
    if (!contactIds || contactIds.length === 0) return;
    const caps = ["urn:ietf:params:jmap:core", "urn:ietf:params:jmap:contacts"];
    const contactAccountId = this.account.primaryAccounts?.["urn:ietf:params:jmap:contacts"] || this.account.accountId || "p";
    
    const response = await this.call([
      ["ContactCard/set", {
        accountId: contactAccountId,
        destroy: contactIds
      }, "0"]
    ], caps);

    // CRITICAL FIX: Catch method-level errors
    if (response.methodResponses?.[0]?.[0] === "error") {
      const errObj = response.methodResponses[0][1];
      console.error("Method error:", errObj);
      throw new Error(`Server returned error: ${errObj.type}`);
    }

    // CRITICAL FIX: Catch JMAP-specific destruction errors
    const result = response.methodResponses?.[0]?.[1];
    if (result?.notDestroyed && Object.keys(result.notDestroyed).length > 0) {
      console.error("Server rejected contact deletion:", result.notDestroyed);
      throw new Error("Server rejected deletion. The contact may no longer exist.");
    }
  }

  async importContacts(vcardData: string): Promise<number> {
    const caps = ["urn:ietf:params:jmap:core", "urn:ietf:params:jmap:contacts", "urn:ietf:params:jmap:principals"];
    const contactAccountId = this.account.primaryAccounts?.["urn:ietf:params:jmap:contacts"] || this.account.accountId || "p";
    
    const vcards = vcardData.split("BEGIN:VCARD").filter(v => v.trim().length > 0);
    const toCreate: any = {};

    vcards.forEach((vcard, idx) => {
      const lines = vcard.split("\n");
      const contact: any = { emails: [], phones: [] };

      lines.forEach(line => {
        const trimmed = line.trim();
        if (trimmed.toUpperCase().startsWith("FN:")) contact.fullName = trimmed.substring(3).trim();
        if (trimmed.toUpperCase().startsWith("N:")) {
          const parts = trimmed.substring(2).split(";");
          if (!contact.fullName) {
            contact.fullName = `${parts[1] || ''} ${parts[0] || ''}`.trim();
          }
        }
        if (trimmed.toUpperCase().startsWith("EMAIL")) {
          const email = trimmed.split(":").pop()?.trim();
          if (email) contact.emails.push({ address: email, type: "other" });
        }
        if (trimmed.toUpperCase().startsWith("TEL")) {
          const phone = trimmed.split(":").pop()?.trim();
          if (phone) contact.phones.push({ number: phone, type: "other" });
        }
        if (trimmed.toUpperCase().startsWith("ORG:")) contact.company = trimmed.substring(4).trim();
      });

      if (contact.fullName || contact.emails.length > 0) {
        toCreate[`import-${idx}`] = {
          "@type": "Card",
          name: { components: [{ kind: "given", value: contact.fullName || "Imported Contact" }], isOrdered: true },
          emails: {
            "e1": { address: contact.emails[0]?.address || "" }
          },
          ...(contact.phones.length > 0 ? {
            phones: { "p1": { number: contact.phones[0].number } }
          } : {}),
          ...(contact.company ? {
            organizations: { "o1": { name: contact.company } }
          } : {})
        };
      }
    });

    if (Object.keys(toCreate).length === 0) {
      throw new Error("No valid contacts found in import data");
    }

    await this.call([
      ["ContactCard/set", {
        accountId: contactAccountId,
        create: toCreate
      }, "0"]
    ], caps);

    return Object.keys(toCreate).length;
  }

  async getCalendars(): Promise<Calendar[]> {
    const caps = ["urn:ietf:params:jmap:core", "urn:ietf:params:jmap:calendars"];
    const calendarAccountId = this.account.primaryAccounts?.["urn:ietf:params:jmap:calendars"] || this.account.accountId || "p";
    
    const data = await this.call([
      ["Calendar/get", { accountId: calendarAccountId, ids: null }, "0"]
    ], caps);
    
    if (data?.methodResponses?.[0] && data.methodResponses[0][1]?.list) {
      return data.methodResponses[0][1].list;
    }
    return [];
  }

  async createCalendar(name: string, color?: string): Promise<Calendar> {
    const caps = ["urn:ietf:params:jmap:core", "urn:ietf:params:jmap:calendars"];
    const calendarAccountId = this.account.primaryAccounts?.["urn:ietf:params:jmap:calendars"] || this.account.accountId || "p";

    const data = await this.call([
      ["Calendar/set", {
        accountId: calendarAccountId,
        create: {
          "new-cal": {
            name: name,
            color: color || "#4f46e5"
          }
        }
      }, "0"]
    ], caps);

    const created = data?.methodResponses?.[0]?.[1]?.created?.["new-cal"];
    if (!created) throw new Error("Failed to create calendar");

    return {
      id: created.id,
      name,
      color: color || "#4f46e5"
    };
  }

  async deleteCalendar(id: string): Promise<void> {
    const caps = ["urn:ietf:params:jmap:core", "urn:ietf:params:jmap:calendars"];
    const calendarAccountId = this.account.primaryAccounts?.["urn:ietf:params:jmap:calendars"] || this.account.accountId || "p";

    await this.call([
      ["Calendar/set", { accountId: calendarAccountId, destroy: [id] }, "0"]
    ], caps);
  }

  async getEvents(start: string, end: string): Promise<Event[]> {
    const caps = ["urn:ietf:params:jmap:core", "urn:ietf:params:jmap:calendars"];
    const calendarAccountId = this.account.primaryAccounts?.["urn:ietf:params:jmap:calendars"] || this.account.accountId || "p";

    try {
      const data = await this.call([
        ["CalendarEvent/query", {
          accountId: calendarAccountId,
          filter: {
            after: start,
            before: end
          }
        }, "0"],
        ["CalendarEvent/get", {
          accountId: calendarAccountId,
          "#ids": {
            resultOf: "0",
            name: "CalendarEvent/query",
            path: "/ids"
          }
        }, "1"]
      ], caps);

      if (data?.methodResponses?.[1] && data.methodResponses[1][1]?.list) {
        return data.methodResponses[1][1].list;
      }
      return [];
    } catch (err) {
      console.error("Failed to fetch events", err);
      const data = await this.call([
        ["CalendarEvent/get", { accountId: calendarAccountId, ids: null }, "0"]
      ], caps);
      
      if (data?.methodResponses?.[0] && data.methodResponses[0][1]?.list) {
        return data.methodResponses[0][1].list;
      }
      return [];
    }
  }

  async createEvent(event: any): Promise<Event> {
    const caps = ["urn:ietf:params:jmap:core", "urn:ietf:params:jmap:calendars"];
    const calendarAccountId = this.account.primaryAccounts?.["urn:ietf:params:jmap:calendars"] || this.account.accountId || "p";
    
    // Get calendar ID first if not provided
    let calendarIds = event.calendarIds;
    if (!calendarIds) {
      let calendarId = event.calendarId;
      if (!calendarId) {
        const calendars = await this.getCalendars();
        if (calendars.length > 0) {
          calendarId = calendars[0].id;
        }
      }
      if (calendarId) {
        calendarIds = { [calendarId]: true };
      }
    }

    if (!event.calendarId && (!calendarIds || Object.keys(calendarIds).length === 0)) {
      throw new Error("No calendar found to add event to");
    }

    const eventPayload: any = {
      "@type": "Event",
      uid: event.uid || (Math.random().toString(36).substring(2) + Date.now()),
      calendarIds: calendarIds,
      title: event.title,
      description: event.description,
      start: event.start,
      duration: event.duration || "PT1H",
      showWithoutTime: event.showWithoutTime
    };

    if (!event.showWithoutTime) {
      eventPayload.timeZone = event.timeZone || "UTC";
    }

    if (event.location) {
      eventPayload.locations = {
        "loc1": { "@type": "Location", name: event.location }
      };
    }
    if (event.recurrenceRules) eventPayload.recurrenceRules = event.recurrenceRules;
    if (event.virtualLocations) eventPayload.virtualLocations = event.virtualLocations;
    if (event.participants) eventPayload.participants = event.participants;
    if (event.alerts) eventPayload.alerts = event.alerts;

    const response = await this.call([
      ["CalendarEvent/set", {
        accountId: calendarAccountId,
        create: {
          "new-event-1": eventPayload
        }
      }, "0"]
    ], caps);

    const result = response?.methodResponses?.[0]?.[1];
    
    if (result?.notCreated?.["new-event-1"]) {
        const error = result.notCreated["new-event-1"];
        const invalidProps = error.properties ? ` (Props: ${error.properties.join(', ')})` : '';
        throw new Error((error.description || `Failed to create event: ${error.type}`) + invalidProps);
    }

    const created = result?.created?.["new-event-1"];
    if (!created?.id) throw new Error("Failed to create event");
    
    return { ...eventPayload, id: created.id } as any;
  }

  async updateEvent(id: string, patches: Partial<Event>): Promise<void> {
    const caps = ["urn:ietf:params:jmap:core", "urn:ietf:params:jmap:calendars"];
    const calendarAccountId = this.account.primaryAccounts?.["urn:ietf:params:jmap:calendars"] || this.account.accountId || "p";

    const response = await this.call([
      ["CalendarEvent/set", {
        accountId: calendarAccountId,
        update: {
          [id]: patches
        }
      }, "0"]
    ], caps);

    if (response.methodResponses?.[0]?.[0] === "error") {
      const errObj = response.methodResponses[0][1];
      throw new Error(`Server returned error: ${errObj.type}`);
    }

    const result = response.methodResponses?.[0]?.[1];
    if (result?.notUpdated && Object.keys(result.notUpdated).length > 0) {
      throw new Error("Server rejected update.");
    }
  }

  async deleteEvent(eventId: string): Promise<void> {
    const caps = ["urn:ietf:params:jmap:core", "urn:ietf:params:jmap:calendars"];
    const calendarAccountId = this.account.primaryAccounts?.["urn:ietf:params:jmap:calendars"] || this.account.accountId || "p";
    
    const response = await this.call([
      ["CalendarEvent/set", {
        accountId: calendarAccountId,
        destroy: [eventId]
      }, "0"]
    ], caps);

    // CRITICAL FIX: Catch method-level errors
    if (response.methodResponses?.[0]?.[0] === "error") {
      const errObj = response.methodResponses[0][1];
      console.error("Method error:", errObj);
      throw new Error(`Server returned error: ${errObj.type}`);
    }

    // CRITICAL FIX: Catch JMAP-specific destruction errors
    const result = response.methodResponses?.[0]?.[1];
    if (result?.notDestroyed && Object.keys(result.notDestroyed).length > 0) {
      console.error("Server rejected event deletion:", result.notDestroyed);
      throw new Error("Server rejected event deletion.");
    }
  }
}
