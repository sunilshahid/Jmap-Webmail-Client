import { 
  Account, 
  Mailbox, 
  Email, 
  Identity, 
  Contact, 
  Event, 
  Calendar, 
  Thread, 
  EmailSubmission, 
  Quota, 
  EmailSearchFilter, 
  Participant 
} from './types';

export class JmapClient {
  private account: Account;
  public ws: WebSocket | null = null;
  public states: {
    mail?: string;
    mailbox?: string;
    thread?: string;
    calendar?: string;
  } = {};

  constructor(account: Account) {
    this.account = account;
  }

  /**
   * Helper to map raw JMAP mailbox payload to Mailbox
   */
  private mapMailboxObject(m: any): Mailbox {
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
    else if (m.name && m.name.toLowerCase().includes('report')) icon = 'BarChart3';

    return {
      id: m.id,
      name: m.role === 'junk' || m.name === 'Junk Mail' ? 'Spam' : m.name,
      unread: (m.role === 'sent' || m.role === 'trash') ? 0 : (m.unreadEmails || 0),
      totalEmails: m.totalEmails || 0,
      role: m.role,
      icon: icon,
      parentId: m.parentId || null,
      sortOrder: m.sortOrder || 0,
      isSubscribed: m.isSubscribed ?? true,
      totalThreads: m.totalThreads,
      unreadThreads: m.unreadThreads,
      myRights: m.myRights,
      isShared: m.isShared
    };
  }

  /**
   * Helper to map raw JMAP Email payload to Email
   */
  private mapEmailObject(e: any, mailboxId?: string | null): Email {
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

    const resolvedMailboxId = mailboxId || (e.mailboxIds ? Object.keys(e.mailboxIds)[0] : "");
    return {
      id: e.id,
      mailboxId: resolvedMailboxId,
      mailboxIds: e.mailboxIds || (resolvedMailboxId ? { [resolvedMailboxId]: true } : {}),
      threadId: e.threadId || e.id,
      blobId: e.blobId,
      size: e.size,
      from: e.from?.[0] || { name: "Unknown", email: "" },
      fromList: e.from || [],
      to: e.to || [],
      cc: e.cc || [],
      bcc: e.bcc || [],
      replyTo: e.replyTo || [],
      subject: e.subject || "No Subject",
      preview: e.preview || "No preview available",
      body: body || "No content",
      date: e.receivedAt,
      sentAt: e.sentAt || e.receivedAt,
      read: !!e.keywords?.["$seen"],
      starred: !!e.keywords?.["$flagged"],
      hasAttachment: e.hasAttachment ?? (Array.isArray(e.attachments) && e.attachments.length > 0),
      unsubscribeUrl,
      headers: e.headers,
      attachments: e.attachments,
      keywords: e.keywords,
      inReplyTo: e.inReplyTo,
      references: e.references
    };
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
      "urn:ietf:params:jmap:submission"
    ];

    let usingCaps: string[];
    if (customCapabilities && customCapabilities.length > 0) {
      usingCaps = Array.from(new Set([...customCapabilities, "urn:ietf:params:jmap:core"]));
    } else if (this.account.capabilities && this.account.capabilities.length > 0) {
      usingCaps = this.account.capabilities;
    } else {
      usingCaps = defaultCapabilities;
    }

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
      console.warn("JMAP Network Error:", e);
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
          "urn:ietf:params:jmap:sieve",
          "urn:ietf:params:jmap:quotas"
        ]
      })
    });
    
    if (!res.ok) {
      const text = await res.text();
      let msg = `Server returned status ${res.status}`;
      try {
        const errorData = JSON.parse(text);
        if (errorData.error) msg = errorData.error;
      } catch (e) {
         if (res.status === 502 || res.status === 404 || res.status >= 500) {
            msg = `Unable to contact the mail server at ${serverUrl}. Please check the Server URL.`;
         } else if (res.status === 401 || res.status === 403) {
            msg = "Authentication failed. Please check your credentials.";
         }
      }
      throw new Error(msg);
    }
    
    const session = await res.json();

    const apiUrl = session.apiUrl;
    const primaryAccounts = session.primaryAccounts || {};
    const accountsInfo = session.accounts || {};
    
    // Capability routing
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
        this.account.apiUrl = refreshed.apiUrl;
        this.account.accountId = refreshed.accountId;
      } catch (e) {
        console.error("Failed to auto-refresh session for upload", e);
      }
    }

    if (!this.account.uploadUrl) throw new Error("Upload URL not available for this session. Please log out and log in again.");
    
    const uploadUrl = this.account.uploadUrl.replace('{accountId}', accountId);
    
    console.log(`Uploading via proxy to JMAP server...`);
    
    const uploadHeaders: Record<string, string> = {
      'Content-Type': file.type || 'application/octet-stream',
      'X-JMAP-Server-Url': this.account.serverUrl,
      'X-JMAP-Upload-Url': uploadUrl,
      'X-JMAP-Username': this.account.username,
      'X-JMAP-Password': this.account.password || '',
    };
    if (this.account.token) {
      uploadHeaders['X-JMAP-Token'] = this.account.token;
    }

    const response = await fetch('/api/jmap/upload', {
      method: 'POST',
      headers: uploadHeaders,
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

    let downloadUrl = this.account.downloadUrl
      .replace('{accountId}', encodeURIComponent(this.account.accountId))
      .replace('{blobId}', encodeURIComponent(blobId))
      .replace('{name}', encodeURIComponent(name))
      .replace('{type}', encodeURIComponent(type));

    if (downloadUrl.includes('{?')) {
      downloadUrl = downloadUrl.replace(/\{\?[^}]+\}/, () => {
        const params = new URLSearchParams({
          accountId: this.account.accountId,
          blobId,
          name,
          type
        });
        return `?${params.toString()}`;
      });
    }

    // Use proxy to avoid CORS
    const downloadHeaders: Record<string, string> = {
      'X-JMAP-Server-Url': this.account.serverUrl,
      'X-JMAP-Download-Url': downloadUrl,
      'X-JMAP-Username': this.account.username,
      'X-JMAP-Password': this.account.password || '',
    };
    if (this.account.token) {
      downloadHeaders['X-JMAP-Token'] = this.account.token;
    }

    const response = await fetch('/api/jmap/download', {
      method: 'GET',
      headers: downloadHeaders
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
          // Send a ping every 30 seconds to keep connection alive
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
               console.warn("Backend WebSocket error:", payload.message);
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
                // Update internal states if present
                if (currentAccountChanges.Email) this.states.mail = currentAccountChanges.Email;
                if (currentAccountChanges.Mailbox) this.states.mailbox = currentAccountChanges.Mailbox;
                if (currentAccountChanges.Thread) this.states.thread = currentAccountChanges.Thread;
                if (currentAccountChanges.CalendarEvent) this.states.calendar = currentAccountChanges.CalendarEvent;
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
      { name: "Templates", role: null },
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
    
    // Save state for delta synchronization
    if (methodResponse?.[1]?.state) {
      this.states.mailbox = methodResponse[1].state;
    }

    const list = methodResponse?.[1]?.list;
    if (!Array.isArray(list)) return [];
    return list.map((m: any) => this.mapMailboxObject(m));
  }

  async updateMailbox(mailboxId: string, updates: Partial<Mailbox>): Promise<void> {
    const updatePayload: any = {};
    if (updates.name !== undefined) updatePayload.name = updates.name;
    if (updates.parentId !== undefined) updatePayload.parentId = updates.parentId;
    if (updates.sortOrder !== undefined) updatePayload.sortOrder = updates.sortOrder;
    if (updates.isSubscribed !== undefined) updatePayload.isSubscribed = updates.isSubscribed;

    await this.call([
      ["Mailbox/set", {
        accountId: this.account.accountId,
        update: {
          [mailboxId]: updatePayload
        }
      }, "0"]
    ]);
  }

  /**
   * RFC 8620 / RFC 8621 Delta synchronization for Mailboxes
   */
  async syncMailboxes(): Promise<{ created: Mailbox[]; updated: Mailbox[]; destroyed: string[]; newState: string } | null> {
    const sinceState = this.states.mailbox;
    if (!sinceState) return null;

    try {
      const changesRes = await this.call([
        ["Mailbox/changes", {
          accountId: this.account.accountId,
          sinceState
        }, "0"]
      ]);

      const changes = changesRes?.methodResponses?.[0]?.[1];
      if (!changes || changesRes?.methodResponses?.[0]?.[0] === "error") {
        return null;
      }

      const createdIds: string[] = changes.created || [];
      const updatedIds: string[] = changes.updated || [];
      const destroyed: string[] = changes.destroyed || [];
      const newState: string = changes.newState || sinceState;
      this.states.mailbox = newState;

      const idsToFetch = Array.from(new Set([...createdIds, ...updatedIds]));
      let created: Mailbox[] = [];
      let updated: Mailbox[] = [];

      if (idsToFetch.length > 0) {
        const getRes = await this.call([
          ["Mailbox/get", {
            accountId: this.account.accountId,
            ids: idsToFetch
          }, "0"]
        ]);
        const list = getRes?.methodResponses?.[0]?.[1]?.list || [];
        const fetchedMap = new Map(list.map((m: any) => [m.id, this.mapMailboxObject(m)]));
        created = createdIds.map((id: string) => fetchedMap.get(id)).filter(Boolean) as Mailbox[];
        updated = updatedIds.map((id: string) => fetchedMap.get(id)).filter(Boolean) as Mailbox[];
      }

      return { created, updated, destroyed, newState };
    } catch (e) {
      console.warn("Mailbox delta sync error:", e);
      return null;
    }
  }

  /**
   * Fetch emails with RFC 8621 server-side search, filtering, and threading support
   */
  async getEmails(
    mailboxId: string | null, 
    limit: number = 50, 
    position: number = 0, 
    filterOrKeyword?: string | EmailSearchFilter, 
    collapseThreads: boolean = true
  ): Promise<Email[]> {
    const filterParams: any = {};
    
    if (mailboxId) {
      filterParams.inMailbox = mailboxId;
    }

    if (typeof filterOrKeyword === 'string' && filterOrKeyword.trim()) {
      filterParams.hasKeyword = filterOrKeyword.trim();
    } else if (typeof filterOrKeyword === 'object' && filterOrKeyword !== null) {
      if (filterOrKeyword.inMailbox) filterParams.inMailbox = filterOrKeyword.inMailbox;
      if (filterOrKeyword.text) filterParams.text = filterOrKeyword.text; // Hits Stalwart Tantivy engine!
      if (filterOrKeyword.from) filterParams.from = filterOrKeyword.from;
      if (filterOrKeyword.to) filterParams.to = filterOrKeyword.to;
      if (filterOrKeyword.subject) filterParams.subject = filterOrKeyword.subject;
      if (filterOrKeyword.body) filterParams.body = filterOrKeyword.body;
      if (filterOrKeyword.after) filterParams.after = new Date(filterOrKeyword.after).toISOString();
      if (filterOrKeyword.before) filterParams.before = new Date(filterOrKeyword.before).toISOString();
      if (filterOrKeyword.hasAttachment !== undefined) filterParams.hasAttachment = filterOrKeyword.hasAttachment;
      if (filterOrKeyword.hasKeyword) filterParams.hasKeyword = filterOrKeyword.hasKeyword;
    }

    const data = await this.call([
      ["Email/query", {
        accountId: this.account.accountId,
        filter: Object.keys(filterParams).length > 0 ? filterParams : undefined,
        sort: [{ property: "receivedAt", isAscending: false }],
        collapseThreads: collapseThreads,
        position: position,
        limit: limit,
        calculateTotal: true
      }, "0"],
      ["Email/get", {
        accountId: this.account.accountId,
        "#ids": {
          resultOf: "0",
          name: "Email/query",
          path: "/ids"
        },
        properties: [
          "id", 
          "blobId",
          "threadId",
          "mailboxIds", 
          "subject", 
          "from", 
          "to", 
          "cc", 
          "bcc", 
          "replyTo", 
          "preview", 
          "bodyValues", 
          "htmlBody", 
          "textBody", 
          "receivedAt", 
          "sentAt",
          "size",
          "keywords", 
          "headers", 
          "header:List-Unsubscribe:asURLs", 
          "header:List-Unsubscribe:asText", 
          "attachments",
          "hasAttachment"
        ],
        maxBodyValueBytes: 256000,
        fetchTextBodyValues: true,
        fetchHTMLBodyValues: true
      }, "1"]
    ]);

    if (data?.methodResponses?.[0]?.[0] === "error") {
       throw new Error(`JMAP Email/query Error: ${data.methodResponses[0][1]?.type || 'Unknown'}`);
    }
    if (data?.methodResponses?.[1]?.[0] === "error") {
       throw new Error(`JMAP Email/get Error: ${data.methodResponses[1][1]?.type || 'Unknown'}`);
    }

    // Save Email state for delta syncing
    if (data?.methodResponses?.[1]?.[1]?.state) {
      this.states.mail = data.methodResponses[1][1].state;
    }

    const list = data?.methodResponses?.[1]?.[1]?.list;
    if (!Array.isArray(list)) return [];
    
    const mappedEmails = list.map((e: any) => this.mapEmailObject(e, mailboxId));
    
    // Attach query totals if available
    const total = data?.methodResponses?.[0]?.[1]?.total;
    if (total !== undefined) {
      (mappedEmails as any).total = total;
    }

    return mappedEmails;
  }

  /**
   * RFC 8621 §3: Conversation Thread Methods
   */
  async getThreads(threadIds: string[]): Promise<Thread[]> {
    if (!threadIds || threadIds.length === 0) return [];
    const caps = ["urn:ietf:params:jmap:core", "urn:ietf:params:jmap:mail"];
    const response = await this.call([
      ["Thread/get", {
        accountId: this.account.accountId,
        ids: threadIds
      }, "0"]
    ], caps);
    
    const list = response?.methodResponses?.[0]?.[1]?.list;
    if (Array.isArray(list)) {
      return list.map((t: any) => ({
        id: t.id,
        emailIds: t.emailIds || []
      }));
    }
    return [];
  }

  /**
   * Fetch complete conversation thread with all ordered emails
   */
  async getThreadWithEmails(threadId: string): Promise<{ thread: Thread; emails: Email[] }> {
    const caps = ["urn:ietf:params:jmap:core", "urn:ietf:params:jmap:mail"];
    const tData = await this.call([
      ["Thread/get", {
        accountId: this.account.accountId,
        ids: [threadId]
      }, "0"]
    ], caps);

    const thread = tData?.methodResponses?.[0]?.[1]?.list?.[0];
    if (!thread || !thread.emailIds || thread.emailIds.length === 0) {
      return { thread: { id: threadId, emailIds: [] }, emails: [] };
    }

    const eData = await this.call([
      ["Email/get", {
        accountId: this.account.accountId,
        ids: thread.emailIds,
        properties: [
          "id", 
          "blobId", 
          "threadId", 
          "mailboxIds", 
          "subject", 
          "from", 
          "to", 
          "cc", 
          "bcc", 
          "replyTo", 
          "preview", 
          "bodyValues", 
          "htmlBody", 
          "textBody", 
          "receivedAt", 
          "sentAt", 
          "size", 
          "keywords", 
          "headers", 
          "attachments", 
          "hasAttachment"
        ],
        maxBodyValueBytes: 256000,
        fetchTextBodyValues: true,
        fetchHTMLBodyValues: true
      }, "0"]
    ], caps);

    const emailList = eData?.methodResponses?.[0]?.[1]?.list || [];
    const mapped = emailList.map((e: any) => this.mapEmailObject(e));
    mapped.sort((a: any, b: any) => new Date(a.date).getTime() - new Date(b.date).getTime());
    
    return {
      thread: { id: thread.id, emailIds: thread.emailIds },
      emails: mapped
    };
  }

  /**
   * RFC 8621 §4.2: Delta synchronization for Emails
   */
  async syncEmails(mailboxId?: string): Promise<{ created: Email[]; updated: Email[]; destroyed: string[]; newState: string } | null> {
    const sinceState = this.states.mail;
    if (!sinceState) return null;

    const caps = ["urn:ietf:params:jmap:core", "urn:ietf:params:jmap:mail"];
    try {
      const changesRes = await this.call([
        ["Email/changes", {
          accountId: this.account.accountId,
          sinceState,
          maxChanges: 100
        }, "0"]
      ], caps);

      const changes = changesRes?.methodResponses?.[0]?.[1];
      if (!changes || changesRes?.methodResponses?.[0]?.[0] === "error") {
        return null;
      }

      const createdIds: string[] = changes.created || [];
      const updatedIds: string[] = changes.updated || [];
      const destroyedIds: string[] = changes.destroyed || [];
      const newState: string = changes.newState || sinceState;
      this.states.mail = newState;

      const idsToFetch = Array.from(new Set([...createdIds, ...updatedIds]));
      let createdEmails: Email[] = [];
      let updatedEmails: Email[] = [];

      if (idsToFetch.length > 0) {
        const getRes = await this.call([
          ["Email/get", {
            accountId: this.account.accountId,
            ids: idsToFetch,
            properties: [
              "id", 
              "blobId", 
              "threadId", 
              "mailboxIds", 
              "subject", 
              "from", 
              "to", 
              "cc", 
              "bcc", 
              "replyTo", 
              "preview", 
              "bodyValues", 
              "htmlBody", 
              "textBody", 
              "receivedAt", 
              "sentAt", 
              "size", 
              "keywords", 
              "headers", 
              "attachments", 
              "hasAttachment"
            ],
            maxBodyValueBytes: 256000,
            fetchTextBodyValues: true,
            fetchHTMLBodyValues: true
          }, "0"]
        ], caps);

        const list = getRes?.methodResponses?.[0]?.[1]?.list || [];
        const fetchedMap = new Map(list.map((e: any) => [e.id, this.mapEmailObject(e, mailboxId)]));

        createdEmails = createdIds.map(id => fetchedMap.get(id)).filter(Boolean) as Email[];
        updatedEmails = updatedIds.map(id => fetchedMap.get(id)).filter(Boolean) as Email[];
      }

      return {
        created: createdEmails,
        updated: updatedEmails,
        destroyed: destroyedIds,
        newState
      };
    } catch (e) {
      console.warn("Email delta sync error:", e);
      return null;
    }
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
      mailboxId: "",
      from: e.from?.[0] || { name: "Unknown", email: "" },
      to: e.to || [],
      subject: e.subject || "No Subject",
      preview: e.preview || "No preview available",
      body: "",
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
      updateKeywords[`keywords/${key}`] = value === false ? null : value;
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

  /**
   * RFC 8621 §7: Email Submission with native scheduled sending (sendAt) and atomic cleanup
   */
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
    attachments?: any[],
    inReplyTo?: string,
    references?: string[],
    sendAt?: string
  ): Promise<{ emailId: string; submissionId?: string }> {
    const toArray = Array.isArray(to) ? to : [to];
    const emailId = draftId || `draft-${Date.now()}`;
    const mailboxes = await this.getMailboxes();
    const sentMailbox = mailboxes.find(mb => mb.role === 'sent') || mailboxes[0];

    if (!sentMailbox) {
      throw new Error('No sent mailbox found');
    }

    // Resolve Identity
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
    const isHtml = /<(html|body|p|div|br|table|span|h[1-6]|ul|ol|li)[^>]*>/i.test(body);

    const submissionCreatePayload: any = {
      identityId: finalIdentityId,
      emailId: draftId ? draftId : `#${emailId}`
    };

    // Native Stalwart scheduled send (RFC 8621 sendAt)
    if (sendAt) {
      submissionCreatePayload.sendAt = new Date(sendAt).toISOString();
    }

    // Atomic draft cleanup on successful submission
    if (draftId && !sendAt) {
      submissionCreatePayload.onSuccessDestroyEmail = [draftId];
    }

    if (draftId) {
      // Update existing draft and submit atomically
      methodCalls.push(["Email/set", {
        accountId: this.account.accountId,
        update: {
          [draftId]: {
            "keywords/$draft": null,
            "keywords/$seen": true,
            mailboxIds: { [sentMailbox.id]: true },
          },
        },
      }, "0"]);
      
      methodCalls.push(["EmailSubmission/set", {
        accountId: this.account.accountId,
        create: { 
          "sub1": submissionCreatePayload
        },
      }, "1"]);
    } else {
      // Create email and submit
      const emailPayload: any = {
        from: [{ ...(fromName ? { name: fromName } : {}), email: fromEmail || this.account.username }],
        to: toArray.map((email: string) => ({ email })),
        cc: cc && cc.length > 0 ? cc.map((email: string) => ({ email })) : undefined,
        bcc: bcc && bcc.length > 0 ? bcc.map((email: string) => ({ email })) : undefined,
        subject,
        keywords: { "$seen": true },
        mailboxIds: { [sentMailbox.id]: true },
        bodyValues: { "1": { value: body } },
        ...(isHtml ? { htmlBody: [{ partId: "1", type: "text/html" }] } : { textBody: [{ partId: "1", type: "text/plain" }] }),
        attachments: attachments || []
      };
      if (inReplyTo) emailPayload.inReplyTo = [inReplyTo];
      if (references && references.length > 0) emailPayload.references = references;

      methodCalls.push(["Email/set", {
        accountId: this.account.accountId,
        create: {
          [emailId]: emailPayload,
        },
      }, "0"]);

      methodCalls.push(["EmailSubmission/set", {
        accountId: this.account.accountId,
        create: { 
          "sub1": submissionCreatePayload
        },
      }, "1"]);
    }

    const response = await this.call(methodCalls, [
      "urn:ietf:params:jmap:core", 
      "urn:ietf:params:jmap:mail", 
      "urn:ietf:params:jmap:submission"
    ]);

    if (response.methodResponses) {
      for (const [methodName, result] of response.methodResponses) {
        if (methodName === 'error' || methodName.endsWith('/error')) {
          throw new Error(result.description || `Failed to send email: ${result.type || 'method error'}`);
        }

        const notCreated = result.notCreated && Object.keys(result.notCreated).length > 0 ? result.notCreated : null;
        const notUpdated = result.notUpdated && Object.keys(result.notUpdated).length > 0 ? result.notUpdated : null;
        if (notCreated || notUpdated) {
          const errors = notCreated || notUpdated;
          const firstError = Object.values(errors)[0] as { description?: string; type?: string; properties?: string[] };
          let errorMsg = firstError?.description || firstError?.type || 'Failed to send email';
          if (firstError?.properties) {
            errorMsg += ` (Rejected Properties: ${firstError.properties.join(', ')})`;
          }
          throw new Error(errorMsg);
        }
      }
    }

    const subResult = response?.methodResponses?.find((r: any) => r[0] === 'EmailSubmission/set')?.[1];
    const createdSubmission = subResult?.created?.["sub1"];

    return {
      emailId: draftId || emailId,
      submissionId: createdSubmission?.id
    };
  }

  /**
   * Cancel or undo an EmailSubmission
   */
  async undoSend(submissionId: string): Promise<boolean> {
    const caps = ["urn:ietf:params:jmap:core", "urn:ietf:params:jmap:submission"];
    const response = await this.call([
      ["EmailSubmission/set", {
        accountId: this.account.accountId,
        destroy: [submissionId]
      }, "0"]
    ], caps);

    const destroyed = response?.methodResponses?.[0]?.[1]?.destroyed;
    return Array.isArray(destroyed) && destroyed.includes(submissionId);
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

    const isHtml = /<(html|body|p|div|br|table|span|h[1-6]|ul|ol|li)[^>]*>/i.test(body);
    const draftData: any = {
      from: [{ ...(fromName ? { name: fromName } : {}), email: fromEmail || this.account.username }],
      to: to.map(email => ({ email })),
      subject,
      keywords: { "$draft": true, "$seen": true },
      mailboxIds: { [draftsMailbox.id]: true },
      bodyValues: { "1": { value: body } },
      ...(isHtml ? { htmlBody: [{ partId: "1", type: "text/html" }] } : { textBody: [{ partId: "1", type: "text/plain" }] }),
      attachments: attachments || []
    };

    if (cc && cc.length > 0) draftData.cc = cc.map(email => ({ email }));
    if (bcc && bcc.length > 0) draftData.bcc = bcc.map(email => ({ email }));
    if (attachments && attachments.length > 0) draftData.attachments = attachments;

    const newDraftKey = `draft-${Date.now()}`;
    const emailSetArgs: any = {
      accountId: this.account.accountId,
      create: {
        [newDraftKey]: draftData,
      }
    };
    if (draftId) {
      emailSetArgs.destroy = [draftId];
    }

    const methodCalls: [string, Record<string, unknown>, string][] = [
      ["Email/set", emailSetArgs, "0"]
    ];

    const response = await this.request(methodCalls);
    const methodResponse = response.methodResponses?.[0]?.[1];
    const created = methodResponse?.created;
    if (created && created[newDraftKey]) {
      return created[newDraftKey].id;
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

    const file = new File([scriptContent], "script.sieve", { type: "application/sieve" });
    const uploaded = await this.uploadBlob(file, sieveAccountId);
    const blobId = uploaded.blobId;

    const queryData = await this.call([
      ["SieveScript/get", {
        accountId: sieveAccountId
      }, "0"]
    ], caps);

    const scripts = queryData.methodResponses?.[0]?.[1]?.list || [];
    const existingScript = scripts.find((s: any) => s.name === "Webmail Rules");

    const methodArgs: any = { accountId: sieveAccountId };

    if (existingScript) {
      methodArgs.update = {
        [existingScript.id]: {
          blobId: blobId
        }
      };
      methodArgs.onSuccessActivateScript = existingScript.id;
    } else {
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

  /**
   * RFC 9425: JMAP for Quotas
   */
  async getQuotas(): Promise<Quota[]> {
    const caps = ["urn:ietf:params:jmap:core", "urn:ietf:params:jmap:quotas"];
    try {
      const res = await this.call([
        ["Quota/get", { accountId: this.account.accountId }, "0"]
      ], caps);
      const list = res?.methodResponses?.[0]?.[1]?.list;
      if (Array.isArray(list)) {
        return list.map((q: any) => ({
          id: q.id,
          name: q.name || "Mailbox Storage Quota",
          resourceType: q.resourceType,
          used: q.used || 0,
          limit: q.limit || 0,
          scope: q.scope || "account"
        }));
      }
    } catch (e) {
      console.warn("Server does not support Quota/get or returned error:", e);
    }
    return [];
  }

  /**
   * RFC 8621 §5: Search snippets with keyword highlights
   */
  async getSearchSnippets(emailIds: string[], filter: any): Promise<Record<string, string>> {
    const caps = ["urn:ietf:params:jmap:core", "urn:ietf:params:jmap:mail"];
    try {
      const res = await this.call([
        ["SearchSnippet/get", {
          accountId: this.account.accountId,
          emailIds,
          filter
        }, "0"]
      ], caps);
      const list = res?.methodResponses?.[0]?.[1]?.list || [];
      const snippets: Record<string, string> = {};
      list.forEach((s: any) => {
        if (s.emailId && (s.preview || s.subject)) {
          snippets[s.emailId] = s.preview || s.subject;
        }
      });
      return snippets;
    } catch (e) {
      return {};
    }
  }

  async getContacts(): Promise<Contact[]> {
    const caps = ["urn:ietf:params:jmap:core", "urn:ietf:params:jmap:contacts"];
    const contactAccountId = this.account.primaryAccounts?.["urn:ietf:params:jmap:contacts"] || this.account.accountId || "p";
    
    try {
      const data = await this.call([
        ["ContactCard/get", { 
          accountId: contactAccountId
        }, "0"]
      ], caps);
      
      const list = data?.methodResponses?.[0]?.[1]?.list;
      return list || [];
    } catch (err) {
      console.error("Failed to fetch contacts", err);
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
        console.warn("Fallback fetch also failed", e);
        return [];
      }
    }
  }

  async createContact(contactData: { firstName: string, lastName?: string, email: string, emailType?: string, phone?: string, phoneType?: string, notes?: string, avatarUrl?: string, organization?: string, birthday?: string }): Promise<Contact> {
    const caps = ["urn:ietf:params:jmap:core", "urn:ietf:params:jmap:contacts"];
    const contactAccountId = this.account.primaryAccounts?.["urn:ietf:params:jmap:contacts"] || this.account.accountId || "p";
    
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
      contactPayload.anniversaries = {
        "a1": { kind: "birth", date: birthday }
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

    if (response.methodResponses?.[0]?.[0] === "error") {
      const errObj = response.methodResponses[0][1];
      console.error("Method error:", errObj);
      throw new Error(`Server returned error: ${errObj.type}`);
    }

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

  /**
   * RFC 8984 & JMAP Calendars Implementation
   */
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

  async updateCalendar(id: string, patches: Partial<Calendar>): Promise<void> {
    const caps = ["urn:ietf:params:jmap:core", "urn:ietf:params:jmap:calendars"];
    const calendarAccountId = this.account.primaryAccounts?.["urn:ietf:params:jmap:calendars"] || this.account.accountId || "p";

    await this.call([
      ["Calendar/set", {
        accountId: calendarAccountId,
        update: {
          [id]: patches
        }
      }, "0"]
    ], caps);
  }

  async deleteCalendar(id: string): Promise<void> {
    const caps = ["urn:ietf:params:jmap:core", "urn:ietf:params:jmap:calendars"];
    const calendarAccountId = this.account.primaryAccounts?.["urn:ietf:params:jmap:calendars"] || this.account.accountId || "p";

    await this.call([
      ["Calendar/set", { accountId: calendarAccountId, destroy: [id] }, "0"]
    ], caps);
  }

  /**
   * Fetch calendar events with RFC 8984 recurrence expansion
   */
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
          },
          expandRecurrences: true // Instructs Stalwart to generate synthetic instances for recurring events!
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
      console.warn("Failed to query events with expandRecurrences, falling back to full get", err);
      const data = await this.call([
        ["CalendarEvent/get", { accountId: calendarAccountId, ids: null }, "0"]
      ], caps);
      
      if (data?.methodResponses?.[0] && data.methodResponses[0][1]?.list) {
        return data.methodResponses[0][1].list;
      }
      return [];
    }
  }

  /**
   * RFC 8984 JSCalendar event creation
   */
  async createEvent(event: any): Promise<Event> {
    const caps = ["urn:ietf:params:jmap:core", "urn:ietf:params:jmap:calendars"];
    const calendarAccountId = this.account.primaryAccounts?.["urn:ietf:params:jmap:calendars"] || this.account.accountId || "p";
    
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

    // Default to system IANA timezone if not provided
    const userTz = typeof Intl !== 'undefined' ? Intl.DateTimeFormat().resolvedOptions().timeZone : 'UTC';

    const eventPayload: any = {
      "@type": "Event",
      uid: event.uid || (Math.random().toString(36).substring(2) + Date.now()),
      calendarIds: calendarIds,
      title: event.title,
      description: event.description,
      start: event.start,
      duration: event.duration || "PT1H",
      showWithoutTime: event.showWithoutTime,
      status: event.status || "confirmed"
    };

    if (!event.showWithoutTime) {
      eventPayload.timeZone = event.timeZone || userTz;
    }

    if (event.location) {
      eventPayload.locations = {
        "loc1": { "@type": "Location", name: event.location }
      };
    }
    if (event.recurrenceRules) eventPayload.recurrenceRules = event.recurrenceRules;
    if (event.recurrenceOverrides) eventPayload.recurrenceOverrides = event.recurrenceOverrides;
    if (event.virtualLocations) eventPayload.virtualLocations = event.virtualLocations;
    if (event.participants) eventPayload.participants = event.participants;
    if (event.alerts) eventPayload.alerts = event.alerts;
    if (event.priority) eventPayload.priority = event.priority;

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

  /**
   * RFC 8984 & JMAP Calendar Scheduling: RSVP to meeting invitations
   */
  async rsvpEvent(
    eventId: string, 
    participantEmail: string, 
    status: "accepted" | "declined" | "tentative", 
    comment?: string
  ): Promise<void> {
    const caps = ["urn:ietf:params:jmap:core", "urn:ietf:params:jmap:calendars"];
    const calendarAccountId = this.account.primaryAccounts?.["urn:ietf:params:jmap:calendars"] || this.account.accountId || "p";

    // 1. Fetch current event to find participant key
    const evData = await this.call([
      ["CalendarEvent/get", { accountId: calendarAccountId, ids: [eventId] }, "0"]
    ], caps);

    const event = evData?.methodResponses?.[0]?.[1]?.list?.[0];
    if (!event) throw new Error("Event not found");

    let participantKey = Object.keys(event.participants || {}).find(
      k => event.participants[k].email?.toLowerCase() === participantEmail.toLowerCase()
    );

    const patch: any = {};
    if (participantKey) {
      patch[`participants/${participantKey}/participationStatus`] = status;
      if (comment) {
        patch[`participants/${participantKey}/comment`] = comment;
      }
    } else {
      const newKey = `part_${Date.now()}`;
      patch[`participants/${newKey}`] = {
        "@type": "Participant",
        email: participantEmail,
        participationStatus: status,
        roles: { attendee: true },
        ...(comment ? { comment } : {})
      };
    }

    await this.call([
      ["CalendarEvent/set", {
        accountId: calendarAccountId,
        update: {
          [eventId]: patch
        }
      }, "0"]
    ], caps);
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

    if (response.methodResponses?.[0]?.[0] === "error") {
      const errObj = response.methodResponses[0][1];
      console.error("Method error:", errObj);
      throw new Error(`Server returned error: ${errObj.type}`);
    }

    const result = response.methodResponses?.[0]?.[1];
    if (result?.notDestroyed && Object.keys(result.notDestroyed).length > 0) {
      console.error("Server rejected event deletion:", result.notDestroyed);
      throw new Error("Server rejected event deletion.");
    }
  }
}
