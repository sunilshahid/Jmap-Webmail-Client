import { Account, Mailbox, Email, Identity, Contact, Event } from './types';

export class JmapClient {
  private account: Account;

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
      "urn:ietf:params:jmap:contacts",
      "urn:ietf:params:jmap:calendars"
    ];
    usingCaps = Array.from(new Set([...usingCaps, ...requiredCaps]));

    const payload = {
      using: usingCaps,
      methodCalls: methodCalls.map(call => {
        if (call[1] && call[1].accountId) {
          // Default to 'p' if not otherwise specified, as per Stalwart conventions
          call[1].accountId = call[1].accountId === "p" ? "p" : this.account.accountId;
        }
        return call;
      })
    };

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
    return await res.json();
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
          "urn:ietf:params:jmap:principals"
        ]
      })
    });
    
    if (!res.ok) {
      throw new Error("Authentication failed. Check your credentials and server URL.");
    }
    
    const session = await res.json();

    const apiUrl = session.apiUrl;
    const accountId = "p"; // Based on Stalwart session object
    const primaryAccounts = session.primaryAccounts;
    const capabilities = Object.keys(session.capabilities || {});
    
    return { serverUrl, username, password, token, apiUrl, accountId, primaryAccounts, capabilities };
  }

  async getMailboxes(): Promise<Mailbox[]> {
    const data = await this.call([
      ["Mailbox/get", { accountId: this.account.accountId }, "0"]
    ]);
    const list = data.methodResponses[0][1].list;
    return list.map((m: any) => ({
      id: m.id,
      name: m.name,
      unread: m.role === 'sent' ? 0 : (m.unreadEmails || 0),
      role: m.role,
      icon: m.role === 'inbox' ? 'Inbox' : m.role === 'sent' ? 'Send' : m.role === 'drafts' ? 'File' : m.role === 'trash' ? 'Trash2' : 'File'
    }));
  }

  async getEmails(mailboxId: string): Promise<Email[]> {
    const data = await this.call([
      ["Email/query", {
        accountId: this.account.accountId,
        filter: { inMailbox: mailboxId },
        sort: [{ property: "receivedAt", isAscending: false }],
        limit: 50
      }, "0"],
      ["Email/get", {
        accountId: this.account.accountId,
        "#ids": {
          resultOf: "0",
          name: "Email/query",
          path: "/ids"
        },
        properties: ["id", "subject", "from", "to", "preview", "bodyValues", "htmlBody", "textBody", "receivedAt", "keywords"],
        fetchAllBodyValues: true
      }, "1"]
    ]);

    const list = data.methodResponses[1][1].list;
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
        starred: !!e.keywords?.["$flagged"]
      };
    });
  }

  async getIdentities(): Promise<Identity[]> {
    const data = await this.call([
      ["Identity/get", { accountId: this.account.accountId }, "0"]
    ]);
    return data.methodResponses[0][1].list || [];
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

  async sendEmail(
    to: string[],
    subject: string,
    body: string,
    cc?: string[],
    bcc?: string[],
    identityId?: string,
    fromEmail?: string,
    draftId?: string,
    fromName?: string
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
            textBody: [{ partId: "1" }],
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
      textBody: [{ partId: "1" }],
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

  async setVacationResponse(config: { isEnabled: boolean, textBody: string, subject?: string }): Promise<void> {
    await this.call([
      ["VacationResponse/set", {
        accountId: this.account.accountId,
        update: {
          "singleton": config
        }
      }, "0"]
    ], ["urn:ietf:params:jmap:vacationresponse"]);
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
    await this.call([
      ["SieveScript/set", {
        accountId: this.account.accountId,
        onSuccessDestroy: ["webmail-master-script"],
        create: {
          "webmail-master-script": {
            name: "Webmail Rules",
            content: scriptContent,
            isActive: true
          }
        }
      }, "0"]
    ], ["urn:ietf:params:jmap:core", "urn:ietf:params:jmap:sieve"]);
  }

  async getContacts(): Promise<Contact[]> {
    const caps = ["urn:ietf:params:jmap:core", "urn:ietf:params:jmap:contacts", "urn:ietf:params:jmap:principals"];
    const contactAccountId = "p";
    
    try {
      const data = await this.call([
        ["ContactCard/get", { accountId: contactAccountId, ids: null }, "0"]
      ], caps);
      
      if (data.methodResponses[0] && data.methodResponses[0][1].list) {
        return data.methodResponses[0][1].list;
      }
      return [];
    } catch (err) {
      console.error("Failed to fetch contacts", err);
      // Fallback to query if get null fails
      const data = await this.call([
        ["ContactCard/query", { accountId: contactAccountId }, "0"],
        ["ContactCard/get", { accountId: contactAccountId, "#ids": { resultOf: "0", name: "ContactCard/query", path: "/ids" } }, "1"]
      ], caps);
      
      if (data.methodResponses[1] && data.methodResponses[1][1].list) {
        return data.methodResponses[1][1].list;
      }
      return [];
    }
  }

  async createContact(contact: any): Promise<void> {
    const contactAccountId = "p";
    const caps = ["urn:ietf:params:jmap:core", "urn:ietf:params:jmap:contacts", "urn:ietf:params:jmap:principals"];
    
    const res = await this.call([
      ["ContactCard/set", {
        accountId: contactAccountId,
        create: {
          "new-contact": {
            "@type": "Card",
            "version": "1.0",
            uid: `urn:uuid:${crypto.randomUUID()}`,
            kind: "individual",
            name: {
              components: [
                ...(contact.firstName ? [{ kind: "given", value: contact.firstName }] : []),
                ...(contact.lastName ? [{ kind: "surname", value: contact.lastName }] : [])
              ]
            },
            emails: {
              "email-1": {
                address: contact.email,
                contexts: contact.emailType ? { [contact.emailType]: true } : undefined
              }
            },
            ...(contact.phone ? {
              phones: {
                "phone-1": {
                  number: contact.phone,
                  contexts: contact.phoneType ? { [contact.phoneType]: true } : undefined
                }
              }
            } : {}),
            ...(contact.organization ? {
              organizations: {
                "org-1": {
                  name: contact.organization
                }
              }
            } : {})
          }
        }
      }, "0"]
    ], caps);

    const methodResponse = res.methodResponses?.[0];
    if (!methodResponse) throw new Error("No response from server");

    const [name, response] = methodResponse;
    if (name === "error") {
      if (response.type === "invalidProperties") {
        const fieldErrors: Record<string, string> = {};
        Object.keys(response.properties).forEach(prop => {
          fieldErrors[prop] = response.properties[prop].description || "Invalid field";
        });
        throw { type: "invalidProperties", fieldErrors };
      }
      throw new Error(`JMAP Error: ${response.type} ${response.description || ""}`);
    }
  }

  async deleteContact(contactId: string): Promise<void> {
    const contactAccountId = "p";
    const caps = ["urn:ietf:params:jmap:core", "urn:ietf:params:jmap:contacts", "urn:ietf:params:jmap:principals"];
    
    await this.call([
      ["ContactCard/set", {
        accountId: contactAccountId,
        destroy: [contactId]
      }, "0"]
    ], caps);
  }

  async importContacts(vcardData: string): Promise<number> {
    const contactAccountId = "p";
    const caps = ["urn:ietf:params:jmap:core", "urn:ietf:params:jmap:contacts", "urn:ietf:params:jmap:principals"];
    
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
        const names = (contact.fullName || "Imported Contact").split(" ");
        
        const emailsMap: any = {};
        contact.emails.forEach((e: any, i: number) => {
          emailsMap[`email-${i}`] = { address: e.address };
        });

        const phonesMap: any = {};
        contact.phones.forEach((p: any, i: number) => {
          phonesMap[`phone-${i}`] = { number: p.number };
        });

        toCreate[`import-${idx}`] = {
          "@type": "Card",
          "version": "1.0",
          uid: `urn:uuid:${crypto.randomUUID()}`,
          kind: "individual",
          name: {
            components: [
              ...(names[0] ? [{ kind: "given", value: names[0] }] : []),
              ...(names.slice(1).join(" ") ? [{ kind: "surname", value: names.slice(1).join(" ") }] : [])
            ]
          },
          ...(Object.keys(emailsMap).length > 0 ? { emails: emailsMap } : {}),
          ...(Object.keys(phonesMap).length > 0 ? { phones: phonesMap } : {}),
          ...(contact.company ? {
            organizations: {
              "org-1": { name: contact.company }
            }
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

  async getEvents(start: string, end: string): Promise<Event[]> {
    const calendarAccountId = "p";
    const caps = ["urn:ietf:params:jmap:core", "urn:ietf:params:jmap:calendars", "urn:ietf:params:jmap:principals"];

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

      if (data.methodResponses[1] && data.methodResponses[1][1].list) {
        return data.methodResponses[1][1].list;
      }
      return [];
    } catch (err) {
      console.error("Failed to fetch events", err);
      // Fallback
      const data = await this.call([
        ["CalendarEvent/get", { accountId: calendarAccountId, ids: null }, "0"]
      ], caps);
      
      if (data.methodResponses[0] && data.methodResponses[0][1].list) {
        return data.methodResponses[0][1].list;
      }
      return [];
    }
  }

  async createEvent(event: any): Promise<void> {
    const calendarAccountId = "p";
    const caps = ["urn:ietf:params:jmap:core", "urn:ietf:params:jmap:calendars", "urn:ietf:params:jmap:principals"];
    
    // Get calendar ID first
    const calData = await this.call([
      ["Calendar/get", { accountId: calendarAccountId, ids: null }, "0"]
    ], caps);
    
    let calendarId = null;
    if (calData.methodResponses[0] && calData.methodResponses[0][1].list && calData.methodResponses[0][1].list.length > 0) {
      calendarId = calData.methodResponses[0][1].list[0].id;
    }

    if (!calendarId) {
      throw new Error("No calendar found to add event to");
    }

    const res = await this.call([
      ["CalendarEvent/set", {
        accountId: calendarAccountId,
        create: {
          "new-event": {
            "@type": "jscalendar",
            calendarId: calendarId,
            title: event.title,
            description: event.description,
            start: event.start,
            duration: "PT1H", // Simple default 1 hour duration
            locations: event.location ? { "loc-1": { name: event.location } } : undefined
          }
        }
      }, "0"]
    ], caps);

    const methodResponse = res.methodResponses?.[0];
    if (!methodResponse) throw new Error("No response from server");

    const [name, response] = methodResponse;
    if (name === "error") {
      throw new Error(`JMAP Error: ${response.type} ${response.description || ""}`);
    }
  }

  async deleteEvent(eventId: string): Promise<void> {
    const calendarAccountId = "p";
    const caps = ["urn:ietf:params:jmap:core", "urn:ietf:params:jmap:calendars", "urn:ietf:params:jmap:principals"];
    
    await this.call([
      ["CalendarEvent/set", {
        accountId: calendarAccountId,
        destroy: [eventId]
      }, "0"]
    ], caps);
  }
}
