export type EmailAddress = {
  name?: string;
  email: string;
};

export type Mailbox = {
  id: string;
  name: string;
  unread: number;
  totalEmails?: number;
  icon: string;
  role?: string;
  parentId?: string | null;
  sortOrder?: number;
  isSubscribed?: boolean;
  totalThreads?: number;
  unreadThreads?: number;
  myRights?: Record<string, boolean>;
  isShared?: boolean;
};

export type Email = {
  id: string;
  mailboxId: string;
  mailboxIds?: Record<string, boolean>;
  threadId?: string;
  blobId?: string;
  size?: number;
  from: { name: string; email: string };
  fromList?: EmailAddress[];
  to: EmailAddress[];
  cc?: EmailAddress[];
  bcc?: EmailAddress[];
  replyTo?: EmailAddress[];
  sender?: EmailAddress[];
  subject: string;
  preview: string;
  body: string;
  date: string;
  sentAt?: string;
  read: boolean;
  starred: boolean;
  hasAttachment?: boolean;
  unsubscribeUrl?: string;
  headers?: { name: string; value: string }[];
  attachments?: any[];
  keywords?: Record<string, boolean>;
  inReplyTo?: string[];
  references?: string[];
  threadEmails?: Email[];
  searchSnippet?: string;
};

export type Thread = {
  id: string;
  emailIds: string[];
};

export type EmailSubmission = {
  id: string;
  identityId: string;
  emailId: string;
  threadId?: string;
  sendAt?: string;
  undoStatus?: "pending" | "final" | "canceled";
  deliveryStatus?: Record<string, any>;
};

export type Quota = {
  id: string;
  name: string;
  resourceType: "count" | "octets";
  used: number;
  limit: number;
  scope: "account" | "domain" | "global";
};

export type EmailSearchFilter = {
  text?: string;
  from?: string;
  to?: string;
  subject?: string;
  body?: string;
  after?: string;
  before?: string;
  hasAttachment?: boolean;
  inMailbox?: string;
  hasKeyword?: string;
};

export type Identity = {
  id: string;
  name: string;
  email: string;
  replyTo?: { name: string; email: string }[];
  bcc?: { name: string; email: string }[];
  textSignature?: string;
  htmlSignature?: string;
};

export type Contact = {
  id: string;
  fullName?: string;
  notes?: string;
  avatar?: string;
  emails?: Record<string, { address: string; contexts?: Record<string, boolean> }>;
  phones?: Record<string, { number: string; contexts?: Record<string, boolean> }>;
  organizations?: Record<string, { name: string; contexts?: Record<string, boolean> }>;
};

export type Calendar = {
  id: string;
  name: string;
  color?: string;
  sortOrder?: number;
  isSubscribed?: boolean;
  isVisible?: boolean;
  isDefault?: boolean;
  myRights?: Record<string, boolean>;
};

export type Participant = {
  "@type": "Participant";
  name?: string;
  email: string;
  roles?: Record<"owner" | "attendee" | "chair", boolean>;
  participationStatus?: "needs-action" | "accepted" | "declined" | "tentative" | "delegated";
  expectReply?: boolean;
  sendTo?: Record<string, string>;
};

export type Event = {
  id: string;
  "@type"?: "Event";
  title: string;
  description?: string;
  start: string;
  duration?: string;
  timeZone?: string;
  location?: string; // used for custom UI, internal JMAP uses locations
  locations?: Record<string, any>;
  calendarId?: string; // deprecated, use calendarIds
  calendarIds?: Record<string, boolean>;
  uid?: string;
  showWithoutTime?: boolean;
  status?: "confirmed" | "cancelled" | "tentative";
  recurrenceRules?: any[];
  recurrenceOverrides?: Record<string, any>;
  virtualLocations?: Record<string, any>;
  participants?: Record<string, Participant | any>;
  alerts?: Record<string, any>;
  sequence?: number;
  priority?: number;
  freeBusyStatus?: "free" | "busy";
  links?: Record<string, any>;
};

export type Account = {
  serverUrl: string;
  username: string;
  password?: string;
  token?: string;
  apiUrl: string;
  accountId: string;
  uploadUrl?: string;
  downloadUrl?: string;
  websocketUrl?: string;
  primaryAccounts: Record<string, string>;
  capabilities: string[];
};
