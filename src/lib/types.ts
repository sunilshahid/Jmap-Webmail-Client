export type Mailbox = {
  id: string;
  name: string;
  unread: number;
  totalEmails?: number;
  icon: string;
  role?: string;
};

export type Email = {
  id: string;
  mailboxId: string;
  from: { name: string; email: string };
  to: { name: string; email: string }[];
  subject: string;
  preview: string;
  body: string;
  date: string;
  read: boolean;
  starred: boolean;
  unsubscribeUrl?: string;
  headers?: { name: string; value: string }[];
  attachments?: any[];
  keywords?: Record<string, boolean>;
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
  recurrenceRules?: any[];
  virtualLocations?: Record<string, any>;
  participants?: Record<string, any>;
  alerts?: Record<string, any>;
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
