export type Mailbox = {
  id: string;
  name: string;
  unread: number;
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
  name?: any;
  email?: string;
  emails?: any;
  phone?: string;
  phones?: any;
  company?: string;
  organizations?: any;
};

export type Event = {
  id: string;
  title?: string;
  description?: string;
  start?: string;
  end?: string;
  location?: string;
};

export type Account = {
  serverUrl: string;
  username: string;
  password?: string;
  token?: string;
  apiUrl: string;
  accountId: string;
  primaryAccounts: Record<string, string>;
  capabilities: string[];
};
