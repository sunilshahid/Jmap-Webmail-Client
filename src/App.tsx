import React, { useState, useEffect, useCallback, useRef } from "react";
import { 
  Inbox, Send, File, AlertCircle, Trash2, Menu, Search, 
  Settings, User, ChevronDown, Star, Archive, MoreVertical,
  Reply, Forward, X, Edit3, Mail, LogOut, Loader2, Server,
  Calendar, Users, RefreshCw, Lock, Clock, Key, Shield, Plus,
  Sparkles, Download, Upload, Bell, Check, MailCheck
} from "lucide-react";
import { formatDistanceToNow, format } from "date-fns";
import { cn } from "./lib/utils";
import { Toaster, toast } from 'sonner';
import { Mailbox, Email, Identity, Contact, Event, Account } from "./lib/types";
import { JmapClient } from "./lib/jmap-client";
import DOMPurify from 'dompurify';

const iconMap: Record<string, React.ElementType> = {
  Inbox, Send, File, AlertCircle, Trash2,
};

// --- Storage Utilities ---
const STORAGE_KEY = "webmail_accounts";

// Cookie Utilities
const setCookie = (name: string, value: string, days: number = 365) => {
  const expires = new Date(Date.now() + days * 864e5).toUTCString();
  document.cookie = `${name}=${encodeURIComponent(value)}; expires=${expires}; path=/; SameSite=Lax`;
};

const getCookie = (name: string) => {
  return document.cookie.split('; ').reduce((r, v) => {
    const parts = v.split('=');
    return parts[0] === name ? decodeURIComponent(parts[1]) : r;
  }, '');
};

// --- Encryption Utilities ---
async function deriveKey(password: string, salt: Uint8Array) {
  const encoder = new TextEncoder();
  const baseKey = await crypto.subtle.importKey(
    "raw",
    encoder.encode(password),
    "PBKDF2",
    false,
    ["deriveKey"]
  );
  return crypto.subtle.deriveKey(
    {
      name: "PBKDF2",
      salt,
      iterations: 100000,
      hash: "SHA-256",
    },
    baseKey,
    { name: "AES-GCM", length: 256 },
    true,
    ["encrypt", "decrypt"]
  );
}

async function encryptData(data: string, password: string) {
  const encoder = new TextEncoder();
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const key = await deriveKey(password, salt);
  const encrypted = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv },
    key,
    encoder.encode(data)
  );
  return {
    encryptedPayload: btoa(String.fromCharCode(...new Uint8Array(encrypted))),
    iv: btoa(String.fromCharCode(...iv)),
    salt: btoa(String.fromCharCode(...salt)),
  };
}

async function decryptData(encryptedPayload: string, iv: string, salt: string, password: string) {
  const decoder = new TextDecoder();
  const saltArr = new Uint8Array(atob(salt).split("").map(c => c.charCodeAt(0)));
  const ivArr = new Uint8Array(atob(iv).split("").map(c => c.charCodeAt(0)));
  const encryptedArr = new Uint8Array(atob(encryptedPayload).split("").map(c => c.charCodeAt(0)));
  const key = await deriveKey(password, saltArr);
  const decrypted = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv: ivArr },
    key,
    encryptedArr
  );
  return decoder.decode(decrypted);
}

function SecurePortal({ id, initialKey, onBack }: { id: string, initialKey: string | null, onBack: () => void }) {
  const [password, setPassword] = useState(initialKey || "");
  const [decryptedData, setDecryptedData] = useState<{ subject: string, body: string } | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [isDecrypting, setIsDecrypting] = useState(false);
  
  // THE FIX: Create a mutable lock that survives re-renders
  const autoDecryptAttempted = useRef(false);

  const handleDecrypt = useCallback(async () => {
    if (!password) return;
    setIsDecrypting(true);
    setError(null);
    try {
      const response = await fetch(`/api/secure-retrieve/${id}`);
      if (!response.ok) {
        if (response.status === 404) throw new Error("Message not found or already burned.");
        throw new Error("Failed to retrieve message.");
      }
      const { encryptedPayload, iv, salt } = await response.json();
      const decryptedText = await decryptData(encryptedPayload, iv, salt, password);
      const data = JSON.parse(decryptedText);
      setDecryptedData(data);
    } catch (e: any) {
      setError(e.message);
    } finally {
      setIsDecrypting(false);
    }
  }, [id, password]);

  useEffect(() => {
    // THE FIX: Only fire if the key exists AND the lock hasn't been triggered
    if (initialKey && !autoDecryptAttempted.current) {
      autoDecryptAttempted.current = true;
      handleDecrypt();
    }
  }, [initialKey, handleDecrypt]);

  return (
    <div className="min-h-screen bg-slate-50 dark:bg-[#020617] flex items-center justify-center p-4">
      <div className="w-full max-w-lg bg-white dark:bg-slate-900 rounded-3xl shadow-2xl border border-slate-200 dark:border-slate-800 overflow-hidden animate-in fade-in zoom-in duration-300">
        <div className="p-8 border-b border-slate-100 dark:border-slate-800 bg-slate-50/50 dark:bg-slate-900/50 flex flex-col items-center text-center">
          <div className="w-16 h-16 bg-indigo-100 dark:bg-indigo-500/20 rounded-2xl flex items-center justify-center mb-4 shadow-inner">
            <Shield className="w-8 h-8 text-indigo-600 dark:text-indigo-400" />
          </div>
          <h1 className="text-2xl font-bold text-slate-900 dark:text-white mb-2">Secure Message Portal</h1>
          <p className="text-slate-500 dark:text-slate-400 text-sm">This message is protected with zero-knowledge encryption.</p>
        </div>

        <div className="p-8">
          {!decryptedData ? (
            <div className="space-y-6">
              <div className="space-y-2">
                <label className="text-sm font-bold text-slate-700 dark:text-slate-300 ml-1">Access Password</label>
                <div className="relative">
                  <Key className="absolute left-4 top-1/2 -translate-y-1/2 w-5 h-5 text-slate-400" />
                  <input 
                    type="password" 
                    value={password}
                    onChange={(e) => setPassword(e.target.value)}
                    placeholder="Enter the decryption key..."
                    className="w-full pl-12 pr-4 py-4 bg-slate-50 dark:bg-slate-800 border border-slate-200 dark:border-slate-700 rounded-2xl outline-none focus:ring-2 focus:ring-indigo-500/20 transition-all dark:text-white"
                  />
                </div>
              </div>

              {error && (
                <div className="p-4 bg-red-50 dark:bg-red-900/20 border border-red-100 dark:border-red-800 rounded-2xl flex items-center gap-3 text-red-600 dark:text-red-400 text-sm">
                  <AlertCircle className="w-5 h-5 shrink-0" />
                  {error}
                </div>
              )}

              <button 
                onClick={handleDecrypt}
                disabled={isDecrypting || !password}
                className="w-full py-4 bg-indigo-600 hover:bg-indigo-700 text-white font-bold rounded-2xl shadow-lg shadow-indigo-500/20 transition-all active:scale-[0.98] disabled:opacity-50 flex items-center justify-center gap-2"
              >
                {isDecrypting ? <Loader2 className="w-5 h-5 animate-spin" /> : <Lock className="w-5 h-5" />}
                Decrypt Message
              </button>
            </div>
          ) : (
            <div className="space-y-6 animate-in fade-in slide-in-from-bottom-4 duration-500">
              <div className="p-6 bg-indigo-50/50 dark:bg-indigo-500/5 rounded-2xl border border-indigo-100 dark:border-indigo-500/20">
                <h2 className="text-xl font-bold text-indigo-900 dark:text-indigo-100 mb-4 flex items-center gap-2">
                  <Sparkles className="w-5 h-5" />
                  {decryptedData.subject}
                </h2>
                <div className="prose dark:prose-invert max-w-none">
                  <p className="text-lg text-slate-700 dark:text-slate-200 leading-relaxed whitespace-pre-wrap">
                    {decryptedData.body}
                  </p>
                </div>
              </div>

              <div className="flex items-center gap-3 p-4 bg-amber-50 dark:bg-amber-900/20 border border-amber-100 dark:border-amber-800 rounded-2xl text-amber-700 dark:text-amber-400 text-xs">
                <AlertCircle className="w-4 h-4 shrink-0" />
                This message has been decrypted locally. If it was marked as "Burn after reading", it has now been deleted from the server.
              </div>
            </div>
          )}
        </div>

        <div className="p-6 bg-slate-50 dark:bg-slate-900/50 border-t border-slate-100 dark:border-slate-800 flex justify-center">
          <button 
            onClick={() => {
              window.history.pushState({}, '', '/');
              onBack();
            }}
            className="text-slate-500 hover:text-slate-800 dark:hover:text-slate-200 text-sm font-medium transition-colors"
          >
            Return to Webmail
          </button>
        </div>
      </div>
    </div>
  );
}

export default function App() {
  // 1. Synchronous Routing State (Prevents the Login Flash)
  const [secureRoute, setSecureRoute] = useState<{id: string, key: string | null} | null>(() => {
    if (typeof window !== 'undefined') {
      const path = window.location.pathname;
      if (path.startsWith('/secure/')) {
        const id = path.split('/secure/')[1];
        const hash = window.location.hash;
        const key = hash.startsWith('#') ? hash.substring(1) : null;
        return { id, key };
      }
    }
    return null;
  });

  // 2. All standard App hooks MUST run before any early returns
  const [accounts, setAccounts] = useState<any[]>([]);
  const [currentAccountIndex, setCurrentAccountIndex] = useState<number>(0);
  const [isAddingAccount, setIsAddingAccount] = useState(false);
  const [isDarkMode, setIsDarkMode] = useState(() => {
    const saved = getCookie("webmail_dark_mode");
    if (saved) return saved === "true";
    return window.matchMedia('(prefers-color-scheme: dark)').matches;
  });
  const [isStorageReady, setIsStorageReady] = useState(false);

  // Load encrypted accounts
  useEffect(() => {
    const loadAccounts = async () => {
      const saved = localStorage.getItem(STORAGE_KEY);
      if (saved) {
        try {
          const parsed = JSON.parse(saved);
          if (parsed) setAccounts(parsed);
        } catch (e) {
          console.error("Failed to load accounts", e);
        }
      }
      
      const savedIndex = localStorage.getItem("webmail_current_index");
      if (savedIndex) setCurrentAccountIndex(parseInt(savedIndex, 10));
      
      setIsStorageReady(true);
    };
    loadAccounts();
  }, []);

  const credentials = accounts[currentAccountIndex] || null;
  const isLoggedIn = isStorageReady && !!credentials && !isAddingAccount;

  const [serverUrl, setServerUrl] = useState("https://mail.example.com");
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [loginError, setLoginError] = useState("");
  const [isLoggingIn, setIsLoggingIn] = useState(false);

  useEffect(() => {
    const root = window.document.documentElement;
    if (isDarkMode) {
      root.classList.add('dark');
    } else {
      root.classList.remove('dark');
    }
    setCookie("webmail_dark_mode", isDarkMode.toString());
  }, [isDarkMode]);

  useEffect(() => {
    if (!isStorageReady) return;
    const saveAccounts = async () => {
      if (accounts.length > 0) {
        localStorage.setItem(STORAGE_KEY, JSON.stringify(accounts));
      } else {
        localStorage.removeItem(STORAGE_KEY);
      }
    };
    saveAccounts();
  }, [accounts, isStorageReady]);

  useEffect(() => {
    if (!isStorageReady) return;
    localStorage.setItem("webmail_current_index", currentAccountIndex.toString());
  }, [currentAccountIndex, isStorageReady]);

  // 3. THE FIX: Early return goes HERE, after ALL hooks are declared
  if (secureRoute) {
    return (
      <SecurePortal 
        id={secureRoute.id} 
        initialKey={secureRoute.key} 
        onBack={() => {
          window.history.pushState({}, '', '/');
          setSecureRoute(null);
        }} 
      />
    );
  }

  const handleLogin = async (e: React.FormEvent) => {
    e.preventDefault();
    setIsLoggingIn(true);
    setLoginError("");
    try {
      const newAccount = await JmapClient.createSession(serverUrl, username, password);
      
      // Check if account already exists
      const existingIndex = accounts.findIndex(a => a.username === username && a.serverUrl === serverUrl);
      if (existingIndex >= 0) {
        const updatedAccounts = [...accounts];
        updatedAccounts[existingIndex] = newAccount;
        setAccounts(updatedAccounts);
        setCurrentAccountIndex(existingIndex);
      } else {
        setAccounts([...accounts, newAccount]);
        setCurrentAccountIndex(accounts.length);
      }
      
      setIsAddingAccount(false);
      setUsername("");
      setPassword("");
    } catch (err: any) {
      setLoginError(err.message);
    } finally {
      setIsLoggingIn(false);
    }
  };

  const handleLogout = () => {
    const updatedAccounts = accounts.filter((_, i) => i !== currentAccountIndex);
    setAccounts(updatedAccounts);
    setCurrentAccountIndex(0);
    if (updatedAccounts.length === 0) {
      setIsAddingAccount(false);
    }
  };

  const handleSwitchAccount = (index: number) => {
    setCurrentAccountIndex(index);
    setIsAddingAccount(false);
  };

  const handleAddAccount = () => {
    setIsAddingAccount(true);
    setLoginError("");
  };

  const handleCancelAddAccount = () => {
    setIsAddingAccount(false);
    setLoginError("");
  };

  // 4. Standard App Rendering
  if (!isLoggedIn || isAddingAccount) {
    return (
      <div className="min-h-screen bg-slate-50 dark:bg-slate-950 flex flex-col justify-center py-12 sm:px-6 lg:px-8 font-sans transition-colors duration-200">
        <div className="absolute top-4 right-4 flex gap-2">
          {accounts.length > 0 && isAddingAccount && (
            <button 
              onClick={handleCancelAddAccount}
              className="p-2 rounded-full bg-white dark:bg-slate-800 text-slate-600 dark:text-slate-300 shadow-sm border border-slate-200 dark:border-slate-700 hover:bg-slate-50 dark:hover:bg-slate-700 transition-colors"
              title="Go Back"
            >
              <X className="w-5 h-5" />
            </button>
          )}
        </div>
        <div className="sm:mx-auto sm:w-full sm:max-w-md">
          <div className="flex justify-center">
            <div className="w-16 h-16 bg-indigo-600 rounded-2xl flex items-center justify-center shadow-lg shadow-indigo-600/20">
              <Mail className="w-8 h-8 text-white" />
            </div>
          </div>
          <h2 className="mt-6 text-center text-3xl font-extrabold text-slate-900 dark:text-white">
            {isAddingAccount ? "Add Another Account" : "Proton-style Webmail"}
          </h2>
          <p className="mt-2 text-center text-sm text-slate-600 dark:text-slate-400">
            Connect to your Stalwart or JMAP-compatible server
          </p>
        </div>

        <div className="mt-8 sm:mx-auto sm:w-full sm:max-w-md">
          <div className="bg-white dark:bg-slate-900 py-8 px-4 shadow-xl sm:rounded-2xl sm:px-10 border border-slate-100 dark:border-slate-800">
            <form className="space-y-6" onSubmit={handleLogin}>
              {loginError && (
                <div className="bg-red-50 dark:bg-red-900/30 border border-red-200 dark:border-red-800 text-red-600 dark:text-red-400 px-4 py-3 rounded-xl text-sm flex items-start gap-3">
                  <AlertCircle className="w-5 h-5 shrink-0 mt-0.5" />
                  <span>{loginError}</span>
                </div>
              )}

              <div>
                <label className="block text-sm font-medium text-slate-700 dark:text-slate-300">
                  Server URL
                </label>
                <div className="mt-1 relative rounded-xl shadow-sm">
                  <div className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none">
                    <Server className="h-5 w-5 text-slate-400" />
                  </div>
                  <input
                    type="url"
                    required
                    value={serverUrl}
                    onChange={(e) => setServerUrl(e.target.value)}
                    className="focus:ring-indigo-500 focus:border-indigo-500 block w-full pl-10 sm:text-sm border-slate-300 dark:border-slate-700 dark:bg-slate-800 dark:text-white rounded-xl py-3 border outline-none transition-colors"
                    placeholder="https://mail.example.com"
                  />
                </div>
              </div>

              <div>
                <label className="block text-sm font-medium text-slate-700 dark:text-slate-300">
                  Username / Email
                </label>
                <div className="mt-1 relative rounded-xl shadow-sm">
                  <div className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none">
                    <User className="h-5 w-5 text-slate-400" />
                  </div>
                  <input
                    type="text"
                    required
                    value={username}
                    onChange={(e) => setUsername(e.target.value)}
                    className="focus:ring-indigo-500 focus:border-indigo-500 block w-full pl-10 sm:text-sm border-slate-300 dark:border-slate-700 dark:bg-slate-800 dark:text-white rounded-xl py-3 border outline-none transition-colors"
                    placeholder="user@example.com"
                  />
                </div>
              </div>

              <div>
                <label className="block text-sm font-medium text-slate-700 dark:text-slate-300">
                  Password
                </label>
                <div className="mt-1">
                  <input
                    type="password"
                    required
                    value={password}
                    onChange={(e) => setPassword(e.target.value)}
                    className="focus:ring-indigo-500 focus:border-indigo-500 block w-full sm:text-sm border-slate-300 dark:border-slate-700 dark:bg-slate-800 dark:text-white rounded-xl py-3 px-3 border outline-none transition-colors"
                    placeholder="••••••••"
                  />
                </div>
              </div>

              <div className="flex flex-col gap-3">
                <button
                  type="submit"
                  disabled={isLoggingIn}
                  className="w-full flex justify-center py-3 px-4 border border-transparent rounded-xl shadow-sm text-sm font-medium text-white bg-indigo-600 hover:bg-indigo-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-indigo-500 disabled:opacity-70 transition-colors"
                >
                  {isLoggingIn ? (
                    <Loader2 className="w-5 h-5 animate-spin" />
                  ) : (
                    isAddingAccount ? "Add Account" : "Sign in"
                  )}
                </button>
                {isAddingAccount && (
                  <button
                    type="button"
                    onClick={handleCancelAddAccount}
                    className="w-full flex justify-center py-3 px-4 border border-slate-200 dark:border-slate-700 rounded-xl shadow-sm text-sm font-medium text-slate-700 dark:text-slate-300 bg-white dark:bg-slate-800 hover:bg-slate-50 dark:hover:bg-slate-700 focus:outline-none transition-colors"
                  >
                    Cancel
                  </button>
                )}
              </div>
            </form>
          </div>
        </div>
      </div>
    );
  }

  return (
    <>
      <Toaster position="bottom-right" theme={isDarkMode ? 'dark' : 'light'} />
      <MainApp 
        credentials={credentials} 
        accounts={accounts}
        currentAccountIndex={currentAccountIndex}
        onLogout={handleLogout} 
        onSwitchAccount={handleSwitchAccount}
        onAddAccount={handleAddAccount}
        isDarkMode={isDarkMode}
        setIsDarkMode={setIsDarkMode}
      />
    </>
  );
}

function MainApp({ credentials, accounts, currentAccountIndex, onLogout, onSwitchAccount, onAddAccount, isDarkMode, setIsDarkMode }: any) {
  const [mailboxes, setMailboxes] = useState<Mailbox[]>([]);
  const [emails, setEmails] = useState<Email[]>([]);
  const [contacts, setContacts] = useState<any[]>([]);
  const [calendars, setCalendars] = useState<any[]>([]);
  const [events, setEvents] = useState<any[]>([]);
  const [selectedMailbox, setSelectedMailbox] = useState<string>("");
  const [selectedEmail, setSelectedEmail] = useState<Email | null>(null);
  const [identities, setIdentities] = useState<Identity[]>([]);
  const [selectedIdentityId, setSelectedIdentityId] = useState<string>("");
  const [selectedEmailIds, setSelectedEmailIds] = useState<string[]>([]);
  const [activeApp, setActiveApp] = useState<'mail' | 'contacts' | 'calendar' | 'settings'>('mail');
  const [isSidebarOpen, setIsSidebarOpen] = useState(false);
  const [isComposeOpen, setIsComposeOpen] = useState(false);
  const [contextMenuEmail, setContextMenuEmail] = useState<Email | null>(null);
  const [isEmailActionsOpen, setIsEmailActionsOpen] = useState(false);
  const [isContactModalOpen, setIsContactModalOpen] = useState(false);
  const [isEventModalOpen, setIsEventModalOpen] = useState(false);
  const [isImportModalOpen, setIsImportModalOpen] = useState(false);
  const [importData, setImportData] = useState("");
  const [contactSuggestions, setContactSuggestions] = useState<any[]>([]);
  const [newContact, setNewContact] = useState({ firstName: '', lastName: '', email: '', emailType: 'private', phone: '', phoneType: 'private', organization: '' });
  const [contactErrors, setContactErrors] = useState<Record<string, string>>({});
  const [newEvent, setNewEvent] = useState({ title: '', description: '', location: '', startDate: format(new Date(), 'yyyy-MM-dd'), startTime: '09:00', endDate: format(new Date(), 'yyyy-MM-dd'), endTime: '10:00', timeZone: Intl.DateTimeFormat().resolvedOptions().timeZone });
  const [eventErrors, setEventErrors] = useState<Record<string, string>>({});
  const [contactSearchQuery, setContactSearchQuery] = useState("");
  const [eventSearchQuery, setEventSearchQuery] = useState("");
  const [isSettingsSection, setIsSettingsSection] = useState<'general' | 'account' | 'security' | 'advanced' | 'notifications'>('account');
  const [isHeaderExpanded, setIsHeaderExpanded] = useState(false);
  const [isLoading, setIsLoading] = useState(false);
  const [isSyncing, setIsSyncing] = useState(false);
  const [lastSync, setLastSync] = useState<Date>(new Date());
  const [isAccountMenuOpen, setIsAccountMenuOpen] = useState(false);
  const [isIdentityDropdownOpen, setIsIdentityDropdownOpen] = useState(false);
  const [isSecureMessage, setIsSecureMessage] = useState(false);
  const [expiration, setExpiration] = useState("1day");
  const [isExpirationModalOpen, setIsExpirationModalOpen] = useState(false);
  const [securePassword, setSecurePassword] = useState("");
  const [useAutomaticKey, setUseAutomaticKey] = useState(true);
  const expirationOptions = [
    { label: "5 Minutes", value: "5min" },
    { label: "1 Hour", value: "1hour" },
    { label: "1 Day", value: "1day" },
    { label: "1 Week", value: "1week" },
    { label: "Burn after reading", value: "burn" }
  ];
  const [searchQuery, setSearchQuery] = useState("");
  const [pullDistance, setPullDistance] = useState(0);
  const [isPulling, setIsPulling] = useState(false);
  const [startY, setStartY] = useState(0);

  // Delayed Send State
  const [pendingSend, setPendingSend] = useState<any>(null);
  const [sendTimer, setSendTimer] = useState<NodeJS.Timeout | null>(null);
  const [showUndoPill, setShowUndoPill] = useState(false);
  const [countdown, setCountdown] = useState(5);

  const getAccountColor = (username: string) => {
    const colors = [
      'bg-red-500', 'bg-blue-500', 'bg-green-500', 'bg-yellow-500', 
      'bg-purple-500', 'bg-pink-500', 'bg-indigo-500', 'bg-teal-500'
    ];
    let hash = 0;
    for (let i = 0; i < username.length; i++) {
      hash = username.charCodeAt(i) + ((hash << 5) - hash);
    }
    return colors[Math.abs(hash) % colors.length];
  };

  const handleSetDefaultIdentity = async (identityId: string) => {
    setSelectedIdentityId(identityId);
    toast.success("Default identity updated");
  };

  const sortedIdentities = [...identities].sort((a, b) => {
    if (a.id === selectedIdentityId) return -1;
    if (b.id === selectedIdentityId) return 1;
    return 0;
  });

  const getContactName = (contact: any): string => {
    if (!contact) return "Unknown Contact";
    if (contact.name) {
      if (typeof contact.name === 'string') return contact.name;
      if (contact.name.full) return contact.name.full;
      if (contact.name.components && Array.isArray(contact.name.components)) {
        return contact.name.components.map((c: any) => c.value).join(' ').trim();
      }
    }
    
    // Fallback to email
    if (contact.emails && typeof contact.emails === 'object') {
      const firstEmail = Object.values(contact.emails)[0] as any;
      if (firstEmail && firstEmail.email) return firstEmail.email;
      if (firstEmail && firstEmail.value) return firstEmail.value;
    }
    if (contact.email) return contact.email;
    
    return "Unknown Contact";
  };

  const getContactEmail = (contact: any): string => {
    if (!contact) return "";
    if (typeof contact.email === 'string') return contact.email;
    if (contact.emails && typeof contact.emails === 'object') {
      const firstEmail = Object.values(contact.emails)[0] as any;
      if (firstEmail && firstEmail.email) return firstEmail.email;
      if (firstEmail && firstEmail.value) return firstEmail.value;
    }
    return "";
  };

  const filteredEmails = emails.filter(email => {
    const query = searchQuery.toLowerCase();
    return (
      (email.subject || "").toLowerCase().includes(query) ||
      (email.from?.name || "").toLowerCase().includes(query) ||
      (email.from?.email || "").toLowerCase().includes(query) ||
      (email.body || "").toLowerCase().includes(query)
    );
  });

  const filteredContacts = contacts.filter(contact => {
    const query = searchQuery.toLowerCase();
    return (
      getContactName(contact).toLowerCase().includes(query) ||
      getContactEmail(contact).toLowerCase().includes(query)
    );
  });

  const filteredEvents = events.filter(event => {
    const query = searchQuery.toLowerCase();
    return (
      (event.title || "").toLowerCase().includes(query) ||
      (event.description || "").toLowerCase().includes(query)
    );
  });

  const handleExportContacts = () => {
    if (contacts.length === 0) {
      toast.error("No contacts to export");
      return;
    }

    let vcard = "";
    contacts.forEach(c => {
      vcard += "BEGIN:VCARD\nVERSION:3.0\n";
      vcard += `FN:${c.firstName || ''} ${c.lastName || ''}\n`;
      vcard += `N:${c.lastName || ''};${c.firstName || ''};;;\n`;
      if (c.emails && c.emails.length > 0) {
        c.emails.forEach((e: any) => vcard += `EMAIL;TYPE=INTERNET:${e.address}\n`);
      }
      if (c.phones && c.phones.length > 0) {
        c.phones.forEach((p: any) => vcard += `TEL;TYPE=VOICE:${p.number}\n`);
      }
      if (c.company) vcard += `ORG:${c.company}\n`;
      vcard += "END:VCARD\n";
    });

    const blob = new Blob([vcard], { type: "text/vcard" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = "contacts.vcf";
    a.click();
    URL.revokeObjectURL(url);
    toast.success("Contacts exported successfully");
  };

  const handleImportContacts = async () => {
    if (!importData.trim()) {
      toast.error("Please paste vCard data first");
      return;
    }

    setIsLoading(true);
    try {
      if (!credentials) throw new Error("Not logged in");
      const client = new JmapClient(credentials);
      await client.importContacts(importData);

      toast.success("Contacts imported successfully");
      setIsImportModalOpen(false);
      setImportData("");
      
      // Refresh contacts
      const list = await client.getContacts();
      setContacts(list);
    } catch (error: any) {
      console.error("Failed to import contacts:", error);
      toast.error(`Import failed: ${error.message}`);
    } finally {
      setIsLoading(false);
    }
  };

  const handleCreateContact = async (e: React.FormEvent) => {
    e.preventDefault();
    
    // Validation
    const errors: Record<string, string> = {};
    if (!newContact.firstName.trim()) errors.firstName = "First Name is missing";
    if (!newContact.email.trim()) errors.email = "Email Address is missing";
    
    if (Object.keys(errors).length > 0) {
      setContactErrors(errors);
      toast.error("Please fill in all required fields");
      return;
    }

    setIsLoading(true);
    try {
      if (!credentials) throw new Error("Not logged in");
      const client = new JmapClient(credentials);
      const createdContact = await client.createContact({
        firstName: newContact.firstName,
        lastName: newContact.lastName,
        email: newContact.email,
        emailType: newContact.emailType,
        phone: newContact.phone,
        phoneType: newContact.phoneType,
        organization: newContact.organization
      });

      setContacts(prev => [...prev, createdContact]);
      setIsContactModalOpen(false);
      setNewContact({ firstName: '', lastName: '', email: '', emailType: 'private', phone: '', phoneType: 'private', organization: '' });
      setContactErrors({});
      toast.success("Contact created successfully");
    } catch (error: any) {
      console.error("Failed to create contact:", error);
      toast.error(`Failed to create contact: ${error.message}`);
    } finally {
      setIsLoading(false);
    }
  };

  const handleCreateEvent = async (e: React.FormEvent) => {
    e.preventDefault();
    
    // Validation
    const errors: Record<string, string> = {};
    if (!newEvent.title.trim()) errors.title = "Event title is missing";
    
    if (Object.keys(errors).length > 0) {
      setEventErrors(errors);
      toast.error("Please fill in all required fields");
      return;
    }

    setIsLoading(true);
    try {
      if (!credentials) throw new Error("Not logged in");
      const client = new JmapClient(credentials);
      
      // Get the first calendar ID if not specified
      const calendarId = calendars[0]?.id || "personal";

      const createdEvent = await client.createEvent({
        calendarId,
        title: newEvent.title,
        description: newEvent.description,
        start: `${newEvent.startDate}T${newEvent.startTime}:00`,
        timeZone: newEvent.timeZone
      });

      setEvents(prev => [...prev, createdEvent]);
      setIsEventModalOpen(false);
      setNewEvent({ title: '', description: '', location: '', startDate: format(new Date(), 'yyyy-MM-dd'), startTime: '09:00', endDate: format(new Date(), 'yyyy-MM-dd'), endTime: '10:00', timeZone: Intl.DateTimeFormat().resolvedOptions().timeZone });
      setEventErrors({});
      toast.success("Event created successfully");
    } catch (error: any) {
      console.error("Failed to create event:", error);
      toast.error(`Failed to create event: ${error.message}`);
    } finally {
      setIsLoading(false);
    }
  };

  const handleTouchStart = (e: React.TouchEvent) => {
    if (window.scrollY === 0) {
      setStartY(e.touches[0].pageY);
      setIsPulling(true);
    }
  };

  const handleTouchMove = (e: React.TouchEvent) => {
    if (!isPulling) return;
    const currentY = e.touches[0].pageY;
    const diff = currentY - startY;
    if (diff > 0) {
      setPullDistance(Math.min(diff * 0.5, 80));
    }
  };

  const handleTouchEnd = () => {
    if (pullDistance > 60) {
      syncMail();
    }
    setIsPulling(false);
    setPullDistance(0);
  };

  const handleSwitchAccountAndClose = (index: number) => {
    onSwitchAccount(index);
    setIsAccountMenuOpen(false);
  };

  // Compose State
  const [emailBody, setEmailBody] = useState('');
  const [toAddresses, setToAddresses] = useState<string[]>([]);
  const [toInput, setToInput] = useState('');
  const [subject, setSubject] = useState('');
  const [isSending, setIsSending] = useState(false);
  const [newIdentityName, setNewIdentityName] = useState('');
  const [newIdentityEmail, setNewIdentityEmail] = useState('');

  const handleSendEmail = async () => {
    // Process input addresses
    const processedAddresses = toInput
      .split(',')
      .map(email => email.trim())
      .filter(email => email.length > 0);
    
    if (processedAddresses.length === 0 && toAddresses.length === 0) {
      toast.error("Please enter at least one recipient");
      return;
    }

    const finalToAddresses = processedAddresses.length > 0 ? processedAddresses : toAddresses;                
    
    if (!emailBody && !isSecureMessage) {
      toast.error("Message body cannot be empty");
      return;
    }
    
    // Delayed Send Logic
    if (!pendingSend) {
      const emailData = {
        toAddresses: finalToAddresses,
        subject: subject || "No Subject",
        body: emailBody,
        selectedIdentityId,
        isSecure: isSecureMessage,
        secureConfig: isSecureMessage ? {
          useAutomaticKey,
          securePassword,
          expiration
        } : null
      };
      
      setPendingSend(emailData);
      setShowUndoPill(true);
      setCountdown(5);
      setIsComposeOpen(false); // Close compose modal immediately
      
      const timer = setInterval(() => {
        setCountdown(prev => {
          if (prev <= 1) {
            clearInterval(timer);
            return 0;
          }
          return prev - 1;
        });
      }, 1000);

      const timeout = setTimeout(async () => {
        clearInterval(timer);
        await executeSend(emailData);
        setPendingSend(null);
        setShowUndoPill(false);
      }, 5000);

      setSendTimer(timeout);
      return;
    }
  };

  const handleUndoSend = () => {
    if (sendTimer) {
      clearTimeout(sendTimer);
      setSendTimer(null);
    }
    
    if (pendingSend) {
      // Restore state
      setToAddresses(pendingSend.toAddresses);
      setSubject(pendingSend.subject);
      setEmailBody(pendingSend.finalBody);
      setSelectedIdentityId(pendingSend.selectedIdentityId);
      setIsComposeOpen(true);
    }
    
    setPendingSend(null);
    setShowUndoPill(false);
  };

  const executeSend = async (emailData: any) => {
    setIsSending(true);
    try {
      if (!credentials) throw new Error("Not logged in");
      
      let finalBody = emailData.body;
      let finalSubject = emailData.subject;

      // Handle Secure Message encryption right before sending
      if (emailData.isSecure && emailData.secureConfig) {
        const { useAutomaticKey, securePassword, expiration } = emailData.secureConfig;
        let password = "";
        if (useAutomaticKey) {
          password = Array.from(crypto.getRandomValues(new Uint8Array(16)))
            .map(b => b.toString(16).padStart(2, '0'))
            .join('');
        } else {
          password = securePassword;
          if (!password) throw new Error("Secure password is required");
        }

        const { encryptedPayload, iv, salt } = await encryptData(
          JSON.stringify({ subject: finalSubject, body: finalBody }), 
          password
        );
        
        const response = await fetch('/api/secure-store', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ 
            encryptedPayload, 
            iv, 
            salt, 
            expiration, 
            viewOnce: expiration === 'burn' 
          })
        });
        
        if (!response.ok) throw new Error("Failed to store secure message");
        const { id } = await response.json();
        
        const secureUrl = useAutomaticKey 
          ? `${window.location.origin}/secure/${id}#${password}` 
          : `${window.location.origin}/secure/${id}`;
        
        const expirationText: Record<string, string> = {
          "5min": "5 minutes",
          "1hour": "1 hour",
          "1day": "1 day",
          "1week": "1 week",
          "burn": "after reading"
        };

        finalBody = `You have received a secure message from Sunil Shahid. It will expire in ${expirationText[expiration] || "1 day"}. Link: ${secureUrl}`;
        finalSubject = `🔒 Secure message from Sunil Shahid`;
      }

      // 1. Get Selected Identity
      const identity = identities.find(i => i.id === emailData.selectedIdentityId) || identities[0];
      if (!identity) throw new Error("No identity found to send from");
      const identityId = identity.id;

      // 2. Find Sent Mailbox
      const sentMailbox = mailboxes.find(m => m.role === 'sent') || mailboxes.find(m => m.name.toLowerCase().includes('sent')) || mailboxes[0];
      if (!sentMailbox) throw new Error("No mailbox found to store the sent message");

      // 3. Create and Send Email
      const client = new JmapClient(credentials);
      await client.sendEmail(
        emailData.toAddresses,
        finalSubject,
        finalBody,
        undefined, // cc
        undefined, // bcc
        identityId, // identityId
        identity.email, // <-- THE FIX: Pass the actual email address
        undefined, // draftId
        identity.name // <-- THE FIX: Pass the display name
      );

      toast.success("Email sent successfully!");
      
      // Reset compose state
      setToAddresses([]);
      setToInput('');
      setSubject('');
      setEmailBody('');
      setIsSecureMessage(false);
      setExpiration("1day");
      
      if (selectedMailbox === sentMailbox?.id) {
        fetchEmails(selectedMailbox);
      }
    } catch (err: any) {
      console.error(err);
      toast.error(err.message || "Failed to send email");
    } finally {
      setIsSending(false);
    }
  };

  const fetchMailboxes = useCallback(async () => {
    if (!credentials) return;
    try {
      const client = new JmapClient(credentials);
      const mapped = await client.getMailboxes();
      setMailboxes(mapped);
      if (mapped.length > 0 && !selectedMailbox) {
        setSelectedMailbox(mapped.find((m: any) => m.icon === 'Inbox')?.id || mapped[0].id);
      }
      return mapped;
    } catch (err) {
      console.error("Failed to fetch mailboxes", err);
      throw err;
    }
  }, [credentials, selectedMailbox]);

  useEffect(() => {
    fetchMailboxes();
  }, [fetchMailboxes]);

  // Fetch Identities
  useEffect(() => {
    if (!credentials) return;
    const client = new JmapClient(credentials);
    client.getIdentities().then(list => {
      setIdentities(list);
      if (list.length > 0 && !selectedIdentityId) {
        setSelectedIdentityId(list[0].id);
      }
    }).catch(err => console.error("Failed to fetch identities", err));
  }, [credentials]);

  const handleCreateIdentity = async () => {
    if (!newIdentityName || !newIdentityEmail || !credentials) {
      toast.error("Name and Email are required");
      return;
    }
    try {
      const client = new JmapClient(credentials);
      const list = await client.createIdentity(newIdentityName, newIdentityEmail);
      toast.success("Identity created successfully");
      setNewIdentityName('');
      setNewIdentityEmail('');
      setIdentities(list);
    } catch (err) {
      console.error("Failed to create identity", err);
      toast.error("Failed to create identity. Your server might not support creating identities via JMAP.");
    }
  };

  // Fetch Contacts
  useEffect(() => {
    if (!credentials) return;
    if (credentials.capabilities?.includes("urn:ietf:params:jmap:contacts") || credentials.capabilities?.includes("urn:ietf:params:jmap:jscontact")) {
      const client = new JmapClient(credentials);
      client.getContacts()
        .then(list => setContacts(list))
        .catch(err => console.error("Contact retrieval failed completely", err));
    }
  }, [credentials]);

  // Fetch Calendars and Events
  useEffect(() => {
    if (!credentials) return;
    if (credentials.capabilities?.includes("urn:ietf:params:jmap:calendars") || credentials.capabilities?.includes("urn:ietf:params:jmap:jscalendar")) {
      const client = new JmapClient(credentials);
      const now = new Date();
      const startOfMonth = new Date(now.getFullYear(), now.getMonth(), 1).toISOString();
      const endOfMonth = new Date(now.getFullYear(), now.getMonth() + 1, 0).toISOString();

      client.getEvents(startOfMonth, endOfMonth)
        .then(list => setEvents(list))
        .catch(err => console.error("Event retrieval failed completely", err));
    }
  }, [credentials]);

  // Fetch Emails Function
  const fetchEmails = useCallback(async (mailboxId: string, background = false) => {
    if (!mailboxId || !credentials) return;
    
    if (!background) setIsLoading(true);
    else setIsSyncing(true);

    try {
      const client = new JmapClient(credentials);
      const mapped = await client.getEmails(mailboxId);
      
      setEmails(mapped);
      if (!background) setSelectedEmail(null);
      setLastSync(new Date());
    } catch (err) {
      console.error("Failed to fetch emails", err);
      if (!background) setEmails([]);
    } finally {
      setIsLoading(false);
      setIsSyncing(false);
    }
  }, [credentials]);

  const syncMail = async () => {
    if (isSyncing) return;
    setIsSyncing(true);
    try {
      await fetchMailboxes();
      if (selectedMailbox) {
        await fetchEmails(selectedMailbox, true);
      }
      setLastSync(new Date());
    } catch (err) {
      console.error("Sync failed", err);
    } finally {
      setIsSyncing(false);
    }
  };

  // Initial fetch when mailbox changes
  useEffect(() => {
    fetchEmails(selectedMailbox, false);
  }, [selectedMailbox, fetchEmails]);

  // Polling interval (every 15 seconds)
  useEffect(() => {
    if (!selectedMailbox) return;
    const intervalId = setInterval(() => {
      fetchEmails(selectedMailbox, true);
    }, 15000);
    return () => clearInterval(intervalId);
  }, [selectedMailbox, fetchEmails]);

  const handleEmailClick = (email: Email) => {
    const mailbox = mailboxes.find(m => m.id === email.mailboxId);
    if (mailbox?.role === 'drafts') {
      // Open in compose
      setToAddresses(email.to.map(t => t.email));
      setSubject(email.subject);
      setEmailBody(email.body);
      setIsComposeOpen(true);
      return;
    }

    setSelectedEmail(email);
    if (!email.read) {
      // Mark as read locally
      setEmails((prev) =>
        prev.map((e) => (e.id === email.id ? { ...e, read: true } : e))
      );
      
      setMailboxes((prev) =>
        prev.map((m) => (m.id === email.mailboxId ? { ...m, unread: Math.max(0, m.unread - 1) } : m))
      );
      
      if (credentials) {
        const client = new JmapClient(credentials);
        client.call([
          ["Email/set", {
            accountId: credentials.accountId,
            update: {
              [email.id]: { "keywords/$seen": true }
            }
          }, "0"]
        ]).catch(err => console.error("Failed to mark as read", err));
      }
    }
  };

  const handleUpdateEmailKeywords = async (emailId: string, keywords: Record<string, boolean | null>) => {
    if (!credentials) return;
    const client = new JmapClient(credentials);
    try {
      await client.call([
        ["Email/set", {
          accountId: credentials.accountId,
          update: {
            [emailId]: { keywords }
          }
        }, "0"]
      ]);
      // Update local state
      setEmails(prev => prev.map(e => {
        if (e.id === emailId) {
          const newKeywords = { ...(e as any).keywords, ...keywords };
          // Clean up nulls
          Object.keys(newKeywords).forEach(k => {
            if (newKeywords[k] === null) delete newKeywords[k];
          });
          return { 
            ...e, 
            read: !newKeywords["$seen"],
            starred: !!newKeywords["$flagged"],
            keywords: newKeywords
          };
        }
        return e;
      }));
      if (selectedEmail?.id === emailId) {
        setSelectedEmail(prev => prev ? { 
          ...prev, 
          read: !keywords["$seen"] !== undefined ? !keywords["$seen"] : prev.read,
          starred: keywords["$flagged"] !== undefined ? !!keywords["$flagged"] : prev.starred
        } : null);
      }
    } catch (err) {
      toast.error("Failed to update email");
      console.error(err);
    }
  };

  const handleMoveEmail = async (emailId: string, targetMailboxRole: string) => {
    if (!credentials) return;
    const targetMailbox = mailboxes.find(m => m.role === targetMailboxRole) || mailboxes.find(m => m.name.toLowerCase().includes(targetMailboxRole));
    if (!targetMailbox) {
      toast.error(`Target mailbox ${targetMailboxRole} not found`);
      return;
    }

    const client = new JmapClient(credentials);
    try {
      await client.call([
        ["Email/set", {
          accountId: credentials.accountId,
          update: {
            [emailId]: { mailboxIds: { [targetMailbox.id]: true } }
          }
        }, "0"]
      ]);
      // Remove from local list
      setEmails(prev => prev.filter(e => e.id !== emailId));
      if (selectedEmail?.id === emailId) {
        setSelectedEmail(null);
      }
      toast.success(`Moved to ${targetMailbox.name}`);
      // Update unread counts
      fetchMailboxes();
    } catch (err) {
      toast.error("Failed to move email");
      console.error(err);
    }
  };

  const handleDeleteEmail = async (emailId: string) => {
    const trashMailbox = mailboxes.find(m => m.role === 'trash');
    const currentMailbox = mailboxes.find(m => m.id === selectedMailbox);
    
    if (currentMailbox?.role === 'trash') {
      // Permanent delete
      if (!credentials) return;
      const client = new JmapClient(credentials);
      try {
        await client.call([
          ["Email/set", {
            accountId: credentials.accountId,
            destroy: [emailId]
          }, "0"]
        ]);
        setEmails(prev => prev.filter(e => e.id !== emailId));
        if (selectedEmail?.id === emailId) setSelectedEmail(null);
        toast.success("Permanently deleted");
      } catch (err) {
        toast.error("Failed to delete email");
      }
    } else {
      handleMoveEmail(emailId, 'trash');
    }
  };

  const handleArchiveEmail = (emailId: string) => handleMoveEmail(emailId, 'archive');
  const handleToggleStar = (email: Email) => handleUpdateEmailKeywords(email.id, { "$flagged": !email.starred });
  const handleBulkUpdateEmailKeywords = async (emailIds: string[], keywords: Record<string, boolean | null>) => {
    if (!credentials || emailIds.length === 0) return;
    const client = new JmapClient(credentials);
    try {
      const update: Record<string, any> = {};
      emailIds.forEach(id => {
        update[id] = { keywords };
      });

      await client.call([
        ["Email/set", {
          accountId: credentials.accountId,
          update
        }, "0"]
      ]);

      // Update local state
      setEmails(prev => prev.map(e => {
        if (emailIds.includes(e.id)) {
          const newKeywords = { ...(e as any).keywords, ...keywords };
          Object.keys(newKeywords).forEach(k => {
            if (newKeywords[k] === null) delete newKeywords[k];
          });
          return { 
            ...e, 
            read: !!newKeywords["$seen"],
            starred: !!newKeywords["$flagged"],
            keywords: newKeywords
          };
        }
        return e;
      }));
      
      setSelectedEmailIds([]);
      toast.success(`Updated ${emailIds.length} messages`);
      fetchMailboxes();
    } catch (err) {
      toast.error("Failed to update messages");
      console.error(err);
    }
  };

  const handleBulkMoveEmail = async (emailIds: string[], targetMailboxRole: string) => {
    if (!credentials || emailIds.length === 0) return;
    const targetMailbox = mailboxes.find(m => m.role === targetMailboxRole) || mailboxes.find(m => m.name.toLowerCase().includes(targetMailboxRole));
    if (!targetMailbox) {
      toast.error(`Target mailbox ${targetMailboxRole} not found`);
      return;
    }

    const client = new JmapClient(credentials);
    try {
      const update: Record<string, any> = {};
      emailIds.forEach(id => {
        update[id] = { mailboxIds: { [targetMailbox.id]: true } };
      });

      await client.call([
        ["Email/set", {
          accountId: credentials.accountId,
          update
        }, "0"]
      ]);

      // Remove from local list
      setEmails(prev => prev.filter(e => !emailIds.includes(e.id)));
      if (selectedEmail && emailIds.includes(selectedEmail.id)) {
        setSelectedEmail(null);
      }
      setSelectedEmailIds([]);
      toast.success(`Moved ${emailIds.length} messages to ${targetMailbox.name}`);
      fetchMailboxes();
    } catch (err) {
      toast.error("Failed to move messages");
      console.error(err);
    }
  };

  const handleBulkDelete = async (emailIds: string[]) => {
    const currentMailbox = mailboxes.find(m => m.id === selectedMailbox);
    if (currentMailbox?.role === 'trash') {
      if (!credentials) return;
      const client = new JmapClient(credentials);
      try {
        await client.call([
          ["Email/set", {
            accountId: credentials.accountId,
            destroy: emailIds
          }, "0"]
        ]);
        setEmails(prev => prev.filter(e => !emailIds.includes(e.id)));
        if (selectedEmail && emailIds.includes(selectedEmail.id)) {
          setSelectedEmail(null);
        }
        setSelectedEmailIds([]);
        toast.success(`Permanently deleted ${emailIds.length} messages`);
        fetchMailboxes();
      } catch (err) {
        toast.error("Failed to delete messages");
      }
    } else {
      handleBulkMoveEmail(emailIds, 'trash');
    }
  };

  const handleToggleEmailSelection = (emailId: string) => {
    setSelectedEmailIds(prev => 
      prev.includes(emailId) ? prev.filter(id => id !== emailId) : [...prev, emailId]
    );
  };

  const handleSelectAllEmails = () => {
    if (selectedEmailIds.length === filteredEmails.length) {
      setSelectedEmailIds([]);
    } else {
      setSelectedEmailIds(filteredEmails.map(e => e.id));
    }
  };

  const handleMarkAsRead = (emailId: string) => handleUpdateEmailKeywords(emailId, { "$seen": true });
  const handleMarkAsUnread = (emailId: string) => handleUpdateEmailKeywords(emailId, { "$seen": null });
  const handleMoveToJunk = (emailId: string) => handleMoveEmail(emailId, 'junk');
  const handleMoveToInbox = (emailId: string) => handleMoveEmail(emailId, 'inbox');

  return (
    <div className="flex h-screen w-full bg-slate-50 dark:bg-black text-slate-900 dark:text-slate-100 overflow-hidden font-sans transition-colors duration-200 selection:bg-indigo-100 dark:selection:bg-indigo-500/30">
      {/* Mobile Sidebar Overlay */}
      {isSidebarOpen && (
        <div 
          className="fixed inset-0 bg-black/40 dark:bg-black/60 z-40 md:hidden backdrop-blur-md transition-opacity"
          onClick={() => setIsSidebarOpen(false)}
        />
      )}

      {/* Sidebar */}
      <aside
        className={cn(
          "fixed md:static inset-y-0 left-0 z-50 w-64 bg-slate-100 dark:bg-[#0f172a] border-r border-slate-200 dark:border-slate-800/50 transition-transform duration-300 ease-in-out flex flex-col",
          !isSidebarOpen ? "-translate-x-full md:translate-x-0" : "translate-x-0"
        )}
      >
        <div className="flex items-center justify-between h-16 px-4 border-b border-slate-200 dark:border-slate-800/50">
          <div className="flex items-center gap-2 font-bold text-lg text-slate-800 dark:text-white">
            <div className="w-8 h-8 bg-indigo-600 rounded-lg flex items-center justify-center shadow-sm">
              <Mail className="w-5 h-5 text-white" />
            </div>
            <span>Webmail</span>
          </div>
          <button 
            className="md:hidden p-1.5 hover:bg-slate-200 dark:hover:bg-slate-800 rounded-lg text-slate-500 dark:text-slate-400 transition-colors"
            onClick={() => setIsSidebarOpen(false)}
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        <nav className="flex-1 overflow-y-auto py-2 flex flex-col">
          <div className="px-4 mb-2 text-xs font-bold text-slate-400 dark:text-slate-500 uppercase tracking-wider">
            Folders
          </div>
          <ul className="space-y-1 px-3 mb-6">
            {mailboxes.map((mb) => {
              const Icon = iconMap[mb.icon] || Mail;
              const isSelected = selectedMailbox === mb.id;
              return (
                <li key={mb.id}>
                  <button
                    onClick={() => {
                      setActiveApp('mail');
                      setSelectedMailbox(mb.id);
                      setIsSidebarOpen(false);
                    }}
                    className={cn(
                      "w-full flex items-center justify-between px-3 py-2 rounded-lg text-sm font-medium transition-all",
                      isSelected && activeApp === 'mail'
                        ? "bg-indigo-100 dark:bg-indigo-500/15 text-indigo-700 dark:text-indigo-300"
                        : "text-slate-600 dark:text-slate-300 hover:bg-slate-200/50 dark:hover:bg-slate-800/50"
                    )}
                  >
                    <div className="flex items-center gap-3">
                      <Icon className={cn("w-4 h-4", isSelected ? "text-indigo-600 dark:text-indigo-400" : "text-slate-400 dark:text-slate-500")} />
                      {mb.name}
                    </div>
                    {mb.unread > 0 && (
                      <span className={cn(
                        "text-xs py-0.5 px-2 rounded-full font-bold",
                        isSelected 
                          ? "bg-indigo-200 dark:bg-indigo-500/30 text-indigo-800 dark:text-indigo-200" 
                          : "bg-slate-200 dark:bg-slate-800 text-slate-600 dark:text-slate-300"
                      )}>
                        {mb.unread}
                      </span>
                    )}
                  </button>
                </li>
              );
            })}
          </ul>

          <div className="px-4 mb-2 text-xs font-bold text-slate-400 dark:text-slate-500 uppercase tracking-wider">
            Apps
          </div>
          <ul className="space-y-1 px-3">
            {[
              { id: 'mail', name: 'Mail', icon: Mail },
              { id: 'contacts', name: 'Contacts', icon: Users },
              { id: 'calendar', name: 'Calendar', icon: Calendar },
              { id: 'settings', name: 'Settings', icon: Settings },
            ].map((app) => {
              const Icon = app.icon;
              const isSelected = activeApp === app.id;
              return (
                <li key={app.id}>
                  <button 
                    onClick={() => { setActiveApp(app.id as any); setIsSidebarOpen(false); }}
                    className={cn(
                      "w-full flex items-center gap-3 px-3 py-2 rounded-lg text-sm font-medium transition-all duration-200",
                      isSelected 
                        ? "bg-indigo-600 text-white shadow-md shadow-indigo-500/20" 
                        : "text-slate-600 dark:text-slate-400 hover:bg-slate-200/50 dark:hover:bg-slate-800/50 hover:text-slate-900 dark:hover:text-white"
                    )}
                  >
                    <Icon className={cn("w-4 h-4", isSelected ? "text-white" : "text-slate-400 dark:text-slate-500")} />
                    {app.name}
                  </button>
                </li>
              );
            })}
          </ul>
        </nav>

        <div className="p-4 border-t border-slate-200 dark:border-slate-800/50">
          <div className="flex items-center gap-3 w-full px-2 py-2 text-sm font-medium rounded-lg">
            <div className={cn("w-8 h-8 rounded-full flex items-center justify-center text-white shrink-0 font-bold", getAccountColor(credentials.username))}>
              {credentials.username.charAt(0).toUpperCase()}
            </div>
            <div className="flex-1 text-left overflow-hidden">
              <div className="text-slate-900 dark:text-white truncate font-semibold">{credentials.username}</div>
              <div className="text-xs text-slate-500 dark:text-slate-400 truncate">{credentials.serverUrl}</div>
            </div>
            <button 
              onClick={onLogout}
              className="p-2 text-slate-400 hover:text-red-600 dark:hover:text-red-400 hover:bg-red-50 dark:hover:bg-red-900/20 rounded-lg transition-colors"
              title="Sign out"
            >
              <LogOut className="w-4 h-4" />
            </button>
          </div>
        </div>
      </aside>

      {/* Main Content */}
      <main className="flex-1 flex flex-col min-w-0 bg-white dark:bg-black">
        {/* Header */}
        <header className="h-16 border-b border-slate-200 dark:border-slate-800 flex items-center justify-between px-4 bg-white dark:bg-black shrink-0 gap-4">
          <div className="flex items-center gap-4 flex-1">
            <button
              className="md:hidden p-2 -ml-2 text-slate-500 dark:text-slate-400 hover:bg-slate-100 dark:hover:bg-slate-800 rounded-lg transition-colors"
              onClick={() => setIsSidebarOpen(true)}
            >
              <Menu className="w-5 h-5" />
            </button>
            <div className="relative max-w-2xl w-full">
              <div className="absolute left-3 top-1/2 -translate-y-1/2 flex items-center gap-2 pointer-events-none">
                <Search className="w-5 h-5 text-slate-400" />
              </div>
              <input
                type="text"
                placeholder={
                  activeApp === 'contacts' 
                    ? "Search contacts..." 
                    : activeApp === 'calendar' 
                      ? "Search events..." 
                      : "Search in mail"
                }
                value={
                  activeApp === 'contacts' 
                    ? contactSearchQuery 
                    : activeApp === 'calendar' 
                      ? eventSearchQuery 
                      : searchQuery
                }
                onChange={(e) => {
                  const val = e.target.value;
                  if (activeApp === 'contacts') setContactSearchQuery(val);
                  else if (activeApp === 'calendar') setEventSearchQuery(val);
                  else setSearchQuery(val);
                }}
                className="w-full pl-11 pr-12 py-2.5 bg-slate-100 dark:bg-slate-900 border-transparent focus:bg-white dark:focus:bg-slate-800 focus:border-transparent focus:ring-4 focus:ring-indigo-500/10 dark:focus:ring-indigo-500/20 rounded-full text-base outline-none transition-all dark:text-white shadow-sm"
              />
              {(activeApp === 'contacts' ? contactSearchQuery : activeApp === 'calendar' ? eventSearchQuery : searchQuery) && (
                <button 
                  onClick={() => {
                    if (activeApp === 'contacts') setContactSearchQuery("");
                    else if (activeApp === 'calendar') setEventSearchQuery("");
                    else setSearchQuery("");
                  }}
                  className="absolute right-12 top-1/2 -translate-y-1/2 p-1.5 text-slate-400 hover:text-slate-600 dark:hover:text-slate-200 hover:bg-slate-200 dark:hover:bg-slate-700 rounded-full transition-colors"
                >
                  <X className="w-4 h-4" />
                </button>
              )}
              <div className="absolute right-3 top-1/2 -translate-y-1/2 flex items-center gap-2 pointer-events-none">
                <Sparkles className="w-5 h-5 text-indigo-500" />
              </div>
            </div>
          </div>
            <div className="flex items-center gap-2 relative">
              <div className="flex items-center gap-2 mr-4 text-xs text-slate-400 dark:text-slate-500">
                {isSyncing ? (
                  <RefreshCw className="w-3 h-3 animate-spin" />
                ) : (
                  <div className="hidden sm:block">Updated {formatDistanceToNow(lastSync, { addSuffix: true })}</div>
                )}
              </div>
              
              {/* Account Switcher */}
              <div className="relative ml-2">
                <button 
                  onClick={() => setIsAccountMenuOpen(!isAccountMenuOpen)}
                  className={cn(
                    "w-9 h-9 rounded-full flex items-center justify-center text-white font-bold shadow-sm transition-transform active:scale-95",
                    getAccountColor(credentials.username)
                  )}
                >
                  {credentials.username.charAt(0).toUpperCase()}
                </button>
                
                {isAccountMenuOpen && (
                  <>
                    <div 
                      className="fixed inset-0 z-40" 
                      onClick={() => setIsAccountMenuOpen(false)}
                    />
                    <div className="absolute right-0 mt-2 w-72 bg-white dark:bg-slate-900 rounded-2xl shadow-2xl border border-slate-200 dark:border-slate-800 z-50 py-3 animate-in fade-in zoom-in-95 duration-150">
                      <div className="px-5 py-3 border-b border-slate-100 dark:border-slate-800 mb-2">
                        <div className="flex items-center gap-3">
                          <div className={cn(
                            "w-12 h-12 rounded-full flex items-center justify-center text-white font-bold text-xl",
                            getAccountColor(credentials.username)
                          )}>
                            {credentials.username.charAt(0).toUpperCase()}
                          </div>
                          <div className="overflow-hidden">
                            <div className="font-bold text-slate-900 dark:text-white truncate">{credentials.username}</div>
                            <div className="text-xs text-slate-500 truncate">{credentials.serverUrl}</div>
                          </div>
                        </div>
                      </div>
                      
                      <div className="max-h-[300px] overflow-y-auto">
                        {accounts.map((acc: any, idx: number) => (
                          idx !== currentAccountIndex && (
                            <button
                              key={idx}
                              onClick={() => handleSwitchAccountAndClose(idx)}
                              className="w-full px-5 py-3 flex items-center gap-3 hover:bg-slate-50 dark:hover:bg-slate-800 transition-colors text-left"
                            >
                              <div className={cn(
                                "w-8 h-8 rounded-full flex items-center justify-center text-white font-bold text-sm",
                                getAccountColor(acc.username)
                              )}>
                                {acc.username.charAt(0).toUpperCase()}
                              </div>
                              <div className="overflow-hidden">
                                <div className="text-sm font-semibold text-slate-700 dark:text-slate-200 truncate">{acc.username}</div>
                                <div className="text-[10px] text-slate-500 truncate">{acc.serverUrl}</div>
                              </div>
                            </button>
                          )
                        ))}
                      </div>
                      
                      <div className="mt-2 pt-2 border-t border-slate-100 dark:border-slate-800 px-2">
                        <button 
                          onClick={() => { onAddAccount(); setIsAccountMenuOpen(false); }}
                          className="w-full flex items-center gap-3 px-3 py-2.5 rounded-xl text-sm font-medium text-slate-700 dark:text-slate-300 hover:bg-slate-50 dark:hover:bg-slate-800 transition-colors"
                        >
                          <Plus className="w-4 h-4" /> Add another account
                        </button>
                        <button 
                          onClick={() => { onLogout(); setIsAccountMenuOpen(false); }}
                          className="w-full flex items-center gap-3 px-3 py-2.5 rounded-xl text-sm font-medium text-red-600 dark:text-red-400 hover:bg-red-50 dark:hover:bg-red-900/20 transition-colors"
                        >
                          <LogOut className="w-4 h-4" /> Sign out
                        </button>
                      </div>
                    </div>
                  </>
                )}
              </div>
            </div>
        </header>

        {/* Content Area */}
        <div className="flex-1 flex overflow-hidden min-w-0">
          {activeApp === 'mail' && (
            <>
              {/* Email List */}
              <div
                className={cn(
                  "w-full md:w-[350px] lg:w-[420px] border-r border-slate-200 dark:border-slate-800 flex flex-col bg-white dark:bg-black shrink-0 overflow-hidden",
                  selectedEmail ? "hidden md:flex" : "flex"
                )}
              >
                <div 
                  className="flex-1 overflow-y-auto relative"
                  onTouchStart={handleTouchStart}
                  onTouchMove={handleTouchMove}
                  onTouchEnd={handleTouchEnd}
                >
                  {/* Sticky Header */}
                  <div className="sticky top-0 z-20 border-b border-slate-200 dark:border-slate-800 bg-white/80 dark:bg-black/80 backdrop-blur-md">
                    {selectedEmailIds.length > 0 ? (
                      <div className="p-3 flex items-center justify-between animate-in fade-in slide-in-from-top-2 duration-200">
                        <div className="flex items-center gap-3">
                          <button 
                            onClick={handleSelectAllEmails}
                            className="p-1.5 hover:bg-slate-100 dark:hover:bg-slate-800 rounded-md transition-colors"
                          >
                            <div className={cn(
                              "w-4 h-4 border rounded flex items-center justify-center transition-colors",
                              selectedEmailIds.length === filteredEmails.length 
                                ? "bg-indigo-600 border-indigo-600" 
                                : "border-slate-300 dark:border-slate-600"
                            )}>
                              {selectedEmailIds.length === filteredEmails.length && <Check className="w-3 h-3 text-white" />}
                              {selectedEmailIds.length > 0 && selectedEmailIds.length < filteredEmails.length && <div className="w-2 h-0.5 bg-indigo-600" />}
                            </div>
                          </button>
                          <span className="text-sm font-bold text-indigo-600 dark:text-indigo-400">
                            {selectedEmailIds.length} selected
                          </span>
                        </div>
                        <div className="flex items-center gap-1">
                          <button 
                            onClick={() => handleBulkUpdateEmailKeywords(selectedEmailIds, { "$seen": true })}
                            className="p-2 text-slate-500 dark:text-slate-400 hover:text-indigo-600 dark:hover:text-indigo-400 hover:bg-indigo-50 dark:hover:bg-indigo-900/20 rounded-lg transition-colors"
                            title="Mark as read"
                          >
                            <Mail className="w-4 h-4" />
                          </button>
                          <button 
                            onClick={() => handleBulkUpdateEmailKeywords(selectedEmailIds, { "$seen": null })}
                            className="p-2 text-slate-500 dark:text-slate-400 hover:text-indigo-600 dark:hover:text-indigo-400 hover:bg-indigo-50 dark:hover:bg-indigo-900/20 rounded-lg transition-colors"
                            title="Mark as unread"
                          >
                            <Shield className="w-4 h-4" />
                          </button>
                          <button 
                            onClick={() => handleBulkMoveEmail(selectedEmailIds, 'archive')}
                            className="p-2 text-slate-500 dark:text-slate-400 hover:text-slate-700 dark:hover:text-slate-200 hover:bg-slate-100 dark:hover:bg-slate-800 rounded-lg transition-colors"
                            title="Archive"
                          >
                            <Archive className="w-4 h-4" />
                          </button>
                          <button 
                            onClick={() => handleBulkDelete(selectedEmailIds)}
                            className="p-2 text-slate-500 dark:text-slate-400 hover:text-red-600 dark:hover:text-red-400 hover:bg-red-50 dark:hover:bg-red-900/20 rounded-lg transition-colors"
                            title="Delete"
                          >
                            <Trash2 className="w-4 h-4" />
                          </button>
                          <button 
                            onClick={() => setSelectedEmailIds([])}
                            className="p-2 text-slate-500 dark:text-slate-400 hover:text-slate-700 dark:hover:text-slate-200 hover:bg-slate-100 dark:hover:bg-slate-800 rounded-lg transition-colors"
                            title="Cancel"
                          >
                            <X className="w-4 h-4" />
                          </button>
                        </div>
                      </div>
                    ) : (
                      <div className="p-4 flex items-center justify-between">
                        <div className="flex flex-col">
                          <h2 className="font-bold text-lg text-slate-800 dark:text-white">
                            {mailboxes.find((m) => m.id === selectedMailbox)?.name || "Loading..."}
                          </h2>
                          <span className="text-[10px] text-slate-500 dark:text-slate-400 font-medium">
                            {filteredEmails.length} messages
                          </span>
                        </div>
                        <div className="flex items-center gap-1">
                          <button 
                            onClick={() => handleBulkUpdateEmailKeywords(filteredEmails.filter(e => !e.read).map(e => e.id), { "$seen": true })}
                            className="p-1.5 text-slate-400 hover:text-indigo-600 dark:hover:text-indigo-400 hover:bg-indigo-50 dark:hover:bg-indigo-900/20 rounded-lg transition-colors"
                            title="Mark all as read"
                          >
                            <MailCheck className="w-4 h-4" />
                          </button>
                        </div>
                      </div>
                    )}
                    {/* Swipe indicator */}
                    <div className="absolute bottom-0 left-1/2 -translate-x-1/2 w-8 h-1 bg-slate-200 dark:bg-slate-800 rounded-full mb-0.5 opacity-40" />
                  </div>

                  {pullDistance > 0 && (
                    <div 
                      className="absolute top-0 left-0 right-0 flex justify-center items-center overflow-hidden transition-all duration-200 z-10"
                      style={{ height: `${pullDistance}px` }}
                    >
                      <RefreshCw className={cn("w-5 h-5 text-indigo-500", pullDistance > 60 ? "animate-spin" : "")} />
                    </div>
                  )}
                  {isLoading ? (
                    <div className="p-8 flex justify-center">
                      <Loader2 className="w-6 h-6 text-indigo-500 animate-spin" />
                    </div>
                  ) : filteredEmails.length === 0 ? (
                    <div className="p-12 text-center text-slate-500 dark:text-slate-400">
                      <div className="w-16 h-16 bg-slate-50 dark:bg-slate-900 rounded-full flex items-center justify-center mx-auto mb-4">
                        <Inbox className="w-8 h-8 text-slate-300 dark:text-slate-600" />
                      </div>
                      <p className="font-medium">{searchQuery ? "No matching messages" : "No messages found"}</p>
                      <p className="text-sm mt-1 text-slate-400 dark:text-slate-500">You're all caught up!</p>
                    </div>
                  ) : (
                    <ul className="divide-y divide-slate-100 dark:divide-slate-800/50">
                      {filteredEmails.map((email) => (
                        <li key={email.id}>
                          <div
                            role="button"
                            tabIndex={0}
                            onClick={() => handleEmailClick(email)}
                            onKeyDown={(e) => {
                              if (e.key === 'Enter' || e.key === ' ') {
                                e.preventDefault();
                                handleEmailClick(email);
                              }
                            }}
                            className={cn(
                              "w-full text-left p-4 transition-all relative group cursor-pointer outline-none focus-visible:ring-2 focus-visible:ring-inset focus-visible:ring-indigo-500 flex gap-3",
                              selectedEmail?.id === email.id 
                                ? "bg-indigo-50/50 dark:bg-indigo-900/10" 
                                : "bg-white dark:bg-slate-950 hover:bg-slate-50 dark:hover:bg-slate-900/50",
                              selectedEmailIds.includes(email.id) && "bg-indigo-50/30 dark:bg-indigo-900/5"
                            )}
                          >
                            <div className="pt-1 shrink-0">
                              <button 
                                onClick={(e) => {
                                  e.stopPropagation();
                                  handleToggleEmailSelection(email.id);
                                }}
                                className={cn(
                                  "w-5 h-5 border rounded flex items-center justify-center transition-all",
                                  selectedEmailIds.includes(email.id) 
                                    ? "bg-indigo-600 border-indigo-600" 
                                    : "border-slate-300 dark:border-slate-700 bg-white dark:bg-slate-900 group-hover:border-slate-400 dark:group-hover:border-slate-500"
                                )}
                              >
                                {selectedEmailIds.includes(email.id) && <Check className="w-3.5 h-3.5 text-white" />}
                              </button>
                            </div>
                            <div className="flex-1 min-w-0">
                              {!email.read && (
                                <div className="absolute left-0 top-3 bottom-3 w-1 bg-indigo-500 rounded-r-full" />
                              )}
                            <div className="flex items-start justify-between mb-1 gap-2">
                              <div className="flex flex-col min-w-0">
                                <span className={cn(
                                  "text-sm truncate", 
                                  !email.read ? "font-bold text-slate-900 dark:text-white" : "font-medium text-slate-700 dark:text-slate-300"
                                )}>
                                  {email.from.name || email.from.email.split('@')[0]}
                                </span>
                                <span className="text-[10px] text-slate-500 dark:text-slate-400 truncate">
                                  {email.from.email}
                                </span>
                              </div>
                              <div className="flex items-center gap-2">
                                <span className={cn(
                                  "text-xs whitespace-nowrap mt-0.5", 
                                  !email.read ? "font-bold text-indigo-600 dark:text-indigo-400" : "text-slate-400 dark:text-slate-500"
                                )}>
                                  {formatDistanceToNow(new Date(email.date), { addSuffix: true })}
                                </span>
                                <div className="relative group/more">
                                  <button 
                                    onClick={(e) => {
                                      e.stopPropagation();
                                      setContextMenuEmail(contextMenuEmail?.id === email.id ? null : email);
                                    }}
                                    className="p-1 hover:bg-slate-200 dark:hover:bg-slate-800 rounded-full transition-colors"
                                  >
                                    <MoreVertical className="w-3.5 h-3.5 text-slate-400" />
                                  </button>
                                  {contextMenuEmail?.id === email.id && (
                                    <>
                                      <div className="fixed inset-0 z-[60]" onClick={(e) => { e.stopPropagation(); setContextMenuEmail(null); }} />
                                      <div className="absolute right-0 top-full mt-1 w-48 bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-xl shadow-xl z-[70] py-1 animate-in fade-in zoom-in-95 duration-150 overflow-hidden">
                                        <button 
                                          onClick={(e) => { e.stopPropagation(); handleMarkAsRead(email.id); setContextMenuEmail(null); }}
                                          className="w-full px-4 py-2 text-left text-sm hover:bg-slate-50 dark:hover:bg-slate-800 flex items-center gap-2"
                                        >
                                          <Mail className="w-4 h-4" /> Mark as read
                                        </button>
                                        <button 
                                          onClick={(e) => { e.stopPropagation(); handleMarkAsUnread(email.id); setContextMenuEmail(null); }}
                                          className="w-full px-4 py-2 text-left text-sm hover:bg-slate-50 dark:hover:bg-slate-800 flex items-center gap-2"
                                        >
                                          <Bell className="w-4 h-4" /> Mark as unread
                                        </button>
                                        <button 
                                          onClick={(e) => { e.stopPropagation(); handleArchiveEmail(email.id); setContextMenuEmail(null); }}
                                          className="w-full px-4 py-2 text-left text-sm hover:bg-slate-50 dark:hover:bg-slate-800 flex items-center gap-2"
                                        >
                                          <Archive className="w-4 h-4" /> Archive
                                        </button>
                                        <button 
                                          onClick={(e) => { e.stopPropagation(); handleDeleteEmail(email.id); setContextMenuEmail(null); }}
                                          className="w-full px-4 py-2 text-left text-sm hover:bg-red-50 dark:hover:bg-red-900/20 text-red-600 dark:text-red-400 flex items-center gap-2"
                                        >
                                          <Trash2 className="w-4 h-4" /> Delete
                                        </button>
                                        <div className="h-px bg-slate-100 dark:bg-slate-800 my-1" />
                                        {mailboxes.find(m => m.id === selectedMailbox)?.role === 'junk' ? (
                                          <button 
                                            onClick={(e) => { e.stopPropagation(); handleMoveToInbox(email.id); setContextMenuEmail(null); }}
                                            className="w-full px-4 py-2 text-left text-sm hover:bg-slate-50 dark:hover:bg-slate-800 flex items-center gap-2"
                                          >
                                            <Inbox className="w-4 h-4" /> Move to Inbox
                                          </button>
                                        ) : (
                                          <button 
                                            onClick={(e) => { e.stopPropagation(); handleMoveToJunk(email.id); setContextMenuEmail(null); }}
                                            className="w-full px-4 py-2 text-left text-sm hover:bg-slate-50 dark:hover:bg-slate-800 flex items-center gap-2"
                                          >
                                            <AlertCircle className="w-4 h-4" /> Move to Junk
                                          </button>
                                        )}
                                      </div>
                                    </>
                                  )}
                                  </div>
                                </div>
                              </div>
                              <div className={cn(
                                  "text-sm mb-1.5 truncate min-w-0", 
                                  !email.read ? "font-bold text-slate-800 dark:text-slate-100" : "font-medium text-slate-600 dark:text-slate-400"
                                )}>
                                  {email.subject}
                                </div>
                                <div className="text-xs text-slate-500 dark:text-slate-400 line-clamp-2 leading-relaxed break-words">
                                  {email.preview}
                                </div>
                              </div>
                            </div>
                          </li>
                        ))}
                      </ul>
                  )}

                  {/* Floating Compose Button */}
                  {!isSidebarOpen && (
                    <button 
                      onClick={() => setIsComposeOpen(true)}
                      className="fixed bottom-6 right-4 md:absolute md:bottom-6 md:right-6 z-10 bg-indigo-600 hover:bg-indigo-700 text-white p-3.5 rounded-full shadow-lg flex items-center justify-center transition-all active:scale-90 group"
                      title="Compose"
                    >
                      <Edit3 className="w-5 h-5" />
                    </button>
                  )}
                </div>
              </div>

              {/* Email Viewer */}
              <div
                className={cn(
                  "flex-1 flex flex-col bg-white dark:bg-slate-950 min-w-0",
                  !selectedEmail ? "hidden md:flex" : "flex"
                )}
              >
                {selectedEmail ? (
                  <>
                    {/* Viewer Toolbar */}
                    <div className="h-14 border-b border-slate-200 dark:border-slate-800 flex items-center justify-between px-4 shrink-0 bg-white dark:bg-black">
                      <div className="flex items-center gap-1">
                        <button 
                          className="md:hidden p-2 -ml-2 text-slate-500 dark:text-slate-400 hover:bg-slate-100 dark:hover:bg-slate-800 rounded-lg mr-2 transition-colors"
                          onClick={() => setSelectedEmail(null)}
                        >
                          <ChevronDown className="w-5 h-5 rotate-90" />
                        </button>
                        <button 
                          onClick={() => handleArchiveEmail(selectedEmail.id)}
                          className="p-2 text-slate-500 dark:text-slate-400 hover:text-slate-700 dark:hover:text-slate-200 hover:bg-slate-100 dark:hover:bg-slate-800 rounded-lg transition-colors" 
                          title="Archive"
                        >
                          <Archive className="w-4 h-4" />
                        </button>
                        <button 
                          onClick={() => handleDeleteEmail(selectedEmail.id)}
                          className="p-2 text-slate-500 dark:text-slate-400 hover:text-red-600 dark:hover:text-red-400 hover:bg-red-50 dark:hover:bg-red-900/20 rounded-lg transition-colors" 
                          title="Delete"
                        >
                          <Trash2 className="w-4 h-4" />
                        </button>
                        <div className="w-px h-4 bg-slate-200 dark:bg-slate-700 mx-2" />
                        <button 
                          onClick={() => handleToggleStar(selectedEmail)}
                          className="p-2 text-slate-500 dark:text-slate-400 hover:text-yellow-500 dark:hover:text-yellow-400 hover:bg-yellow-50 dark:hover:bg-yellow-900/20 rounded-lg transition-colors" 
                          title="Star"
                        >
                          <Star className={cn("w-4 h-4", selectedEmail.starred && "fill-yellow-400 text-yellow-400")} />
                        </button>
                        <button 
                          onClick={() => selectedEmail.read ? handleMarkAsUnread(selectedEmail.id) : handleMarkAsRead(selectedEmail.id)}
                          className="p-2 text-slate-500 dark:text-slate-400 hover:text-indigo-500 dark:hover:text-indigo-400 hover:bg-indigo-50 dark:hover:bg-indigo-900/20 rounded-lg transition-colors" 
                          title={selectedEmail.read ? "Mark as unread" : "Mark as read"}
                        >
                          {selectedEmail.read ? <Mail className="w-4 h-4" /> : <Shield className="w-4 h-4" />}
                        </button>
                      </div>
                      <div className="flex items-center gap-1">
                        <button 
                          onClick={() => {
                            setToAddresses([selectedEmail.from.email]);
                            setSubject(`Re: ${selectedEmail.subject}`);
                            setEmailBody(`\n\n--- On ${format(new Date(selectedEmail.date), "MMM d, yyyy")} ${selectedEmail.from.name} wrote ---\n> ${selectedEmail.preview}`);
                            setIsComposeOpen(true);
                          }}
                          className="p-2 text-slate-500 dark:text-slate-400 hover:text-slate-700 dark:hover:text-slate-200 hover:bg-slate-100 dark:hover:bg-slate-800 rounded-lg transition-colors" 
                          title="Reply"
                        >
                          <Reply className="w-4 h-4" />
                        </button>
                        <button 
                          onClick={() => {
                            setSubject(`Fwd: ${selectedEmail.subject}`);
                            setEmailBody(`\n\n--- Forwarded message ---\nFrom: ${selectedEmail.from.name} <${selectedEmail.from.email}>\nDate: ${format(new Date(selectedEmail.date), "MMM d, yyyy")}\nSubject: ${selectedEmail.subject}\n\n${selectedEmail.body}`);
                            setIsComposeOpen(true);
                          }}
                          className="p-2 text-slate-500 dark:text-slate-400 hover:text-slate-700 dark:hover:text-slate-200 hover:bg-slate-100 dark:hover:bg-slate-800 rounded-lg transition-colors" 
                          title="Forward"
                        >
                          <Forward className="w-4 h-4" />
                        </button>
                        <div className="relative">
                          <button 
                            onClick={() => setIsEmailActionsOpen(!isEmailActionsOpen)}
                            className="p-2 text-slate-500 dark:text-slate-400 hover:text-slate-700 dark:hover:text-slate-200 hover:bg-slate-100 dark:hover:bg-slate-800 rounded-lg transition-colors" 
                            title="More"
                          >
                            <MoreVertical className="w-4 h-4" />
                          </button>
                          {isEmailActionsOpen && (
                            <>
                              <div className="fixed inset-0 z-40" onClick={() => setIsEmailActionsOpen(false)} />
                              <div className="absolute right-0 top-full mt-2 w-48 bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-xl shadow-xl z-50 py-1 animate-in fade-in zoom-in-95 duration-150 overflow-hidden">
                                {mailboxes.find(m => m.id === selectedMailbox)?.role === 'junk' ? (
                                  <button 
                                    onClick={() => { handleMoveToInbox(selectedEmail.id); setIsEmailActionsOpen(false); }}
                                    className="w-full px-4 py-2 text-left text-sm hover:bg-slate-50 dark:hover:bg-slate-800 flex items-center gap-2"
                                  >
                                    <Inbox className="w-4 h-4" /> Move to Inbox
                                  </button>
                                ) : (
                                  <button 
                                    onClick={() => { handleMoveToJunk(selectedEmail.id); setIsEmailActionsOpen(false); }}
                                    className="w-full px-4 py-2 text-left text-sm hover:bg-slate-50 dark:hover:bg-slate-800 flex items-center gap-2"
                                  >
                                    <AlertCircle className="w-4 h-4" /> Move to Junk
                                  </button>
                                )}
                                <button 
                                  onClick={() => { handleArchiveEmail(selectedEmail.id); setIsEmailActionsOpen(false); }}
                                  className="w-full px-4 py-2 text-left text-sm hover:bg-slate-50 dark:hover:bg-slate-800 flex items-center gap-2"
                                >
                                  <Archive className="w-4 h-4" /> Archive
                                </button>
                                <button 
                                  onClick={() => { handleDeleteEmail(selectedEmail.id); setIsEmailActionsOpen(false); }}
                                  className="w-full px-4 py-2 text-left text-sm hover:bg-red-50 dark:hover:bg-red-900/20 text-red-600 dark:text-red-400 flex items-center gap-2"
                                >
                                  <Trash2 className="w-4 h-4" /> Delete
                                </button>
                              </div>
                            </>
                          )}
                        </div>
                      </div>
                    </div>

                    {/* Viewer Content */}
                    <div className="flex-1 overflow-y-auto p-4 md:p-8 bg-white dark:bg-black">
                      <div className="max-w-4xl mx-auto">
                        <div className="flex items-start justify-between mb-6 group">
                          <h1 className="text-xl md:text-2xl font-bold text-slate-900 dark:text-white leading-tight break-words flex-1">
                            {selectedEmail.subject}
                          </h1>
                          <div className="flex items-center gap-2 ml-4 shrink-0">
                            <span className="px-2 py-0.5 bg-slate-100 dark:bg-slate-800 text-slate-500 dark:text-slate-400 text-[10px] font-bold rounded uppercase tracking-wider">Inbox</span>
                            <button className="p-1.5 text-slate-400 hover:text-slate-600 dark:hover:text-slate-200 transition-colors">
                              <Star className={cn("w-4 h-4", selectedEmail.starred && "fill-yellow-400 text-yellow-400")} />
                            </button>
                          </div>
                        </div>
                        
                        <div className="mb-8">
                          <div className="flex items-start gap-3">
                            <div className={cn(
                              "w-10 h-10 rounded-full flex items-center justify-center text-white font-bold text-lg shrink-0 shadow-sm",
                              getAccountColor(selectedEmail.from.email)
                            )}>
                              {(selectedEmail.from.name || selectedEmail.from.email || "?").charAt(0).toUpperCase()}
                            </div>
                            <div className="flex-1 min-w-0">
                              <div className="flex flex-wrap items-baseline justify-between gap-x-4 gap-y-1">
                                <div className="flex items-center gap-1.5 min-w-0">
                                  <span className="font-bold text-slate-900 dark:text-white truncate">
                                    {selectedEmail.from.name || selectedEmail.from.email.split('@')[0]}
                                  </span>
                                  <span className="text-xs text-slate-500 dark:text-slate-400 truncate hidden sm:inline">
                                    &lt;{selectedEmail.from.email}&gt;
                                  </span>
                                  <button 
                                    onClick={() => setIsHeaderExpanded(!isHeaderExpanded)}
                                    className="p-0.5 hover:bg-slate-100 dark:hover:bg-slate-800 rounded transition-colors"
                                  >
                                    <ChevronDown className={cn("w-3.5 h-3.5 text-slate-400 transition-transform duration-200", isHeaderExpanded && "rotate-180")} />
                                  </button>
                                </div>
                                <div className="text-[11px] text-slate-500 dark:text-slate-400 font-medium whitespace-nowrap">
                                  {format(new Date(selectedEmail.date), "MMM d, yyyy, h:mm a")}
                                </div>
                              </div>
                              
                              <div className="flex items-center gap-1 text-xs text-slate-500 dark:text-slate-400 mt-0.5">
                                <span>to me</span>
                                <ChevronDown className="w-3 h-3 opacity-0 group-hover:opacity-100 transition-opacity" />
                              </div>

                              {isHeaderExpanded && (
                                <div className="mt-3 p-3 bg-slate-50 dark:bg-slate-900/50 rounded-xl border border-slate-200 dark:border-slate-800 text-xs space-y-2 animate-in fade-in slide-in-from-top-2 duration-200 shadow-inner">
                                  <div className="grid grid-cols-[60px_1fr] gap-2">
                                    <span className="text-slate-400 dark:text-slate-500">from:</span>
                                    <span className="text-slate-700 dark:text-slate-300 break-all font-medium">
                                      {selectedEmail.from.name} <span className="text-slate-400 font-normal">&lt;{selectedEmail.from.email}&gt;</span>
                                    </span>
                                  </div>
                                  <div className="grid grid-cols-[60px_1fr] gap-2">
                                    <span className="text-slate-400 dark:text-slate-500">to:</span>
                                    <span className="text-slate-700 dark:text-slate-300 break-all font-medium">
                                      {selectedEmail.to.map(t => `${t.name || ""} <${t.email}>`).join(", ")}
                                    </span>
                                  </div>
                                  <div className="grid grid-cols-[60px_1fr] gap-2">
                                    <span className="text-slate-400 dark:text-slate-500">date:</span>
                                    <span className="text-slate-700 dark:text-slate-300 font-medium">
                                      {format(new Date(selectedEmail.date), "MMM d, yyyy, h:mm a")}
                                    </span>
                                  </div>
                                  <div className="grid grid-cols-[60px_1fr] gap-2">
                                    <span className="text-slate-400 dark:text-slate-500">subject:</span>
                                    <span className="text-slate-700 dark:text-slate-300 font-medium">{selectedEmail.subject}</span>
                                  </div>
                                  <div className="grid grid-cols-[60px_1fr] gap-2">
                                    <span className="text-slate-400 dark:text-slate-500">security:</span>
                                    <div className="flex items-center gap-1.5 text-green-600 dark:text-green-400 font-medium">
                                      <Shield className="w-3 h-3" />
                                      Standard encryption (TLS)
                                    </div>
                                  </div>
                                </div>
                              )}
                            </div>
                          </div>
                        </div>

                        <div className="relative">
                          <div 
                            className="prose prose-slate dark:prose-invert max-w-none prose-p:leading-relaxed prose-a:text-indigo-600 dark:prose-a:text-indigo-400 prose-img:rounded-xl prose-img:shadow-lg bg-white dark:bg-slate-950 p-1 rounded-lg break-words overflow-x-hidden"
                            dangerouslySetInnerHTML={{ __html: DOMPurify.sanitize(selectedEmail.body || "<em>No content</em>") }}
                          />
                        </div>
                        
                        <div className="mt-12 pt-8 border-t border-slate-100 dark:border-slate-800 flex gap-3">
                          <button 
                            onClick={() => {
                              const email = emails.find(e => e.id === selectedEmail);
                              if (email) {
                                setToAddresses([email.from.email]);
                                setSubject(`Re: ${email.subject}`);
                                setEmailBody(`\n\nOn ${format(new Date(email.date), 'MMM d, yyyy')} at ${format(new Date(email.date), 'h:mm a')}, ${email.from.name || email.from.email} wrote:\n> ${email.preview}...`);
                                setIsComposeOpen(true);
                              }
                            }}
                            className="flex items-center gap-2 px-6 py-2 rounded-full border border-slate-200 dark:border-slate-700 text-slate-600 dark:text-slate-300 hover:bg-slate-50 dark:hover:bg-slate-900 transition-all font-medium text-sm"
                          >
                            <Reply className="w-4 h-4" /> Reply
                          </button>
                          <button 
                            onClick={() => {
                              const email = emails.find(e => e.id === selectedEmail);
                              if (email) {
                                setToAddresses([]);
                                setSubject(`Fwd: ${email.subject}`);
                                setEmailBody(`\n\n---------- Forwarded message ---------\nFrom: ${email.from.name || email.from.email} <${email.from.email}>\nDate: ${format(new Date(email.date), 'MMM d, yyyy')} at ${format(new Date(email.date), 'h:mm a')}\nSubject: ${email.subject}\nTo: ${email.to.map(t => t.email).join(', ')}\n\n${email.body}`);
                                setIsComposeOpen(true);
                              }
                            }}
                            className="flex items-center gap-2 px-6 py-2 rounded-full border border-slate-200 dark:border-slate-700 text-slate-600 dark:text-slate-300 hover:bg-slate-50 dark:hover:bg-slate-900 transition-all font-medium text-sm"
                          >
                            <Forward className="w-4 h-4" /> Forward
                          </button>
                        </div>
                      </div>
                    </div>
                  </>
                ) : (
                  <div className="flex-1 flex flex-col items-center justify-center text-slate-400 dark:text-slate-500">
                    <div className="w-20 h-20 bg-slate-50 dark:bg-slate-900 rounded-full flex items-center justify-center mb-6">
                      <Mail className="w-10 h-10 text-slate-300 dark:text-slate-600" />
                    </div>
                    <p className="text-lg font-medium text-slate-500 dark:text-slate-400">Select a message to read</p>
                  </div>
                )}
              </div>
            </>
          )}

          {activeApp === 'contacts' && (
            <div className="flex-1 flex flex-col bg-slate-50 dark:bg-black overflow-hidden">
              <div className="flex-1 overflow-y-auto">
                <div className="sticky top-0 z-20 p-6 border-b border-slate-200 dark:border-slate-800 bg-white/80 dark:bg-black/80 backdrop-blur-md flex flex-col sm:flex-row sm:items-center justify-between gap-4">
                  <div>
                    <h1 className="text-2xl font-bold text-slate-900 dark:text-white">Contacts</h1>
                    <p className="text-sm text-slate-500 dark:text-slate-400">{filteredContacts.length} total contacts</p>
                  </div>
                  <div className="flex items-center gap-2">
                    <button 
                      onClick={handleExportContacts}
                      className="px-4 py-2.5 border border-slate-200 dark:border-slate-800 text-slate-600 dark:text-slate-400 rounded-xl font-medium hover:bg-slate-50 dark:hover:bg-slate-900 transition-all flex items-center gap-2"
                      title="Export to vCard"
                    >
                      <Download className="w-4 h-4" /> Export
                    </button>
                    <button 
                      onClick={() => setIsImportModalOpen(true)}
                      className="px-4 py-2.5 border border-slate-200 dark:border-slate-800 text-slate-600 dark:text-slate-400 rounded-xl font-medium hover:bg-slate-50 dark:hover:bg-slate-900 transition-all flex items-center gap-2"
                      title="Import from vCard"
                    >
                      <Upload className="w-4 h-4" /> Import
                    </button>
                    <button 
                      onClick={() => setIsContactModalOpen(true)}
                      className="px-6 py-2.5 bg-indigo-600 hover:bg-indigo-700 text-white rounded-xl font-medium shadow-lg shadow-indigo-500/20 transition-all active:scale-95 flex items-center gap-2"
                    >
                      <Plus className="w-4 h-4" /> Create Contact
                    </button>
                  </div>
                </div>
                <div className="p-6">
                  {filteredContacts.length > 0 ? (
                    <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4 gap-4">
                      {filteredContacts.map((contact, idx) => (
                        <div key={idx} className="group bg-white dark:bg-slate-900 p-4 rounded-2xl border border-slate-200 dark:border-slate-800 shadow-sm hover:shadow-md hover:border-indigo-500/30 transition-all cursor-pointer">
                          <div className="flex items-center gap-4">
                            <div className="w-12 h-12 rounded-2xl bg-gradient-to-br from-indigo-500 to-purple-600 text-white flex items-center justify-center font-bold text-xl shrink-0 shadow-inner">
                              {getContactName(contact).charAt(0).toUpperCase()}
                            </div>
                            <div className="min-w-0">
                              <h3 className="font-semibold text-slate-900 dark:text-white truncate group-hover:text-indigo-600 dark:group-hover:text-indigo-400 transition-colors">{getContactName(contact)}</h3>
                              {getContactEmail(contact) && <p className="text-xs text-slate-500 dark:text-slate-400 truncate">{getContactEmail(contact)}</p>}
                            </div>
                          </div>
                          <div className="mt-4 flex items-center justify-end gap-2 opacity-0 group-hover:opacity-100 transition-opacity">
                            <button className="p-1.5 text-slate-400 hover:text-indigo-600 dark:hover:text-indigo-400 hover:bg-indigo-50 dark:hover:bg-indigo-900/20 rounded-lg transition-all">
                              <Mail className="w-4 h-4" />
                            </button>
                            <button 
                              onClick={() => setContacts(contacts.filter(c => c.id !== contact.id))}
                              className="p-1.5 text-slate-400 hover:text-red-600 dark:hover:text-red-400 hover:bg-red-50 dark:hover:bg-red-900/20 rounded-lg transition-all"
                            >
                              <Trash2 className="w-4 h-4" />
                            </button>
                          </div>
                        </div>
                      ))}
                    </div>
                  ) : (
                    <div className="flex flex-col items-center justify-center py-20 text-slate-400 dark:text-slate-600 text-center">
                      <div className="w-24 h-24 bg-white dark:bg-slate-900 rounded-3xl flex items-center justify-center mb-6 shadow-xl border border-slate-100 dark:border-slate-800">
                        <Users className="w-10 h-10 text-slate-300 dark:text-slate-700" />
                      </div>
                      <p className="text-xl font-bold text-slate-900 dark:text-white">No Contacts Found</p>
                      <p className="text-sm mt-2 max-w-xs text-slate-500 dark:text-slate-400">Start building your network by adding your first contact.</p>
                      <button 
                        onClick={() => setIsContactModalOpen(true)}
                        className="mt-6 px-6 py-2.5 bg-indigo-600 hover:bg-indigo-700 text-white rounded-xl font-medium shadow-lg shadow-indigo-500/20 transition-all active:scale-95 flex items-center gap-2"
                      >
                        <Plus className="w-4 h-4" /> Create Contact
                      </button>
                    </div>
                  )}
                </div>
              </div>
            </div>
          )}

          {activeApp === 'calendar' && (
            <div className="flex-1 flex flex-col bg-slate-50 dark:bg-black overflow-hidden">
              <div className="flex-1 overflow-y-auto">
                <div className="sticky top-0 z-20 p-6 border-b border-slate-200 dark:border-slate-800 bg-white/80 dark:bg-black/80 backdrop-blur-md flex flex-col sm:flex-row sm:items-center justify-between gap-4">
                  <div>
                    <h1 className="text-2xl font-bold text-slate-900 dark:text-white">Calendar</h1>
                    <p className="text-sm text-slate-500 dark:text-slate-400">{format(new Date(), 'MMMM yyyy')}</p>
                  </div>
                  <div className="flex items-center gap-2">
                    <button className="px-4 py-2 bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-xl text-sm font-medium hover:bg-slate-50 dark:hover:bg-slate-800 transition-all">
                      Today
                    </button>
                    <button 
                      onClick={() => setIsEventModalOpen(true)}
                      className="p-2 bg-indigo-600 hover:bg-indigo-700 text-white rounded-xl shadow-lg shadow-indigo-500/20 transition-all active:scale-95"
                    >
                      <Plus className="w-5 h-5" />
                    </button>
                  </div>
                </div>
                <div className="p-6">
                  {/* Mock Calendar Grid */}
                  <div className="bg-white dark:bg-slate-900 rounded-2xl border border-slate-200 dark:border-slate-800 overflow-hidden shadow-sm">
                    <div className="grid grid-cols-7 border-b border-slate-200 dark:border-slate-800">
                      {['Sun', 'Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat'].map(day => (
                        <div key={day} className="p-3 text-center text-xs font-bold text-slate-400 uppercase tracking-wider border-r border-slate-100 dark:border-slate-800 last:border-0">
                          {day}
                        </div>
                      ))}
                    </div>
                    <div className="grid grid-cols-7 grid-rows-5">
                      {(() => {
                        const now = new Date();
                        const startOfMonth = new Date(now.getFullYear(), now.getMonth(), 1);
                        const startDay = startOfMonth.getDay();
                        const daysInMonth = new Date(now.getFullYear(), now.getMonth() + 1, 0).getDate();
                        
                        return Array.from({ length: 35 }).map((_, i) => {
                          const dayNum = i - startDay + 1;
                          const isToday = dayNum === now.getDate() && now.getMonth() === new Date().getMonth();
                          const isCurrentMonth = dayNum > 0 && dayNum <= daysInMonth;
                          
                          // Find events for this day
                          const dayEvents = filteredEvents.filter(e => {
                            const eventDate = new Date(e.start || e.startDate);
                            return eventDate.getDate() === dayNum && eventDate.getMonth() === now.getMonth() && eventDate.getFullYear() === now.getFullYear();
                          });

                          return (
                            <div key={i} className={cn(
                              "min-h-[120px] p-2 border-r border-b border-slate-100 dark:border-slate-800 transition-colors hover:bg-slate-50 dark:hover:bg-slate-800/50 cursor-pointer group",
                              !isCurrentMonth && "bg-slate-50/50 dark:bg-slate-900/50"
                            )}>
                              <div className="flex justify-between items-start">
                                <span className={cn(
                                  "text-sm font-medium w-7 h-7 flex items-center justify-center rounded-full transition-all",
                                  isToday ? "bg-indigo-600 text-white shadow-md shadow-indigo-500/20" : "text-slate-600 dark:text-slate-400",
                                  !isCurrentMonth && "opacity-30"
                                )}>
                                  {isCurrentMonth ? dayNum : ""}
                                </span>
                                {isToday && (
                                  <div className="w-1.5 h-1.5 rounded-full bg-indigo-500 animate-pulse" />
                                )}
                              </div>
                              
                              <div className="mt-2 space-y-1">
                                {dayEvents.map((event, idx) => (
                                  <div key={idx} className="p-1.5 bg-indigo-50 dark:bg-indigo-900/20 border-l-2 border-indigo-500 rounded text-[10px] font-medium text-indigo-700 dark:text-indigo-300 truncate group-hover:whitespace-normal group-hover:overflow-visible group-hover:z-10 group-hover:relative">
                                    {event.title}
                                  </div>
                                ))}
                              </div>
                            </div>
                          );
                        });
                      })()}
                    </div>
                  </div>

                  <div className="mt-8">
                    <h2 className="text-lg font-bold text-slate-900 dark:text-white mb-4">Your Calendars</h2>
                    <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-4">
                      {calendars.map((calendar, idx) => (
                        <div key={idx} className="bg-white dark:bg-slate-900 p-4 rounded-2xl border border-slate-200 dark:border-slate-800 shadow-sm flex items-center justify-between group hover:border-indigo-500/30 transition-all">
                          <div className="flex items-center gap-4">
                            <div className="w-10 h-10 rounded-xl bg-indigo-100 dark:bg-indigo-900/50 text-indigo-700 dark:text-indigo-300 flex items-center justify-center shrink-0">
                              <Calendar className="w-5 h-5" />
                            </div>
                            <h3 className="font-semibold text-slate-900 dark:text-white">{calendar.name || "Calendar"}</h3>
                          </div>
                          <div className="w-3 h-3 rounded-full bg-indigo-500 shadow-[0_0_8px_rgba(99,102,241,0.5)]" />
                        </div>
                      ))}
                    </div>
                  </div>
                </div>
              </div>
            </div>
          )}

          {activeApp === 'settings' && (
            <div className="flex-1 flex flex-col bg-slate-50 dark:bg-black overflow-hidden">
              <div className="flex-1 flex overflow-hidden">
                {/* Settings Sidebar */}
                <div className="w-64 border-r border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-950 hidden md:flex flex-col p-4 gap-2">
                  <button 
                    onClick={() => setIsSettingsSection('account')}
                    className={cn(
                      "flex items-center gap-3 px-4 py-2.5 rounded-xl text-sm font-medium transition-all",
                      isSettingsSection === 'account' ? "bg-indigo-50 dark:bg-indigo-500/10 text-indigo-600 dark:text-indigo-400" : "text-slate-600 dark:text-slate-400 hover:bg-slate-50 dark:hover:bg-slate-900"
                    )}
                  >
                    <User className="w-4 h-4" /> Account
                  </button>
                  <button 
                    onClick={() => setIsSettingsSection('general')}
                    className={cn(
                      "flex items-center gap-3 px-4 py-2.5 rounded-xl text-sm font-medium transition-all",
                      isSettingsSection === 'general' ? "bg-indigo-50 dark:bg-indigo-500/10 text-indigo-600 dark:text-indigo-400" : "text-slate-600 dark:text-slate-400 hover:bg-slate-50 dark:hover:bg-slate-900"
                    )}
                  >
                    <Settings className="w-4 h-4" /> General
                  </button>
                  <button 
                    onClick={() => setIsSettingsSection('security')}
                    className={cn(
                      "flex items-center gap-3 px-4 py-2.5 rounded-xl text-sm font-medium transition-all",
                      isSettingsSection === 'security' ? "bg-indigo-50 dark:bg-indigo-500/10 text-indigo-600 dark:text-indigo-400" : "text-slate-600 dark:text-slate-400 hover:bg-slate-50 dark:hover:bg-slate-900"
                    )}
                  >
                    <Shield className="w-4 h-4" /> Security
                  </button>
                  <button 
                    onClick={() => setIsSettingsSection('advanced')}
                    className={cn(
                      "flex items-center gap-3 px-4 py-2.5 rounded-xl text-sm font-medium transition-all",
                      isSettingsSection === 'advanced' ? "bg-indigo-50 dark:bg-indigo-500/10 text-indigo-600 dark:text-indigo-400" : "text-slate-600 dark:text-slate-400 hover:bg-slate-50 dark:hover:bg-slate-900"
                    )}
                  >
                    <Lock className="w-4 h-4" /> Advanced
                  </button>
                  <button 
                    onClick={() => setIsSettingsSection('notifications')}
                    className={cn(
                      "flex items-center gap-3 px-4 py-2.5 rounded-xl text-sm font-medium transition-all",
                      isSettingsSection === 'notifications' ? "bg-indigo-50 dark:bg-indigo-500/10 text-indigo-600 dark:text-indigo-400" : "text-slate-600 dark:text-slate-400 hover:bg-slate-50 dark:hover:bg-slate-900"
                    )}
                  >
                    <Bell className="w-4 h-4" /> Notifications
                  </button>
                </div>

                <div className="flex-1 overflow-y-auto">
                  <div className="sticky top-0 z-20 p-6 border-b border-slate-200 dark:border-slate-800 bg-white/80 dark:bg-black/80 backdrop-blur-md flex items-center justify-between">
                    <h1 className="text-2xl font-bold text-slate-900 dark:text-white">
                      {isSettingsSection === 'account' ? 'Account Settings' : 
                       isSettingsSection === 'general' ? 'General Settings' : 
                       isSettingsSection === 'security' ? 'Security & Privacy' : 
                       isSettingsSection === 'notifications' ? 'Notification Settings' : 'Advanced Settings'}
                    </h1>
                    <div className="md:hidden">
                      <select 
                        value={isSettingsSection}
                        onChange={(e) => setIsSettingsSection(e.target.value as any)}
                        className="bg-slate-100 dark:bg-slate-800 border-none rounded-lg px-3 py-1.5 text-sm outline-none dark:text-white"
                      >
                        <option value="account">Account</option>
                        <option value="general">General</option>
                        <option value="security">Security</option>
                        <option value="notifications">Notifications</option>
                        <option value="advanced">Advanced</option>
                      </select>
                    </div>
                  </div>
                  
                  <div className="p-6 max-w-3xl mx-auto w-full">
                    <div className="space-y-6">
                      {isSettingsSection === 'account' && (
                        <>
                          <div className="bg-white dark:bg-slate-900 p-6 rounded-xl border border-slate-200 dark:border-slate-800 shadow-sm">
                            <h2 className="text-lg font-semibold text-slate-900 dark:text-white mb-4 flex items-center gap-2">
                              <User className="w-5 h-5 text-indigo-500" /> Account Information
                            </h2>
                            <div className="space-y-3 text-sm">
                              <div className="flex justify-between py-2 border-b border-slate-100 dark:border-slate-800">
                                <span className="text-slate-500 dark:text-slate-400">Username</span>
                                <span className="font-medium text-slate-900 dark:text-white">{credentials.username}</span>
                              </div>
                              <div className="flex justify-between py-2 border-b border-slate-100 dark:border-slate-800">
                                <span className="text-slate-500 dark:text-slate-400">Server URL</span>
                                <span className="font-medium text-slate-900 dark:text-white">{credentials.serverUrl}</span>
                              </div>
                              <div className="flex justify-between py-2 border-b border-slate-100 dark:border-slate-800">
                                <span className="text-slate-500 dark:text-slate-400">API URL</span>
                                <span className="font-medium text-slate-900 dark:text-white truncate max-w-[200px] sm:max-w-none">{credentials.apiUrl}</span>
                              </div>
                            </div>
                          </div>

                          <div className="bg-white dark:bg-slate-900 p-6 rounded-xl border border-slate-200 dark:border-slate-800 shadow-sm">
                            <h2 className="text-lg font-semibold text-slate-900 dark:text-white mb-4 flex items-center gap-2">
                              <Mail className="w-5 h-5 text-indigo-500" /> Email Identities
                            </h2>
                            <div className="space-y-4">
                              {sortedIdentities.map((id) => (
                                <div key={id.id} className={cn(
                                  "flex items-center justify-between p-4 rounded-xl border transition-all",
                                  selectedIdentityId === id.id 
                                    ? "bg-indigo-50/50 dark:bg-indigo-500/10 border-indigo-500 dark:border-indigo-500 ring-1 ring-indigo-500/20 shadow-sm" 
                                    : "bg-white dark:bg-slate-900 border-slate-200 dark:border-slate-800 hover:border-slate-300 dark:hover:border-slate-700"
                                )}>
                                  <div className="flex flex-col gap-1 min-w-0 flex-1">
                                    <div className="font-bold text-slate-900 dark:text-white truncate">
                                      {id.name}
                                    </div>
                                    <div className="text-sm text-slate-500 dark:text-slate-400 truncate">{id.email}</div>
                                  </div>
                                  <div className="flex items-center gap-3 shrink-0 ml-4">
                                    {selectedIdentityId === id.id ? (
                                      <span className="flex items-center gap-1 text-[10px] font-bold uppercase tracking-wider bg-indigo-600 text-white px-2.5 py-1 rounded-full shadow-sm">
                                        Default
                                      </span>
                                    ) : (
                                      <button
                                        onClick={() => handleSetDefaultIdentity(id.id)}
                                        className="px-3 py-1.5 text-xs font-semibold text-indigo-600 dark:text-indigo-400 hover:bg-indigo-50 dark:hover:bg-indigo-500/10 rounded-lg transition-all border border-slate-200 dark:border-slate-800 hover:border-indigo-200 dark:hover:border-indigo-500/30"
                                      >
                                        Set as Default
                                      </button>
                                    )}
                                  </div>
                                </div>
                              ))}
                              
                              <div className="pt-4 border-t border-slate-100 dark:border-slate-800">
                                <h3 className="text-sm font-medium text-slate-700 dark:text-slate-300 mb-3">Add New Identity</h3>
                                <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 mb-3">
                                  <input
                                    type="text"
                                    placeholder="Display Name"
                                    value={newIdentityName}
                                    onChange={(e) => setNewIdentityName(e.target.value)}
                                    className="px-3 py-2 bg-slate-50 dark:bg-slate-800 border border-slate-200 dark:border-slate-700 rounded-lg text-sm outline-none focus:ring-2 focus:ring-indigo-500/20 focus:border-indigo-500 dark:text-white"
                                  />
                                  <input
                                    type="email"
                                    placeholder="Email Address"
                                    value={newIdentityEmail}
                                    onChange={(e) => setNewIdentityEmail(e.target.value)}
                                    className="px-3 py-2 bg-slate-50 dark:bg-slate-800 border border-slate-200 dark:border-slate-700 rounded-lg text-sm outline-none focus:ring-2 focus:ring-indigo-500/20 focus:border-indigo-500 dark:text-white"
                                  />
                                </div>
                                <button
                                  onClick={handleCreateIdentity}
                                  className="w-full sm:w-auto px-4 py-2 bg-indigo-600 hover:bg-indigo-700 text-white rounded-lg text-sm font-medium transition-colors flex items-center justify-center gap-2"
                                >
                                  <Plus className="w-4 h-4" /> Add Identity
                                </button>
                              </div>
                            </div>
                          </div>
                        </>
                      )}

                      {isSettingsSection === 'general' && (
                        <>
                          <div className="bg-white dark:bg-slate-900 p-6 rounded-xl border border-slate-200 dark:border-slate-800 shadow-sm">
                            <h2 className="text-lg font-semibold text-slate-900 dark:text-white mb-4 flex items-center gap-2">
                              <Settings className="w-5 h-5 text-indigo-500" /> Appearance
                            </h2>
                            <div className="flex items-center justify-between">
                              <div>
                                <div className="font-medium text-slate-900 dark:text-white">Dark Mode</div>
                                <div className="text-sm text-slate-500 dark:text-slate-400">Toggle dark theme across the app</div>
                              </div>
                              <button
                                onClick={() => setIsDarkMode(!isDarkMode)}
                                className={cn(
                                  "relative inline-flex h-6 w-11 items-center rounded-full transition-colors focus:outline-none focus:ring-2 focus:ring-indigo-500 focus:ring-offset-2",
                                  isDarkMode ? "bg-indigo-600" : "bg-slate-200 dark:bg-slate-700"
                                )}
                              >
                                <span
                                  className={cn(
                                    "inline-block h-4 w-4 transform rounded-full bg-white transition-transform",
                                    isDarkMode ? "translate-x-6" : "translate-x-1"
                                  )}
                                />
                              </button>
                            </div>
                          </div>

                          <div className="bg-white dark:bg-slate-900 p-6 rounded-xl border border-slate-200 dark:border-slate-800 shadow-sm">
                            <h2 className="text-lg font-semibold text-slate-900 dark:text-white mb-4 flex items-center gap-2">
                              <Clock className="w-5 h-5 text-indigo-500" /> Regional
                            </h2>
                            <div className="space-y-4">
                              <div className="flex items-center justify-between">
                                <span className="text-sm text-slate-600 dark:text-slate-400">Language</span>
                                <select className="bg-slate-50 dark:bg-slate-800 border border-slate-200 dark:border-slate-700 rounded-lg px-3 py-1.5 text-sm outline-none dark:text-white">
                                  <option>English (US)</option>
                                  <option>Spanish</option>
                                  <option>French</option>
                                </select>
                              </div>
                              <div className="flex items-center justify-between">
                                <span className="text-sm text-slate-600 dark:text-slate-400">Timezone</span>
                                <select className="bg-slate-50 dark:bg-slate-800 border border-slate-200 dark:border-slate-700 rounded-lg px-3 py-1.5 text-sm outline-none dark:text-white">
                                  <option>UTC (Coordinated Universal Time)</option>
                                  <option>EST (Eastern Standard Time)</option>
                                  <option>PST (Pacific Standard Time)</option>
                                </select>
                              </div>
                            </div>
                          </div>
                        </>
                      )}

                      {isSettingsSection === 'security' && (
                        <div className="bg-white dark:bg-slate-900 p-6 rounded-xl border border-slate-200 dark:border-slate-800 shadow-sm">
                          <h2 className="text-lg font-semibold text-slate-900 dark:text-white mb-4 flex items-center gap-2">
                            <Shield className="w-5 h-5 text-indigo-500" /> Privacy & Security
                          </h2>
                          <div className="space-y-4">
                            <div className="flex items-center justify-between">
                              <div>
                                <div className="text-sm font-medium text-slate-900 dark:text-white">Local Encryption</div>
                                <div className="text-xs text-slate-500 dark:text-slate-400">Accounts are encrypted with AES-GCM locally</div>
                              </div>
                              <span className="px-2 py-1 bg-emerald-100 dark:bg-emerald-900/30 text-emerald-600 dark:text-emerald-400 text-[10px] font-bold rounded uppercase">Active</span>
                            </div>
                            <button className="w-full py-2.5 border border-slate-200 dark:border-slate-800 rounded-xl text-sm font-medium text-slate-600 dark:text-slate-400 hover:bg-slate-50 dark:hover:bg-slate-800 transition-colors">
                              Change Master Password
                            </button>
                          </div>
                        </div>
                      )}

                      {isSettingsSection === 'advanced' && (
                        <div className="bg-white dark:bg-slate-900 p-6 rounded-xl border border-slate-200 dark:border-slate-800 shadow-sm">
                          <h2 className="text-lg font-semibold text-slate-900 dark:text-white mb-4 flex items-center gap-2">
                            <Lock className="w-5 h-5 text-indigo-500" /> Server Capabilities
                          </h2>
                          <div className="flex flex-wrap gap-2">
                            {credentials.capabilities.map((cap, idx) => (
                              <span key={idx} className="px-2.5 py-1 bg-slate-100 dark:bg-slate-800 text-slate-600 dark:text-slate-300 rounded-lg text-xs font-mono border border-slate-200 dark:border-slate-700">
                                {cap}
                              </span>
                            ))}
                          </div>
                        </div>
                      )}

                      {isSettingsSection === 'notifications' && (
                        <div className="bg-white dark:bg-slate-900 p-6 rounded-xl border border-slate-200 dark:border-slate-800 shadow-sm">
                          <h2 className="text-lg font-semibold text-slate-900 dark:text-white mb-4 flex items-center gap-2">
                            <Bell className="w-5 h-5 text-indigo-500" /> Notifications
                          </h2>
                          <div className="space-y-4">
                            <div className="flex items-center justify-between">
                              <div>
                                <div className="font-medium text-slate-900 dark:text-white">Desktop Notifications</div>
                                <div className="text-sm text-slate-500 dark:text-slate-400">Show notifications for new emails</div>
                              </div>
                              <button className="relative inline-flex h-6 w-11 items-center rounded-full bg-slate-200 dark:bg-slate-700">
                                <span className="inline-block h-4 w-4 transform rounded-full bg-white translate-x-1" />
                              </button>
                            </div>
                            <div className="flex items-center justify-between">
                              <div>
                                <div className="font-medium text-slate-900 dark:text-white">Sound Effects</div>
                                <div className="text-sm text-slate-500 dark:text-slate-400">Play sound when a new message arrives</div>
                              </div>
                              <button className="relative inline-flex h-6 w-11 items-center rounded-full bg-indigo-600">
                                <span className="inline-block h-4 w-4 transform rounded-full bg-white translate-x-6" />
                              </button>
                            </div>
                          </div>
                        </div>
                      )}

                      <div className="pt-6 border-t border-slate-200 dark:border-slate-800">
                        <button
                          onClick={onLogout}
                          className="w-full sm:w-auto px-6 py-2.5 bg-red-50 dark:bg-red-500/10 text-red-600 dark:text-red-400 hover:bg-red-100 dark:hover:bg-red-500/20 rounded-xl font-medium transition-colors flex items-center justify-center gap-2"
                        >
                          <LogOut className="w-4 h-4" />
                          Sign Out
                        </button>
                      </div>
                    </div>
                  </div>
                </div>
              </div>
            </div>
          )}
        </div>
      </main>

      {/* Compose Modal */}
      {isComposeOpen && (
        <div className="fixed inset-0 z-50 flex items-end sm:items-center justify-center sm:p-4 bg-black/40 dark:bg-black/60 backdrop-blur-sm">
          <div className="bg-white dark:bg-black w-full sm:w-[650px] sm:rounded-2xl shadow-2xl flex flex-col h-full sm:h-[650px] overflow-hidden animate-in fade-in slide-in-from-bottom-4 sm:slide-in-from-bottom-0 sm:zoom-in-95 duration-200 border border-slate-200 dark:border-slate-800">
            <div className="h-14 border-b border-slate-200 dark:border-slate-800 flex items-center justify-between px-4 bg-slate-50 dark:bg-black sm:rounded-t-2xl shrink-0">
              <span className="font-bold text-slate-700 dark:text-slate-200">New Message</span>
              <button 
                onClick={() => setIsComposeOpen(false)}
                className="p-2 text-slate-400 hover:text-slate-600 dark:hover:text-slate-200 hover:bg-slate-200 dark:hover:bg-slate-800 rounded-lg transition-colors"
              >
                <X className="w-5 h-5" />
              </button>
            </div>

            <div className="flex-1 overflow-y-auto p-6 flex flex-col gap-4 bg-white dark:bg-black">
              {/* Tab Toggle */}
              <div className="flex p-1 bg-slate-100 dark:bg-slate-800 rounded-xl w-fit mb-2 shrink-0">
                <button 
                  onClick={() => setIsSecureMessage(false)}
                  className={cn(
                    "px-4 py-2 rounded-lg text-sm font-medium transition-all",
                    !isSecureMessage ? "bg-white dark:bg-slate-700 shadow-sm text-slate-900 dark:text-white" : "text-slate-500 hover:text-slate-700 dark:hover:text-slate-300"
                  )}
                >
                  Standard Email
                </button>
                <button 
                  onClick={() => setIsSecureMessage(true)}
                  className={cn(
                    "px-4 py-2 rounded-lg text-sm font-medium transition-all flex items-center gap-2",
                    isSecureMessage ? "bg-white dark:bg-slate-700 shadow-sm text-indigo-600 dark:text-indigo-400" : "text-slate-500 hover:text-slate-700 dark:hover:text-slate-300"
                  )}
                >
                  <Lock className="w-3.5 h-3.5" />
                  Secure Message
                </button>
              </div>

              <div className="flex items-start gap-3 border-b border-slate-200 dark:border-slate-800 pb-4 shrink-0">
                <span className="text-slate-500 text-sm mt-2.5 shrink-0">From:</span>
                <div className="flex-1 relative min-w-0">
                  <div 
                    onClick={() => setIsIdentityDropdownOpen(!isIdentityDropdownOpen)}
                    className="flex items-center gap-3 p-3 bg-slate-50 dark:bg-slate-800/50 rounded-xl border border-slate-200 dark:border-slate-700/50 hover:border-indigo-500/50 transition-all cursor-pointer min-w-0 shadow-sm"
                  >
                    <div className={cn(
                      "w-8 h-8 rounded-full flex items-center justify-center text-xs text-white font-bold shadow-sm shrink-0",
                      getAccountColor(identities.find(i => i.id === selectedIdentityId)?.email || "")
                    )}>
                      {(identities.find(i => i.id === selectedIdentityId)?.name || "?").charAt(0).toUpperCase()}
                    </div>
                    <div className="flex-1 min-w-0 flex flex-col">
                      <div className="text-sm font-bold text-slate-900 dark:text-white truncate">
                        {identities.find(i => i.id === selectedIdentityId)?.name}
                      </div>
                      <div className="text-[10px] text-slate-500 dark:text-slate-400 truncate font-medium">
                        {identities.find(i => i.id === selectedIdentityId)?.email}
                      </div>
                    </div>
                    <ChevronDown className={cn("w-4 h-4 text-slate-400 transition-transform", isIdentityDropdownOpen && "rotate-180")} />
                  </div>

                  {isIdentityDropdownOpen && (
                    <>
                      <div className="fixed inset-0 z-10" onClick={() => setIsIdentityDropdownOpen(false)} />
                      <div className="absolute top-full left-0 right-0 mt-2 bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-xl shadow-xl z-20 py-2 animate-in fade-in zoom-in-95 duration-150 overflow-hidden">
                        {identities.map(id => (
                          <button
                            key={id.id}
                            onClick={() => {
                              setSelectedIdentityId(id.id);
                              setIsIdentityDropdownOpen(false);
                            }}
                            className={cn(
                              "w-full px-4 py-3 flex items-center gap-3 hover:bg-slate-50 dark:hover:bg-slate-800 transition-colors text-left",
                              selectedIdentityId === id.id && "bg-indigo-50/50 dark:bg-indigo-500/10"
                            )}
                          >
                            <div className={cn(
                              "w-8 h-8 rounded-full flex items-center justify-center text-xs text-white font-bold shrink-0",
                              getAccountColor(id.email)
                            )}>
                              {id.name.charAt(0).toUpperCase()}
                            </div>
                            <div className="flex-1 min-w-0">
                              <div className="text-sm font-bold text-slate-900 dark:text-white truncate">{id.name}</div>
                              <div className="text-xs text-slate-500 dark:text-slate-400 truncate">{id.email}</div>
                            </div>
                            {selectedIdentityId === id.id && (
                              <div className="w-2 h-2 rounded-full bg-indigo-500" />
                            )}
                          </button>
                        ))}
                      </div>
                    </>
                  )}
                </div>
              </div>

              <div className="flex flex-wrap items-center gap-2 border-b border-slate-200 dark:border-slate-800 pb-3 shrink-0">
                <span className="text-slate-500 text-sm">To:</span>
                {toAddresses.map((email, idx) => (
                  <div key={idx} className="flex items-center gap-1 bg-slate-100 dark:bg-slate-800 text-slate-700 dark:text-slate-300 px-3 py-1 rounded-full text-sm font-medium">
                    <span>{email}</span>
                    <button 
                      onClick={() => setToAddresses(toAddresses.filter((_, i) => i !== idx))} 
                      className="hover:text-slate-900 dark:hover:text-white ml-1"
                    >
                      <X className="w-3 h-3" />
                    </button>
                  </div>
                ))}
                <div className="flex-1 relative min-w-[120px]">
                  <input 
                    type="text" 
                    value={toInput}
                    onChange={(e) => {
                      const val = e.target.value;
                      setToInput(val);
                      if (val.length > 0) {
                        const filtered = contacts.filter(c => {
                          const name = getContactName(c).toLowerCase();
                          const email = getContactEmail(c).toLowerCase();
                          const query = val.toLowerCase();
                          return name.includes(query) || email.includes(query);
                        });
                        setContactSuggestions(filtered.slice(0, 5));
                      } else {
                        setContactSuggestions([]);
                      }
                    }}
                    onPaste={(e) => {
                      e.preventDefault();
                      const pastedText = e.clipboardData.getData('text');
                      const emails = pastedText.split(/[\s,;]+/).filter(Boolean);
                      const newAddresses = emails.filter(email => !toAddresses.includes(email));
                      if (newAddresses.length > 0) {
                        setToAddresses([...toAddresses, ...newAddresses]);
                      }
                    }}
                    onKeyDown={(e) => {
                      if (e.key === 'Enter' || e.key === ' ' || e.key === ',') {
                        e.preventDefault();
                        const val = toInput.trim().replace(/,$/, '');
                        if (val && !toAddresses.includes(val)) {
                          setToAddresses([...toAddresses, val]);
                          setToInput('');
                          setContactSuggestions([]);
                        }
                      } else if (e.key === 'Backspace' && !toInput && toAddresses.length > 0) {
                        setToAddresses(toAddresses.slice(0, -1));
                      }
                    }}
                    onBlur={() => {
                      // Small timeout to allow clicking on a suggestion
                      setTimeout(() => {
                        const val = toInput.trim().replace(/,$/, '');
                        if (val && !toAddresses.includes(val)) {
                          setToAddresses([...toAddresses, val]);
                          setToInput('');
                          setContactSuggestions([]);
                        }
                      }, 200);
                    }}
                    className="w-full bg-transparent outline-none text-slate-900 dark:text-white"
                  />
                  {contactSuggestions.length > 0 && (
                    <div className="absolute top-full left-0 right-0 mt-1 bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-xl shadow-xl z-30 py-2 animate-in fade-in zoom-in-95 duration-150 overflow-hidden">
                      {contactSuggestions.map((contact, idx) => (
                        <button
                          key={idx}
                          onClick={() => {
                            const email = getContactEmail(contact);
                            if (email && !toAddresses.includes(email)) {
                              setToAddresses([...toAddresses, email]);
                              setToInput('');
                              setContactSuggestions([]);
                            }
                          }}
                          className="w-full px-4 py-2 flex items-center gap-3 hover:bg-slate-50 dark:hover:bg-slate-800 transition-colors text-left"
                        >
                          <div className={cn(
                            "w-8 h-8 rounded-full flex items-center justify-center text-xs text-white font-bold shrink-0",
                            getAccountColor(getContactEmail(contact) || getContactName(contact))
                          )}>
                            {getContactName(contact).charAt(0).toUpperCase()}
                          </div>
                          <div className="flex-1 min-w-0">
                            <div className="text-sm font-bold text-slate-900 dark:text-white truncate">{getContactName(contact)}</div>
                            <div className="text-xs text-slate-500 dark:text-slate-400 truncate">{getContactEmail(contact)}</div>
                          </div>
                        </button>
                      ))}
                    </div>
                  )}
                </div>
              </div>

              <input 
                type="text" 
                placeholder="Subject" 
                value={subject}
                onChange={(e) => setSubject(e.target.value)}
                className="w-full border-b border-slate-200 dark:border-slate-800 pb-3 bg-transparent focus:border-indigo-500 dark:focus:border-indigo-500 outline-none transition-colors font-bold text-slate-900 dark:text-white shrink-0"
              />

              {isSecureMessage ? (
                <div className="bg-indigo-50/50 dark:bg-indigo-500/5 border border-indigo-100 dark:border-indigo-500/20 rounded-2xl p-5 mt-2 animate-in fade-in slide-in-from-top-4 duration-300">
                  <div className="flex items-center gap-3 mb-4">
                    <div className="w-8 h-8 rounded-lg bg-indigo-100 dark:bg-indigo-500/20 flex items-center justify-center">
                      <Lock className="w-4 h-4 text-indigo-600 dark:text-indigo-400" />
                    </div>
                    <span className="font-bold text-indigo-900 dark:text-indigo-100">PrivateBin Encryption</span>
                  </div>
                  
                  <textarea 
                    value={emailBody}
                    onChange={(e) => setEmailBody(e.target.value)}
                    placeholder="Type your highly sensitive message here. It will be encrypted in your browser before a link is generated..."
                    className="w-full bg-white dark:bg-slate-900 border border-indigo-100 dark:border-indigo-500/30 rounded-xl p-4 min-h-[150px] outline-none focus:ring-2 focus:ring-indigo-500/20 transition-all text-slate-700 dark:text-slate-200 placeholder:text-slate-400 dark:placeholder:text-slate-500"
                  />
                  
                  <div className="mt-4 space-y-4">
                    <div className="flex items-center justify-between">
                      <div className="flex items-center gap-2 text-slate-500 dark:text-slate-400">
                        <Key className="w-4 h-4" />
                        <span className="text-sm">Access Control</span>
                      </div>
                      <div className="flex p-1 bg-slate-100 dark:bg-slate-800 rounded-lg">
                        <button 
                          onClick={() => setUseAutomaticKey(true)}
                          className={cn(
                            "px-3 py-1 rounded-md text-xs font-medium transition-all",
                            useAutomaticKey ? "bg-white dark:bg-slate-700 shadow-sm text-indigo-600 dark:text-indigo-400" : "text-slate-500"
                          )}
                        >
                          Automatic
                        </button>
                        <button 
                          onClick={() => setUseAutomaticKey(false)}
                          className={cn(
                            "px-3 py-1 rounded-md text-xs font-medium transition-all",
                            !useAutomaticKey ? "bg-white dark:bg-slate-700 shadow-sm text-indigo-600 dark:text-indigo-400" : "text-slate-500"
                          )}
                        >
                          Password
                        </button>
                      </div>
                    </div>

                    {!useAutomaticKey && (
                      <input 
                        type="password"
                        value={securePassword}
                        onChange={(e) => setSecurePassword(e.target.value)}
                        placeholder="Set a custom decryption password..."
                        className="w-full bg-white dark:bg-slate-900 border border-indigo-100 dark:border-indigo-500/30 rounded-xl px-4 py-2 text-sm outline-none focus:ring-2 focus:ring-indigo-500/20 transition-all text-slate-700 dark:text-slate-200"
                      />
                    )}

                    <div className="flex items-center justify-between">
                      <div className="flex items-center gap-2 text-slate-500 dark:text-slate-400">
                        <Clock className="w-4 h-4" />
                        <span className="text-sm">Expiration</span>
                      </div>
                      <button 
                        onClick={() => setIsExpirationModalOpen(true)}
                        className="flex items-center gap-2 px-3 py-1.5 bg-white dark:bg-slate-800 border border-slate-200 dark:border-slate-700 rounded-lg text-sm font-medium text-slate-700 dark:text-slate-300 hover:border-indigo-500/50 transition-all shadow-sm"
                      >
                        {expirationOptions.find(o => o.value === expiration)?.label}
                        <ChevronDown className="w-4 h-4 text-slate-400" />
                      </button>
                    </div>
                  </div>
                </div>
              ) : (
                <textarea 
                  placeholder="Write your message..." 
                  value={emailBody}
                  onChange={(e) => setEmailBody(e.target.value)}
                  className="w-full flex-1 resize-none outline-none pt-4 bg-transparent text-slate-900 dark:text-white"
                />
              )}
            </div>
            <div className="p-4 border-t border-slate-200 dark:border-slate-800 flex items-center justify-between bg-slate-50 dark:bg-black sm:rounded-b-2xl shrink-0">
              <button 
                onClick={() => handleSendEmail()}
                disabled={isSending || toAddresses.length === 0}
                className="bg-indigo-600 hover:bg-indigo-700 disabled:opacity-50 disabled:cursor-not-allowed text-white px-6 py-2.5 rounded-xl font-medium flex items-center gap-2 transition-all active:scale-[0.98]"
              >
                {isSending ? <Loader2 className="w-4 h-4 animate-spin" /> : <Send className="w-4 h-4" />}
                Send
              </button>
              <button 
                onClick={() => setIsComposeOpen(false)}
                className="p-2 text-slate-400 hover:text-red-600 dark:hover:text-red-400 hover:bg-red-50 dark:hover:bg-red-900/20 rounded-lg transition-colors"
              >
                <Trash2 className="w-5 h-5" />
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Undo Pill */}
      {showUndoPill && (
        <div className="fixed bottom-8 left-1/2 -translate-x-1/2 z-[100] animate-in fade-in slide-in-from-bottom-4 duration-300">
          <div className="bg-slate-900 dark:bg-white text-white dark:text-slate-900 px-6 py-3 rounded-full shadow-2xl flex items-center gap-4 border border-white/10 dark:border-slate-200">
            <div className="flex items-center gap-2">
              <div className="w-5 h-5 rounded-full border-2 border-indigo-500 border-t-transparent animate-spin" />
              <span className="text-sm font-medium">Sending in {countdown}s...</span>
            </div>
            <div className="w-px h-4 bg-white/20 dark:bg-slate-200" />
            <button 
              onClick={handleUndoSend}
              className="text-sm font-bold text-indigo-400 dark:text-indigo-600 hover:text-indigo-300 dark:hover:text-indigo-500 transition-colors uppercase tracking-wider"
            >
              Undo
            </button>
          </div>
        </div>
      )}

      {/* Modals */}
      {isImportModalOpen && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/60 backdrop-blur-sm">
          <div className="bg-white dark:bg-slate-900 w-full max-w-lg rounded-3xl shadow-2xl border border-slate-200 dark:border-slate-800 overflow-hidden animate-in fade-in zoom-in duration-200">
            <div className="p-6 border-b border-slate-100 dark:border-slate-800 flex items-center justify-between bg-slate-50/50 dark:bg-slate-900/50">
              <h2 className="text-xl font-bold text-slate-900 dark:text-white">Import Contacts</h2>
              <button onClick={() => setIsImportModalOpen(false)} className="p-2 hover:bg-slate-200 dark:hover:bg-slate-800 rounded-full transition-colors">
                <X className="w-5 h-5 text-slate-500" />
              </button>
            </div>
            <div className="p-6 space-y-4">
              <p className="text-sm text-slate-500 dark:text-slate-400">Paste your vCard (.vcf) data below to import contacts.</p>
              <textarea 
                value={importData}
                onChange={e => setImportData(e.target.value)}
                placeholder="BEGIN:VCARD..."
                rows={10}
                className="w-full px-4 py-3 bg-slate-50 dark:bg-slate-800 border border-slate-200 dark:border-slate-700 rounded-xl text-sm outline-none focus:ring-2 focus:ring-indigo-500/20 transition-all dark:text-white font-mono"
              />
              <div className="flex gap-3">
                <button 
                  onClick={() => setIsImportModalOpen(false)}
                  className="flex-1 px-4 py-3 border border-slate-200 dark:border-slate-700 text-slate-600 dark:text-slate-400 font-bold rounded-xl hover:bg-slate-50 dark:hover:bg-slate-800 transition-all"
                >
                  Cancel
                </button>
                <button 
                  onClick={handleImportContacts}
                  disabled={isLoading || !importData.trim()}
                  className="flex-1 px-4 py-3 bg-indigo-600 hover:bg-indigo-700 text-white font-bold rounded-xl shadow-lg shadow-indigo-500/20 transition-all active:scale-95 disabled:opacity-50 flex items-center justify-center gap-2"
                >
                  {isLoading ? <Loader2 className="w-4 h-4 animate-spin" /> : <File className="w-4 h-4" />}
                  Import Contacts
                </button>
              </div>
            </div>
          </div>
        </div>
      )}

      {isContactModalOpen && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/60 backdrop-blur-sm">
          <div className="bg-white dark:bg-slate-900 w-full max-w-md rounded-3xl shadow-2xl border border-slate-200 dark:border-slate-800 overflow-hidden animate-in fade-in zoom-in duration-200">
            <div className="p-6 border-b border-slate-100 dark:border-slate-800 flex items-center justify-between bg-slate-50/50 dark:bg-slate-900/50">
              <h2 className="text-xl font-bold text-slate-900 dark:text-white">Create Contact</h2>
              <button onClick={() => setIsContactModalOpen(false)} className="p-2 hover:bg-slate-200 dark:hover:bg-slate-800 rounded-full transition-colors">
                <X className="w-5 h-5 text-slate-500" />
              </button>
            </div>
            <form onSubmit={handleCreateContact} className="p-6 space-y-4">
              <div className="grid grid-cols-2 gap-4">
                <div className="space-y-1">
                  <label className="text-xs font-bold text-slate-400 uppercase tracking-wider">First Name *</label>
                  <input 
                    type="text" 
                    value={newContact.firstName}
                    onChange={e => {
                      setNewContact({...newContact, firstName: e.target.value});
                      if (contactErrors.firstName) {
                        const newErrors = { ...contactErrors };
                        delete newErrors.firstName;
                        setContactErrors(newErrors);
                      }
                    }}
                    placeholder="John"
                    style={contactErrors.firstName ? { border: '2px solid #ef4444' } : {}}
                    className={cn(
                      "w-full px-4 py-3 bg-slate-50 dark:bg-slate-800 border-transparent focus:bg-white dark:focus:bg-slate-700 focus:ring-2 focus:ring-indigo-500/20 rounded-xl text-sm outline-none transition-all dark:text-white",
                      contactErrors.firstName && "bg-red-50 dark:bg-red-900/10"
                    )}
                  />
                  {contactErrors.firstName && <p className="text-[10px] font-bold text-red-500 mt-1 uppercase tracking-tight">{contactErrors.firstName}</p>}
                </div>
                <div className="space-y-1">
                  <label className="text-xs font-bold text-slate-400 uppercase tracking-wider">Last Name</label>
                  <input 
                    type="text" 
                    value={newContact.lastName}
                    onChange={e => setNewContact({...newContact, lastName: e.target.value})}
                    placeholder="Doe"
                    className="w-full px-4 py-3 bg-slate-50 dark:bg-slate-800 border-transparent focus:bg-white dark:focus:bg-slate-700 focus:ring-2 focus:ring-indigo-500/20 rounded-xl text-sm outline-none transition-all dark:text-white"
                  />
                </div>
              </div>

              <div className="space-y-1">
                <label className="text-xs font-bold text-slate-400 uppercase tracking-wider">Email Address *</label>
                <div className="flex gap-2">
                  <input 
                    type="email" 
                    value={newContact.email}
                    onChange={e => {
                      setNewContact({...newContact, email: e.target.value});
                      if (contactErrors.email) {
                        const newErrors = { ...contactErrors };
                        delete newErrors.email;
                        setContactErrors(newErrors);
                      }
                    }}
                    placeholder="john@example.com"
                    style={contactErrors.email ? { border: '2px solid #ef4444' } : {}}
                    className={cn(
                      "flex-1 px-4 py-3 bg-slate-50 dark:bg-slate-800 border-transparent focus:bg-white dark:focus:bg-slate-700 focus:ring-2 focus:ring-indigo-500/20 rounded-xl text-sm outline-none transition-all dark:text-white",
                      contactErrors.email && "bg-red-50 dark:bg-red-900/10"
                    )}
                  />
                  <select
                    value={newContact.emailType}
                    onChange={e => setNewContact({...newContact, emailType: e.target.value})}
                    className="w-28 px-2 py-3 bg-slate-50 dark:bg-slate-800 border-transparent focus:bg-white dark:focus:bg-slate-700 focus:ring-2 focus:ring-indigo-500/20 rounded-xl text-sm outline-none transition-all dark:text-white"
                  >
                    <option value="private">Private</option>
                    <option value="work">Work</option>
                    <option value="other">Other</option>
                  </select>
                </div>
                {contactErrors.email && <p className="text-[10px] font-bold text-red-500 mt-1 uppercase tracking-tight">{contactErrors.email}</p>}
              </div>

              <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                <div className="space-y-1">
                  <label className="text-xs font-bold text-slate-400 uppercase tracking-wider">Phone</label>
                  <div className="flex gap-2">
                    <input 
                      type="tel" 
                      value={newContact.phone}
                      onChange={e => setNewContact({...newContact, phone: e.target.value})}
                      placeholder="+1 (555) 000-0000"
                      className="flex-1 px-4 py-3 bg-slate-50 dark:bg-slate-800 border-transparent focus:bg-white dark:focus:bg-slate-700 focus:ring-2 focus:ring-indigo-500/20 rounded-xl text-sm outline-none transition-all dark:text-white"
                    />
                    <select
                      value={newContact.phoneType}
                      onChange={e => setNewContact({...newContact, phoneType: e.target.value})}
                      className="w-24 px-2 py-3 bg-slate-50 dark:bg-slate-800 border-transparent focus:bg-white dark:focus:bg-slate-700 focus:ring-2 focus:ring-indigo-500/20 rounded-xl text-sm outline-none transition-all dark:text-white"
                    >
                      <option value="private">Private</option>
                      <option value="work">Work</option>
                      <option value="other">Other</option>
                    </select>
                  </div>
                </div>
                <div className="space-y-1">
                  <label className="text-xs font-bold text-slate-400 uppercase tracking-wider">Organization</label>
                  <input 
                    type="text" 
                    value={newContact.organization}
                    onChange={e => setNewContact({...newContact, organization: e.target.value})}
                    placeholder="Company Inc."
                    className="w-full px-4 py-3 bg-slate-50 dark:bg-slate-800 border-transparent focus:bg-white dark:focus:bg-slate-700 focus:ring-2 focus:ring-indigo-500/20 rounded-xl text-sm outline-none transition-all dark:text-white"
                  />
                </div>
              </div>
              <div className="pt-4 flex gap-3">
                <button 
                  type="button"
                  onClick={() => setIsContactModalOpen(false)}
                  className="flex-1 px-4 py-3 border border-slate-200 dark:border-slate-700 text-slate-600 dark:text-slate-400 font-bold rounded-xl hover:bg-slate-50 dark:hover:bg-slate-800 transition-all"
                >
                  Cancel
                </button>
                <button 
                  type="submit"
                  disabled={isLoading}
                  className="flex-1 px-4 py-3 bg-indigo-600 hover:bg-indigo-700 text-white font-bold rounded-xl shadow-lg shadow-indigo-500/20 transition-all active:scale-95 disabled:opacity-50 flex items-center justify-center gap-2"
                >
                  {isLoading ? <Loader2 className="w-4 h-4 animate-spin" /> : <Plus className="w-4 h-4" />}
                  Save Contact
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {isEventModalOpen && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/60 backdrop-blur-sm">
          <div className="bg-white dark:bg-slate-900 w-full max-w-md rounded-3xl shadow-2xl border border-slate-200 dark:border-slate-800 overflow-hidden animate-in fade-in zoom-in duration-200">
            <div className="p-6 border-b border-slate-100 dark:border-slate-800 flex items-center justify-between bg-slate-50/50 dark:bg-slate-900/50">
              <h2 className="text-xl font-bold text-slate-900 dark:text-white">Create Event</h2>
              <button onClick={() => setIsEventModalOpen(false)} className="p-2 hover:bg-slate-200 dark:hover:bg-slate-800 rounded-full transition-colors">
                <X className="w-5 h-5 text-slate-500" />
              </button>
            </div>
            <form onSubmit={handleCreateEvent} className="p-6 space-y-4">
              <div className="space-y-1">
                <label className="text-xs font-bold text-slate-400 uppercase tracking-wider">Event Title</label>
                <input 
                  required
                  type="text" 
                  value={newEvent.title}
                  onChange={e => setNewEvent({...newEvent, title: e.target.value})}
                  placeholder="Meeting with Team"
                  className="w-full px-4 py-3 bg-slate-50 dark:bg-slate-800 border-transparent focus:bg-white dark:focus:bg-slate-700 focus:ring-2 focus:ring-indigo-500/20 rounded-xl text-sm outline-none transition-all dark:text-white"
                />
              </div>
              <div className="space-y-1">
                <label className="text-xs font-bold text-slate-400 uppercase tracking-wider">Location</label>
                <div className="relative">
                  <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-slate-400" />
                  <input 
                    type="text" 
                    value={newEvent.location}
                    onChange={e => setNewEvent({...newEvent, location: e.target.value})}
                    placeholder="Conference Room A"
                    className="w-full pl-10 pr-4 py-3 bg-slate-50 dark:bg-slate-800 border-transparent focus:bg-white dark:focus:bg-slate-700 focus:ring-2 focus:ring-indigo-500/20 rounded-xl text-sm outline-none transition-all dark:text-white"
                  />
                </div>
              </div>
              <div className="grid grid-cols-2 gap-4">
                <div className="space-y-1">
                  <label className="text-xs font-bold text-slate-400 uppercase tracking-wider">Start Date</label>
                  <input 
                    required
                    type="date" 
                    value={newEvent.startDate}
                    onChange={e => setNewEvent({...newEvent, startDate: e.target.value})}
                    className="w-full px-4 py-3 bg-slate-50 dark:bg-slate-800 border-transparent focus:bg-white dark:focus:bg-slate-700 focus:ring-2 focus:ring-indigo-500/20 rounded-xl text-sm outline-none transition-all dark:text-white"
                  />
                </div>
                <div className="space-y-1">
                  <label className="text-xs font-bold text-slate-400 uppercase tracking-wider">Start Time</label>
                  <input 
                    required
                    type="time" 
                    value={newEvent.startTime}
                    onChange={e => setNewEvent({...newEvent, startTime: e.target.value})}
                    className="w-full px-4 py-3 bg-slate-50 dark:bg-slate-800 border-transparent focus:bg-white dark:focus:bg-slate-700 focus:ring-2 focus:ring-indigo-500/20 rounded-xl text-sm outline-none transition-all dark:text-white"
                  />
                </div>
              </div>
              <div className="space-y-1">
                <label className="text-xs font-bold text-slate-400 uppercase tracking-wider">Description</label>
                <textarea 
                  value={newEvent.description}
                  onChange={e => setNewEvent({...newEvent, description: e.target.value})}
                  placeholder="Add details about the event..."
                  rows={3}
                  className="w-full px-4 py-3 bg-slate-50 dark:bg-slate-800 border-transparent focus:bg-white dark:focus:bg-slate-700 focus:ring-2 focus:ring-indigo-500/20 rounded-xl text-sm outline-none transition-all dark:text-white resize-none"
                />
              </div>
              <div className="pt-4 flex gap-3">
                <button 
                  type="button"
                  onClick={() => setIsEventModalOpen(false)}
                  className="flex-1 px-4 py-3 border border-slate-200 dark:border-slate-700 text-slate-600 dark:text-slate-400 font-bold rounded-xl hover:bg-slate-50 dark:hover:bg-slate-800 transition-all"
                >
                  Cancel
                </button>
                <button 
                  type="submit"
                  disabled={isLoading}
                  className="flex-1 px-4 py-3 bg-indigo-600 hover:bg-indigo-700 text-white font-bold rounded-xl shadow-lg shadow-indigo-500/20 transition-all active:scale-95 disabled:opacity-50 flex items-center justify-center gap-2"
                >
                  {isLoading ? <Loader2 className="w-4 h-4 animate-spin" /> : <Plus className="w-4 h-4" />}
                  Save Event
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
      {/* Expiration Modal */}
      {isExpirationModalOpen && (
        <div className="fixed inset-0 z-[60] flex items-center justify-center p-4 bg-black/40 backdrop-blur-sm">
          <div className="bg-white dark:bg-slate-900 w-full max-w-[320px] rounded-3xl shadow-2xl border border-slate-200 dark:border-slate-800 overflow-hidden animate-in fade-in zoom-in duration-200">
            <div className="p-4 border-b border-slate-100 dark:border-slate-800 flex items-center justify-between">
              <h3 className="font-bold text-slate-900 dark:text-white">Select Expiration</h3>
              <button onClick={() => setIsExpirationModalOpen(false)} className="p-1 hover:bg-slate-100 dark:hover:bg-slate-800 rounded-full">
                <X className="w-4 h-4 text-slate-500" />
              </button>
            </div>
            <div className="p-2">
              {expirationOptions.map((option) => (
                <button
                  key={option.value}
                  onClick={() => {
                    setExpiration(option.value);
                    setIsExpirationModalOpen(false);
                  }}
                  className={cn(
                    "w-full px-4 py-3 flex items-center justify-between rounded-xl transition-colors",
                    expiration === option.value ? "bg-indigo-50 dark:bg-indigo-500/10 text-indigo-600 dark:text-indigo-400" : "hover:bg-slate-50 dark:hover:bg-slate-800 text-slate-700 dark:text-slate-300"
                  )}
                >
                  <span className="font-medium">{option.label}</span>
                  {expiration === option.value && <div className="w-2 h-2 rounded-full bg-indigo-500" />}
                </button>
              ))}
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
