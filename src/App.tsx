import React, { useState, useEffect, useCallback, useRef } from "react";
import { 
  Inbox, Send, File, AlertCircle, Trash2, Menu, Search, 
  Settings, User, ChevronDown, Star, Archive, MoreVertical,
  Reply, Forward, X, Edit3, Mail, LogOut, Loader2, Server,
  Calendar, Users, RefreshCw, Lock, Clock, Key, Shield, Plus, ExternalLink,
  Sparkles, Download, Upload, Bell, Check, MailCheck, Sun, Filter, ArrowLeft, Paperclip,
  ChevronLeft, ChevronRight, Edit2, Save, Phone
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
  const [decryptedData, setDecryptedData] = useState<{ subject: string, body: string, attachments?: any[] } | null>(null);
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

  const downloadAttachment = (att: any) => {
    try {
      const byteCharacters = atob(att.data);
      const byteNumbers = new Array(byteCharacters.length);
      for (let i = 0; i < byteCharacters.length; i++) {
        byteNumbers[i] = byteCharacters.charCodeAt(i);
      }
      const byteArray = new Uint8Array(byteNumbers);
      const blob = new Blob([byteArray], { type: att.type });
      
      const url = window.URL.createObjectURL(blob);
      const link = document.createElement('a');
      link.href = url;
      link.download = att.name;
      document.body.appendChild(link);
      link.click();
      document.body.removeChild(link);
      window.URL.revokeObjectURL(url);
    } catch (err) {
      console.error("Failed to download attachment", err);
      toast.error("Failed to download attachment");
    }
  };

  const isImage = (type: string) => type.startsWith('image/');
  const [previews, setPreviews] = useState<Record<string, string>>({});

  useEffect(() => {
    if (decryptedData?.attachments) {
      const newPreviews: Record<string, string> = {};
      decryptedData.attachments.forEach((att, idx) => {
        if (isImage(att.type)) {
          try {
            const byteCharacters = atob(att.data);
            const byteNumbers = new Array(byteCharacters.length);
            for (let i = 0; i < byteCharacters.length; i++) {
              byteNumbers[i] = byteCharacters.charCodeAt(i);
            }
            const byteArray = new Uint8Array(byteNumbers);
            const blob = new Blob([byteArray], { type: att.type });
            newPreviews[`att-${idx}`] = URL.createObjectURL(blob);
          } catch (e) {
            console.error("Failed to create preview", e);
          }
        }
      });
      setPreviews(newPreviews);
      
      return () => {
        Object.values(newPreviews).forEach(url => URL.revokeObjectURL(url));
      };
    }
  }, [decryptedData]);

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

                {decryptedData.attachments && decryptedData.attachments.length > 0 && (
                  <div className="mt-8 pt-8 border-t border-indigo-100 dark:border-indigo-500/20">
                    <h3 className="text-sm font-bold text-slate-400 uppercase tracking-widest mb-4">Secure Attachments</h3>
                    <div className="space-y-4">
                      {decryptedData.attachments.map((att, idx) => (
                        <div key={idx} className="space-y-3">
                          <button
                            onClick={() => downloadAttachment(att)}
                            className="w-full flex items-center gap-3 px-4 py-3 bg-white dark:bg-slate-800 border border-slate-200 dark:border-slate-700 rounded-2xl hover:border-indigo-500 hover:shadow-lg hover:shadow-indigo-500/10 transition-all group"
                          >
                            <div className="w-10 h-10 rounded-xl bg-slate-50 dark:bg-slate-900 flex items-center justify-center text-indigo-500 group-hover:bg-indigo-500 group-hover:text-white transition-colors">
                              <Download className="w-5 h-5" />
                            </div>
                            <div className="text-left flex-1">
                              <div className="text-sm font-bold text-slate-900 dark:text-white group-hover:text-indigo-500 transition-colors">{att.name}</div>
                              <div className="text-xs text-slate-500 dark:text-slate-500">{(att.size / 1024 / 1024).toFixed(2)} MB</div>
                            </div>
                            <div className="opacity-0 group-hover:opacity-100 transition-opacity pr-2">
                              <div className="px-3 py-1 bg-indigo-50 dark:bg-indigo-500/10 text-indigo-600 dark:text-indigo-400 rounded-full text-[10px] font-bold uppercase tracking-wider">Download</div>
                            </div>
                          </button>
                          
                          {isImage(att.type) && previews[`att-${idx}`] && (
                            <div className="rounded-2xl overflow-hidden border border-slate-200 dark:border-slate-800 bg-black/5 dark:bg-white/5 relative group/img">
                              <img 
                                src={previews[`att-${idx}`]} 
                                alt={att.name} 
                                className="w-full h-auto max-h-[400px] object-contain transition-transform duration-500 hover:scale-[1.02]"
                                referrerPolicy="no-referrer"
                              />
                              <div className="absolute inset-0 bg-black/40 opacity-0 group-hover/img:opacity-100 transition-opacity flex items-center justify-center backdrop-blur-[2px]">
                                <button 
                                  onClick={() => window.open(previews[`att-${idx}`], '_blank')}
                                  className="px-6 py-2 bg-white text-black rounded-full font-bold text-sm shadow-xl hover:bg-slate-100 transition-all active:scale-95"
                                >
                                  View Full Size
                                </button>
                              </div>
                            </div>
                          )}
                        </div>
                      ))}
                    </div>
                  </div>
                )}
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

function AttachmentRenderer({ attachment, client }: { attachment: any, client: JmapClient, key?: any }) {
  const [objectUrl, setObjectUrl] = useState<string | null>(null);
  const [isLoading, setIsLoading] = useState(false);

  useEffect(() => {
    let currentUrl: string | null = null;
    const fetchBlob = async () => {
      setIsLoading(true);
      try {
        const blob = await client.getAttachmentBlob(attachment.blobId, attachment.name, attachment.type);
        currentUrl = URL.createObjectURL(blob);
        setObjectUrl(currentUrl);
      } catch (err) {
        console.error("Failed to load attachment blob", err);
      } finally {
        setIsLoading(false);
      }
    };

    fetchBlob();
    return () => {
      if (currentUrl) URL.revokeObjectURL(currentUrl);
    };
  }, [attachment, client]);

  if (isLoading) {
    return (
      <div className="flex items-center gap-2 px-4 py-2 bg-slate-100 dark:bg-slate-800 rounded-full animate-pulse mt-2">
        <Loader2 className="w-4 h-4 animate-spin text-indigo-500" />
        <span className="text-xs text-slate-500 font-medium">Fetching secure blob...</span>
      </div>
    );
  }

  if (!objectUrl) return null;

  if (attachment.type.startsWith('image/')) {
    return (
      <div className="mt-4 group relative inline-block">
        <img 
          src={objectUrl} 
          alt={attachment.name} 
          className="max-w-full h-auto rounded-xl shadow-lg border border-slate-200 dark:border-slate-800 transition-all hover:ring-4 hover:ring-indigo-500/10" 
          referrerPolicy="no-referrer"
          onClick={() => window.open(objectUrl, '_blank')}
        />
        <div className="absolute top-3 right-3 opacity-0 group-hover:opacity-100 transition-opacity">
          <a href={objectUrl} download={attachment.name} className="p-2 bg-white/90 dark:bg-black/90 backdrop-blur-sm rounded-lg shadow-xl text-slate-700 dark:text-slate-300 hover:text-indigo-600 transition-colors">
            <Download className="w-4 h-4" />
          </a>
        </div>
      </div>
    );
  }

  return (
    <a 
      href={objectUrl} 
      download={attachment.name} 
      className="inline-flex items-center gap-2 px-4 py-2.5 bg-slate-100 hover:bg-slate-200 dark:bg-slate-800 dark:hover:bg-slate-700 text-slate-800 dark:text-slate-200 rounded-xl text-sm font-semibold transition-all shadow-sm border border-slate-200/50 dark:border-slate-700/50 mt-2 hover:scale-105 active:scale-95"
    >
      <Paperclip className="w-4 h-4 text-indigo-500" /> 
      <span className="max-w-[200px] truncate">{attachment.name}</span>
      <span className="text-[10px] text-slate-400 font-normal">({Math.round(attachment.size / 1024)} KB)</span>
    </a>
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
    const saved = localStorage.getItem("webmail_dark_mode");
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
    localStorage.setItem("webmail_dark_mode", isDarkMode.toString());
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
  const [isAddingIdentity, setIsAddingIdentity] = useState(false);
  const [selectedEmailIds, setSelectedEmailIds] = useState<string[]>([]);
  const [activeApp, setActiveApp] = useState<'mail' | 'contacts' | 'calendar' | 'settings'>('mail');
  const [isSidebarOpen, setIsSidebarOpen] = useState(false);
  const [isComposeOpen, setIsComposeOpen] = useState(false);
  const [editingTemplateId, setEditingTemplateId] = useState<string | null>(null);
  const [contextMenuEmail, setContextMenuEmail] = useState<Email | null>(null);
  const [isEmailActionsOpen, setIsEmailActionsOpen] = useState(false);
  const [isContactModalOpen, setIsContactModalOpen] = useState(false);
  const [isEventModalOpen, setIsEventModalOpen] = useState(false);
  const [isImportModalOpen, setIsImportModalOpen] = useState(false);
  const [importData, setImportData] = useState("");
  const [contactSuggestions, setContactSuggestions] = useState<any[]>([]);
  const [newContact, setNewContact] = useState({ firstName: '', lastName: '', email: '', emailType: 'private', phone: '', phoneType: 'private', organization: '', notes: '' });
  const [contactErrors, setContactErrors] = useState<Record<string, string>>({});
  const [newEvent, setNewEvent] = useState({ title: '', description: '', location: '', startDate: format(new Date(), 'yyyy-MM-dd'), startTime: '09:00', endDate: format(new Date(), 'yyyy-MM-dd'), endTime: '10:00', timeZone: Intl.DateTimeFormat().resolvedOptions().timeZone });
  const [eventErrors, setEventErrors] = useState<Record<string, string>>({});
  const [contactSearchQuery, setContactSearchQuery] = useState("");
  const [eventSearchQuery, setEventSearchQuery] = useState("");
  const [isSettingsSection, setIsSettingsSection] = useState<'general' | 'account' | 'security' | 'advanced' | 'notifications' | 'vacation' | 'templates' | 'filters' | 'contacts'>(() => {
    return (localStorage.getItem('webmail_settings_section') as any) || 'account';
  });
  const [isSettingsMenuOpen, setIsSettingsMenuOpen] = useState(false);
  const [vacationEnabled, setVacationEnabled] = useState(false);
  const [vacationSubject, setVacationSubject] = useState("");
  const [vacationText, setVacationText] = useState("");
  const [isSavingVacation, setIsSavingVacation] = useState(false);
  const [isHeaderExpanded, setIsHeaderExpanded] = useState(false);
  const [isLoading, setIsLoading] = useState(false);
  const [isSyncing, setIsSyncing] = useState(false);
  const [selectedCalendarDate, setSelectedCalendarDate] = useState<Date | null>(null);
  const [currentCalendarDate, setCurrentCalendarDate] = useState<Date>(new Date());
  const [selectedEvent, setSelectedEvent] = useState<any | null>(null);
  const [selectedContact, setSelectedContact] = useState<any | null>(null);
  const [isEditingContact, setIsEditingContact] = useState(false);
  const [isContactPickerOpen, setIsContactPickerOpen] = useState(false);
  const [contactPickerSearch, setContactPickerSearch] = useState("");
  const [selectedContactIds, setSelectedContactIds] = useState<string[]>([]);
  const [lastSync, setLastSync] = useState<Date>(new Date());
  const [editingContactData, setEditingContactData] = useState<any>(null);
  const [isAccountMenuOpen, setIsAccountMenuOpen] = useState(false);
  const [confirmDialog, setConfirmDialog] = useState<{
    isOpen: boolean;
    title: string;
    message: string;
    confirmText: string;
    onConfirm: () => void;
  }>({
    isOpen: false,
    title: "",
    message: "",
    confirmText: "Delete",
    onConfirm: () => {}
  });

  const requireConfirm = (title: string, message: string, onConfirm: () => void, confirmText = "Delete") => {
    setConfirmDialog({ isOpen: true, title, message, onConfirm, confirmText });
  };
  
  // Track credentials identity to cancel stale promises during account switches
  const currentUsernameRef = React.useRef(credentials?.username);

  // Clear state when account changes
  useEffect(() => {
    currentUsernameRef.current = credentials?.username;
    setMailboxes([]);
    setEmails([]);
    setSelectedMailbox("");
    setSelectedEmail(null);
  }, [credentials]);

  const [viewportHeight, setViewportHeight] = useState('100%');
  
  useEffect(() => {
    if (!window.visualViewport) return;
    
    const handler = () => {
      if (window.visualViewport) {
        setViewportHeight(`${window.visualViewport.height}px`);
      }
    };
    
    window.visualViewport.addEventListener('resize', handler);
    window.visualViewport.addEventListener('scroll', handler);
    return () => {
      window.visualViewport?.removeEventListener('resize', handler);
      window.visualViewport?.removeEventListener('scroll', handler);
    };
  }, []);

  // Sieve Engine State
  const [filterPromotions, setFilterPromotions] = useState(() => localStorage.getItem('webmail_filter_promo') === 'true');
  const [filterSocial, setFilterSocial] = useState(() => localStorage.getItem('webmail_filter_social') === 'true');
  const [filterUpdates, setFilterUpdates] = useState(() => localStorage.getItem('webmail_filter_updates') === 'true');

  const compileAndPushSieve = async (promo: boolean, social: boolean, updates: boolean) => {
    if (!credentials) return;
    let script = 'require ["fileinto", "mailbox"];\n\n';
    if (promo) script += 'if header :contains "list-unsubscribe" "" { fileinto :create "Promotions"; stop; }\n';
    if (social) script += 'if address :domain :is "from" ["linkedin.com", "twitter.com", "facebook.com", "instagram.com"] { fileinto :create "Social"; stop; }\n';
    if (updates) script += 'if header :contains "subject" ["receipt", "invoice", "order", "tracking"] { fileinto :create "Updates"; stop; }\n';
    
    try {
      const client = new JmapClient(credentials);
      await client.updateSieveScript(script);
      toast.success("Mail rules updated");
    } catch (e: any) {
      toast.error(e.message || "Failed to update mail rules");
    }
  };
  
  // Server-Side Template State
  const [serverTemplates, setServerTemplates] = useState<Email[]>([]);
  const [isLoadingTemplates, setIsLoadingTemplates] = useState(false);
  const [isTemplateSelectorOpen, setIsTemplateSelectorOpen] = useState(false);
  const [isContactSelectorModalOpen, setIsContactSelectorModalOpen] = useState(false);

  const handleExportServerTemplates = async () => {
    if (!credentials) return;
    setIsLoading(true);
    try {
      const tplMailbox = mailboxes.find(m => m.role === 'templates' || m.name.toLowerCase() === 'templates');
      if (!tplMailbox) throw new Error("Templates mailbox not found on server");
      
      const client = new JmapClient(credentials);
      const templates = await client.getEmails(tplMailbox.id);
      
      const exportData = templates.map(t => ({
        subject: t.subject,
        body: t.body,
        preview: t.preview
      }));
      
      const blob = new Blob([JSON.stringify(exportData, null, 2)], { type: "application/json" });
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = "webmail-templates-backup.json";
      a.click();
      URL.revokeObjectURL(url);
      toast.success(`Exported ${templates.length} templates`);
    } catch (e: any) {
      toast.error(e.message || "Failed to export templates");
    } finally {
      setIsLoading(false);
    }
  };

  const handleImportServerTemplates = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file || !credentials) return;
    setIsLoading(true);
    
    const reader = new FileReader();
    reader.onload = async (event) => {
      try {
        const parsed = JSON.parse(event.target?.result as string);
        if (!Array.isArray(parsed)) throw new Error("Invalid format");
        
        const tplMailbox = mailboxes.find(m => m.role === 'templates' || m.name.toLowerCase() === 'templates');
        if (!tplMailbox) throw new Error("Templates mailbox not found on server");

        const client = new JmapClient(credentials);
        const creates: Record<string, any> = {};
        
        parsed.forEach((tpl, idx) => {
          creates[`tpl-${idx}`] = {
            mailboxIds: { [tplMailbox.id]: true },
            keywords: { "$draft": true, "$seen": true },
            subject: tpl.subject || "No Subject",
            bodyValues: { "1": { value: tpl.body || "" } },
            textBody: [{ partId: "1" }]
          };
        });

        await client.request([
          ["Email/set", { accountId: credentials.accountId, create: creates }, "0"]
        ]);
        
        toast.success(`Successfully imported ${parsed.length} templates to the server!`);
        fetchMailboxes(); // Refresh counts
      } catch (error: any) {
        toast.error(error.message || "Failed to import templates");
      } finally {
        setIsLoading(false);
      }
    };
    reader.readAsText(file);
    e.target.value = ''; // Reset input
  };

  const [isIdentityDropdownOpen, setIsIdentityDropdownOpen] = useState(false);
  const [isSecureMessage, setIsSecureMessage] = useState(false);
  const [isScheduling, setIsScheduling] = useState(false);
  const [scheduleTime, setScheduleTime] = useState("");
  const [scheduledJobs, setScheduledJobs] = useState<Record<string, number>>({});
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

  // THE FIX: Reset compose states on modal close to prevent state bleeding between drafts
  useEffect(() => {
    if (!isComposeOpen) {
      setIsScheduling(false);
      setScheduleTime("");
    }
  }, [isComposeOpen]);

  // Settings & Vacation State
  const [notificationsEnabled, setNotificationsEnabled] = useState(() => {
    return localStorage.getItem('webmail_notifications') === 'true';
  });
  const [soundEffectsEnabled, setSoundEffectsEnabled] = useState(() => {
    return localStorage.getItem('webmail_sound_effects') === 'true';
  });
  const currentTimeZone = Intl.DateTimeFormat().resolvedOptions().timeZone;

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
    if (!credentials) return;
    setSelectedIdentityId(identityId);
    localStorage.setItem(`webmail_default_identity_${credentials.accountId}`, identityId);
    toast.success("Default identity updated");
  };

  useEffect(() => {
    localStorage.setItem('webmail_settings_section', isSettingsSection);
  }, [isSettingsSection]);

  useEffect(() => {
    localStorage.setItem('webmail_sound_effects', soundEffectsEnabled.toString());
  }, [soundEffectsEnabled]);

  const sortedIdentities = [...identities].sort((a, b) => {
    if (a.id === selectedIdentityId) return -1;
    if (b.id === selectedIdentityId) return 1;
    return 0;
  });

  const getContactName = (contact: any): string => {
    if (!contact) return "Unknown Contact";
    if (contact.fullName) return contact.fullName;
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
      if (firstEmail) return firstEmail.address || firstEmail.email || firstEmail.value || "Unknown Contact";
    }
    if (contact.email) return contact.email;
    
    return "Unknown Contact";
  };

  const getContactEmail = (contact: any): string => {
    if (!contact) return "";
    if (typeof contact.email === 'string') return contact.email;
    if (contact.emails && typeof contact.emails === 'object') {
      const firstEmail = Object.values(contact.emails)[0] as any;
      return firstEmail?.address || firstEmail?.email || firstEmail?.value || "";
    }
    return "";
  };

  const filteredEmails = emails.filter(email => {
    // 1. Search Filter
    const query = searchQuery.toLowerCase();
    const matchesSearch = (
      (email.subject || "").toLowerCase().includes(query) ||
      (email.from?.name || "").toLowerCase().includes(query) ||
      (email.from?.email || "").toLowerCase().includes(query) ||
      (email.body || "").toLowerCase().includes(query)
    );
    if (!matchesSearch) return false;

    // 2. Virtual Folder Segregation
    const draftsId = mailboxes.find(m => m.role === 'drafts')?.id;
    const isScheduled = !!scheduledJobs[email.id];

    if (selectedMailbox === 'virtual-scheduled') {
      return isScheduled; // Show ONLY scheduled items
    }
    if (selectedMailbox === draftsId) {
      return !isScheduled; // HIDE scheduled items from standard drafts
    }
    
    return true;
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
      const fullName = getContactName(c);
      vcard += `FN:${fullName}\n`;
      
      const emails = c.emails ? (typeof c.emails === 'object' ? Object.values(c.emails) : []) : [];
      emails.forEach((e: any) => vcard += `EMAIL;TYPE=INTERNET:${e.address || e.email || e.value}\n`);
      
      const phones = c.phones ? (typeof c.phones === 'object' ? Object.values(c.phones) : []) : [];
      phones.forEach((p: any) => vcard += `TEL;TYPE=VOICE:${p.number || p.value}\n`);
      
      if (c.organizations && Array.isArray(c.organizations)) {
        vcard += `ORG:${c.organizations.map((o: any) => o.name).join('; ')}\n`;
      } else if (c.company) {
        vcard += `ORG:${c.company}\n`;
      }
      
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
      const fullName = `${newContact.firstName.trim()} ${newContact.lastName.trim()}`.trim();
      const createdContact = await client.createContact(
        fullName,
        newContact.email,
        newContact.phone,
        newContact.notes
      );

      setContacts(prev => [...prev, createdContact]);
      setIsContactModalOpen(false);
      setNewContact({ firstName: '', lastName: '', email: '', emailType: 'private', phone: '', phoneType: 'private', organization: '', notes: '' });
      setContactErrors({});
      toast.success("Contact created successfully");
    } catch (error: any) {
      console.error("Failed to create contact:", error);
      toast.error(`Failed to create contact: ${error.message}`);
    } finally {
      setIsLoading(false);
    }
  };

  const handleDeleteContact = (contactId: string) => {
    requireConfirm(
      "Delete Contact",
      "Are you sure you want to delete this contact? This action cannot be undone.",
      async () => {
        setIsLoading(true);
        try {
          if (!credentials) throw new Error("Not logged in");
          const client = new JmapClient(credentials);
          await client.deleteContact(contactId);
          
          setContacts(prev => prev.filter(c => c.id !== contactId));
          setSelectedContactIds(prev => prev.filter(id => id !== contactId));
          
          if (selectedContact?.id === contactId) setSelectedContact(null);
          
          toast.success("Contact deleted");
        } catch (err: any) {
          console.error("Failed to delete contact:", err);
          toast.error(err.message || "Failed to delete contact");
        } finally {
          setIsLoading(false);
        }
      }
    );
  };

  const handleDeleteEvent = (eventId: string) => {
    requireConfirm(
      "Delete Event",
      "Are you sure you want to delete this event? This action cannot be undone.",
      async () => {
        setIsLoading(true);
        try {
          if (!credentials) throw new Error("Not logged in");
          const client = new JmapClient(credentials);
          await client.deleteEvent(eventId);
          setEvents(prev => prev.filter(e => e.id !== eventId));
          if (selectedEvent?.id === eventId) setSelectedEvent(null);
          toast.success("Event deleted");
        } catch (err: any) {
          console.error("Failed to delete event:", err);
          toast.error("Failed to delete event");
        } finally {
          setIsLoading(false);
        }
      }
    );
  };

  const handleBulkDeleteContacts = () => {
    if (selectedContactIds.length === 0) return;
    
    requireConfirm(
      "Delete Contacts",
      `Are you sure you want to delete ${selectedContactIds.length} contacts? This action cannot be undone.`,
      async () => {
        setIsLoading(true);
        try {
          if (!credentials) throw new Error("Not logged in");
          const client = new JmapClient(credentials);
          
          await client.deleteContacts(selectedContactIds);
          
          setContacts(prev => prev.filter(c => !selectedContactIds.includes(c.id)));
          setSelectedContactIds([]);
          toast.success(`${selectedContactIds.length} contacts deleted`);
        } catch (err: any) {
          console.error("Bulk delete failed", err);
          toast.error("Failed to delete some contacts");
        } finally {
          setIsLoading(false);
        }
      }
    );
  };

  useEffect(() => {
    if (selectedContact) {
      const email = getContactEmail(selectedContact);
      let phone = "";
      if (selectedContact.phones && typeof selectedContact.phones === 'object') {
        phone = (Object.values(selectedContact.phones)[0] as any)?.number || "";
      }
      setEditingContactData({
        fullName: getContactName(selectedContact),
        email: email,
        phone: phone,
        notes: selectedContact.notes || ""
      });
    } else {
      setEditingContactData(null);
    }
  }, [selectedContact]);

  const handleUpdateContact = async () => {
    if (!selectedContact || !editingContactData) return;
    
    setIsLoading(true);
    try {
      if (!credentials) throw new Error("Not logged in");
      const client = new JmapClient(credentials);
      
      const parsedNameParts = editingContactData.fullName.trim().split(' ');
      const firstName = parsedNameParts[0] || "";
      const lastName = parsedNameParts.slice(1).join(' ');

      const patches: any = {
        name: {
          components: [
            { kind: "given", value: firstName },
            ...(lastName ? [{ kind: "surname", value: lastName }] : [])
          ],
          isOrdered: true
        },
        notes: editingContactData.notes.trim()
      };
      
      if (editingContactData.email.trim()) {
        const emailKey = (selectedContact.emails && typeof selectedContact.emails === 'object' && Object.keys(selectedContact.emails)[0]) || "e1";
        patches.emails = {
          ...selectedContact.emails,
          [emailKey]: { 
             ...(selectedContact.emails?.[emailKey] || {}),
             address: editingContactData.email.trim(),
             contexts: { private: true }
          }
        };
      }

      if (editingContactData.phone.trim()) {
        const phoneKey = (selectedContact.phones && typeof selectedContact.phones === 'object' && Object.keys(selectedContact.phones)[0]) || "p1";
        patches.phones = {
          ...selectedContact.phones,
          [phoneKey]: { 
             ...(selectedContact.phones?.[phoneKey] || {}),
             number: editingContactData.phone.trim(),
             contexts: { private: true }
          }
        };
      }

      await client.updateContact(selectedContact.id, patches);
      
      // Update local state
      setContacts(prev => prev.map(c => c.id === selectedContact.id ? { ...c, ...patches } : c));
      setSelectedContact(null);
      setIsEditingContact(false);
      toast.success("Contact updated successfully");
    } catch (error: any) {
      console.error("Failed to update contact:", error);
      toast.error(`Update failed: ${error.message}`);
    } finally {
      setIsLoading(false);
    }
  };

  const handleCreateEvent = async (e: React.FormEvent) => {
    e.preventDefault();
    
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
      
      // FIXED: Fallback strictly to 'b' which is Stalwart's default
      const calendarId = calendars[0]?.id || "b"; 

      // FIXED: Generate mandatory UID
      const uid = window.crypto && window.crypto.randomUUID ? window.crypto.randomUUID() : `event-${Date.now()}`;

      // FIXED: Calculate ISO 8601 Duration (e.g. "PT1H")
      const startObj = new Date(`${newEvent.startDate}T${newEvent.startTime}`);
      const endObj = new Date(`${newEvent.endDate}T${newEvent.endTime}`);
      let diffMins = Math.floor((endObj.getTime() - startObj.getTime()) / 60000);
      if (diffMins <= 0) diffMins = 60; // Default 1 hr
      const hours = Math.floor(diffMins / 60);
      const mins = diffMins % 60;
      const durationStr = `PT${hours > 0 ? hours + 'H' : ''}${mins > 0 ? mins + 'M' : ''}`;

      const createdEvent = await client.createEvent({
        calendarIds: { [calendarId]: true }, // FIXED: Flattened map structure
        uid: uid,                            // FIXED: Mandatory UID
        title: newEvent.title,
        description: newEvent.description,
        start: `${newEvent.startDate}T${newEvent.startTime}:00`,
        timeZone: newEvent.timeZone,
        duration: durationStr                // FIXED: Mandatory duration
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
  const [draftAttachments, setDraftAttachments] = useState<Array<{file?: File, blobId: string, name: string, type: string, size: number}>>([]);
  const [isUploading, setIsUploading] = useState(false);
  const [newIdentityName, setNewIdentityName] = useState('');
  const [newIdentityEmail, setNewIdentityEmail] = useState('');

  const handleFileUpload = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const files = e.target.files;
    if (!files || files.length === 0 || !credentials) return;
    
    setIsUploading(true);
    const client = new JmapClient(credentials);
    const newAttachments = [];

    try {
      for (let i = 0; i < files.length; i++) {
        const file = files[i];
        
        // If it's NOT a secure message, we upload to JMAP immediately
        // If it IS a secure message, we might still want to upload to get a blobId if needed,
        // but for secure storage we definitely need the raw file.
        // The spec says: "use the same method to create a secure mail and then it will be decrypted to the client"
        
        let blobId = "";
        try {
          const response = await client.uploadBlob(file, credentials.accountId);
          blobId = response.blobId;
        } catch (err: any) {
          console.error("JMAP upload failed", err);
          // Only show error if it's NOT a secure message (because secure messages fallback to base64)
          // But wait, we don't know if the user WANTS it secure yet. 
          // So let's just log it and if they send standard mail later it will warn them.
          if (!isSecureMessage) {
            toast.error(`JMAP Upload failed for ${file.name}: ${err.message}`);
          }
        }

        newAttachments.push({
          file: file, // Store the file object for secure encryption
          blobId: blobId,
          name: file.name,
          type: file.type || 'application/octet-stream',
          size: file.size
        });
      }
      setDraftAttachments(prev => [...prev, ...newAttachments]);
    } catch (error) {
      toast.error("Failed to upload attachment");
    } finally {
      setIsUploading(false);
      if (e.target) e.target.value = ''; // reset input
    }
  };

  const formatFileSize = (bytes: number) => {
    if (bytes === 0) return '0 Bytes';
    const k = 1024;
    const sizes = ['Bytes', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
  };

  const fileToBase64 = (file: File): Promise<string> => {
    return new Promise((resolve, reject) => {
      const reader = new FileReader();
      reader.readAsDataURL(file);
      reader.onload = () => {
        const result = reader.result as string;
        // Strip the data:prefix
        const base64 = result.split(',')[1];
        resolve(base64);
      };
      reader.onerror = error => reject(error);
    });
  };

  const handleSendEmail = async (isScheduled = false) => {
    if (isSending || pendingSend) return;

    // Merge chip addresses and raw input text
    const inputAddresses = toInput
      .split(',')
      .map(email => email.trim())
      .filter(email => email.length > 0);
    
    // Combine both sources and deduplicate
    const finalToAddresses = [...new Set([...toAddresses, ...inputAddresses])];
    
    if (finalToAddresses.length === 0) {
      toast.error("Please enter at least one recipient");
      return;
    }

    if (!emailBody && !isSecureMessage) {
      toast.error("Message body cannot be empty");
      return;
    }

    if (isScheduling && scheduleTime) {
      try {
        // 1. Get the Selected Identity
        const identity = identities.find(i => i.id === selectedIdentityId) || identities[0];
        if (!identity) throw new Error("No identity found");
        const identityId = identity.id;

        let finalBody = emailBody;
        let finalSubject = subject || "No Subject";
        let isSecure = false;

        // Handle Secure Encryption for Scheduled Mails
        if (isSecureMessage) {
          const totalSize = (draftAttachments || []).reduce((acc, att) => acc + att.size, 0);
          if (totalSize > 10 * 1024 * 1024) throw new Error("Secure attachments must be < 10MB");

          const encryptedAttachments = [];
          for (const att of draftAttachments) {
            if (att.file) {
              const base64 = await fileToBase64(att.file);
              encryptedAttachments.push({ name: att.name, type: att.type, size: att.size, data: base64 });
            }
          }

          let password = useAutomaticKey ? Array.from(crypto.getRandomValues(new Uint8Array(16))).map(b => b.toString(16).padStart(2, '0')).join('') : securePassword;
          if (!password) throw new Error("Secure password required");

          const { encryptedPayload, iv, salt } = await encryptData(JSON.stringify({ subject: finalSubject, body: finalBody, attachments: encryptedAttachments }), password);
          const storeRes = await fetch('/api/secure-store', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ encryptedPayload, iv, salt, expiration, viewOnce: expiration === 'burn' })
          });
          if (!storeRes.ok) throw new Error("Secure store failed");
          const { id } = await storeRes.json();
          const secureUrl = useAutomaticKey ? `${window.location.origin}/secure/${id}#${password}` : `${window.location.origin}/secure/${id}`;
          const expText = { "5min": "5 minutes", "1hour": "1 hour", "1day": "1 day", "1week": "1 week", "burn": "after reading" };
          finalBody = `You have received a secure message from Sunil Shahid. It will expire in ${expText[expiration as keyof typeof expText] || "1 day"}. Link: ${secureUrl}`;
          finalSubject = `🔒 Secure message from Sunil Shahid`;
          isSecure = true;
        }

        const client = new JmapClient(credentials);

        // 2. Safely create the draft (Secure emails have NO standard attachments)
        const actualDraftId = await client.createDraft(
          finalToAddresses,           // to
          finalSubject,               // subject
          finalBody,                  // body
          undefined,                  // cc
          undefined,                  // bcc
          identityId,                 // identityId
          identity.email,             // fromEmail
          undefined,                  // draftId
          isSecure ? [] : draftAttachments.filter(a => a.blobId), // THE FIX: No standard att if secure
          identity.name               // fromName
        );

        // Find Sent mailbox ID
        const sentMailbox = mailboxes.find(m => m.role === 'sent') || mailboxes.find(m => m.name.toLowerCase().includes('sent')) || mailboxes[0];

        // 3. Dispatch to Node.js queue
        const response = await fetch('/api/schedule-send', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            executeAt: new Date(scheduleTime).getTime(),
            draftId: actualDraftId, // <-- THE FIX: Uses the correct variable
            identityId: identityId,
            accountId: credentials.accountId,
            apiUrl: credentials.apiUrl,
            serverUrl: credentials.serverUrl,
            username: credentials.username,
            password: credentials.password,
            sentMailboxId: sentMailbox.id
          })
        });
        
        if (!response.ok) throw new Error("Failed to schedule on backend");
        
        toast.success("Email scheduled successfully!");
        setIsComposeOpen(false);
        setDraftAttachments([]);
        setToAddresses([]);
        setToInput('');
        setSubject('');
        setEmailBody('');
        return; // Exit function so it bypasses standard sending
      } catch (error: any) {
        toast.error(`Failed to schedule: ${error.message}`);
        return;
      }
    }
    
    // Delayed Send Logic
    if (!pendingSend) {
      const emailData = {
        toAddresses: finalToAddresses,
        subject: subject || "No Subject",
        body: emailBody,
        attachments: [...draftAttachments],
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
      setEmailBody(pendingSend.body);
      setDraftAttachments(pendingSend.attachments || []);
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
        // Strict limit check for secure mail attachments
        const totalSize = (emailData.attachments || []).reduce((acc: number, att: any) => acc + att.size, 0);
        if (totalSize > 10 * 1024 * 1024) {
           throw new Error("Secure message attachments must be less than 10MB total");
        }

        const { useAutomaticKey, securePassword, expiration } = emailData.secureConfig;
        
        // Prepare attachments for secure storage (convert to base64)
        const encryptedAttachments = [];
        if (emailData.attachments && emailData.attachments.length > 0) {
          for (const att of emailData.attachments) {
            if (att.file) {
              const base64 = await fileToBase64(att.file);
              encryptedAttachments.push({
                name: att.name,
                type: att.type,
                size: att.size,
                data: base64
              });
            }
          }
        }

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
          JSON.stringify({ 
            subject: finalSubject, 
            body: finalBody,
            attachments: encryptedAttachments
          }), 
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
      
      // THE FIX: Standard attachments should be empty for secure emails
      // because they are already bundled INSIDE the encrypted payload.
      const standardAttachments = emailData.isSecure 
        ? [] 
        : (emailData.attachments || [])
            .filter((att: any) => att.blobId)
            .map((att: any) => ({
              blobId: att.blobId,
              name: att.name,
              type: att.type,
              size: att.size
            }));

      await client.sendEmail(
        emailData.toAddresses,
        finalSubject,
        finalBody,
        undefined, // cc
        undefined, // bcc
        identityId, // identityId
        identity.email, // <-- THE FIX: Pass the actual email address
        undefined, // draftId
        identity.name, // <-- THE FIX: Pass the display name
        standardAttachments
      );

      toast.success("Email sent successfully!");
      
      // Reset compose state
      setDraftAttachments([]);
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

  // Track active app switches for reset logic
  useEffect(() => {
    if (activeApp === 'calendar') {
      setCurrentCalendarDate(new Date());
    }
    // Clear selections when changing apps
    if (activeApp !== 'contacts') {
      setSelectedContactIds([]);
    }
  }, [activeApp]);

  // Fetch Vacation Responder State
  useEffect(() => {
    if (!credentials) return;
    const loadVacation = async () => {
      try {
        const client = new JmapClient(credentials);
        const vacation = await client.getVacationResponse();
        if (vacation) {
          setVacationEnabled(vacation.isEnabled);
          setVacationSubject(vacation.subject || "");
          setVacationText(vacation.textBody || "");
        }
      } catch (e) {
        console.error("Failed to load vacation state", e);
      }
    };
    loadVacation();
  }, [credentials]);

  const fetchMailboxes = useCallback(async () => {
    if (!credentials) return;
    const callerUsername = credentials.username;
    try {
      const client = new JmapClient(credentials);
      let mapped = await client.getMailboxes();
      
      // If no mailboxes exist, this might be a completely fresh account. Auto-provision them.
      if (mapped.length === 0) {
         try {
           setIsLoading(true);
           await client.provisionDefaultMailboxes();
           mapped = await client.getMailboxes(); // Fetch again after provisioning
           toast.success("Provisioned default mailboxes for new account.");
         } catch (e: any) {
           console.error("Failed to provision mailboxes", e);
         } finally {
           setIsLoading(false);
         }
      }

      // If we switched accounts while fetching, discard the result
      if (currentUsernameRef.current !== callerUsername) {
        return;
      }

      const sortOrder = ['inbox', 'drafts', 'sent', 'templates', 'scheduled', 'outbox', 'archive', 'trash', 'junk'];
      mapped.sort((a, b) => {
        const indexA = sortOrder.indexOf(a.role?.toLowerCase() || '');
        const indexB = sortOrder.indexOf(b.role?.toLowerCase() || '');
        if (indexA === -1 && indexB === -1) return a.name.localeCompare(b.name);
        if (indexA === -1) return 1;
        if (indexB === -1) return -1;
        return indexA - indexB;
      });

      setMailboxes(mapped);
      if (mapped.length > 0 && !selectedMailbox) {
        setSelectedMailbox(mapped.find((m: any) => m.icon === 'Inbox')?.id || mapped[0].id);
      }
      return mapped;
    } catch (err) {
      console.error("Failed to fetch mailboxes", err);
      toast.error(err instanceof Error ? err.message : String(err));
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
      const savedDefault = localStorage.getItem(`webmail_default_identity_${credentials.accountId}`);
      if (savedDefault && list.some(i => i.id === savedDefault)) {
        setSelectedIdentityId(savedDefault);
      } else if (list.length > 0 && !selectedIdentityId) {
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

  const handleDeleteIdentity = (id: string) => {
    requireConfirm(
      "Delete Identity",
      "Are you sure you want to delete this identity?",
      async () => {
        try {
          if (!credentials) return;
          const client = new JmapClient(credentials);
          await client.deleteIdentity(id);
          setIdentities(prev => prev.filter(i => i.id !== id));
          if (selectedIdentityId === id) {
            setSelectedIdentityId(identities.find(i => i.id !== id)?.id || "");
          }
          toast.success("Identity deleted");
        } catch (err: any) {
          console.error("Failed to delete identity", err);
          toast.error(err.message || "Failed to delete identity");
        } finally {
          setConfirmDialog(prev => ({ ...prev, isOpen: false }));
        }
      }
    );
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

    const loadSettings = async () => {
      try {
        // Load browser-specific settings
        setNotificationsEnabled(Notification.permission === 'granted');
      } catch (e) {
        console.error("Failed to load settings", e);
      }
    };
    loadSettings();

    if (credentials.capabilities?.includes("urn:ietf:params:jmap:calendars") || credentials.capabilities?.includes("urn:ietf:params:jmap:jscalendar")) {
      const client = new JmapClient(credentials);
      const startOfMonth = new Date(currentCalendarDate.getFullYear(), currentCalendarDate.getMonth(), 1).toISOString();
      const endOfMonth = new Date(currentCalendarDate.getFullYear(), currentCalendarDate.getMonth() + 1, 0).toISOString();

      // FIXED: Actually fetch the calendars to populate the sidebar/modals
      client.getCalendars()
        .then(list => setCalendars(list))
        .catch(err => console.error("Calendar retrieval failed", err));

      client.getEvents(startOfMonth, endOfMonth)
        .then(list => setEvents(list))
        .catch(err => console.error("Event retrieval failed completely", err));
    }
  }, [credentials, currentCalendarDate]);

  // Fetch Scheduled Jobs Queue
  useEffect(() => {
    if (!credentials) return;
    const fetchJobs = async () => {
      try {
        const res = await fetch('/api/scheduled-jobs');
        if (res.ok) {
          const jobs = await res.json();
          const jobMap: Record<string, number> = {};
          jobs.forEach((j: any) => { 
            // THE FIX: Only map valid draftIds to prevent global "Scheduled" badges
            if (j.draftId && typeof j.draftId === 'string' && j.draftId !== 'null' && j.draftId !== 'undefined') {
              jobMap[j.draftId] = j.executeAt;
            }
          });
          setScheduledJobs(jobMap);
        }
      } catch (e) {}
    };
    fetchJobs();
    const interval = setInterval(fetchJobs, 10000);
    return () => clearInterval(interval);
  }, [credentials]);

  const handleSaveAsTemplate = async () => {
    if (!credentials) return;
    if (!emailBody && !subject) {
      toast.error("Template must have a subject or body");
      return;
    }
    
    setIsSending(true);
    try {
      const tplMailbox = mailboxes.find(m => m.role === 'templates' || m.name.toLowerCase() === 'templates');
      if (!tplMailbox) throw new Error("Templates mailbox not found");

      const client = new JmapClient(credentials);
      await client.request([
        ["Email/set", {
          accountId: credentials.accountId,
          create: {
            "tpl-save": {
              mailboxIds: { [tplMailbox.id]: true },
              keywords: { "$draft": true, "$seen": true },
              subject: subject || "No Subject",
              bodyValues: { "1": { value: emailBody || "" } },
              textBody: [{ partId: "1" }]
            }
          },
          ...(editingTemplateId ? { destroy: [editingTemplateId] } : {})
        }, "0"]
      ]);

      toast.success(editingTemplateId ? "Template updated successfully" : "Template saved successfully");
      setIsComposeOpen(false);
      setEditingTemplateId(null);
      setSubject('');
      setEmailBody('');
      fetchMailboxes();
      if (selectedMailbox === tplMailbox.id) {
        fetchEmails(tplMailbox.id);
      }
    } catch (error: any) {
      toast.error(error.message || "Failed to save template");
    } finally {
      setIsSending(false);
    }
  };

  // Fetch Emails Function
  const fetchEmails = useCallback(async (mailboxId: string, background = false) => {
    if (!mailboxId || !credentials) return;
    const callerUsername = credentials.username;
    
    // THE FIX: Intercept virtual mailboxes
    let targetMailboxId = mailboxId;
    if (mailboxId === 'virtual-scheduled') {
      const draftsId = mailboxes.find(m => m.role === 'drafts')?.id;
      if (!draftsId) return;
      targetMailboxId = draftsId;
    }

    if (!background) setIsLoading(true);
    else setIsSyncing(true);

    try {
      const client = new JmapClient(credentials);
      const mapped = await client.getEmails(targetMailboxId); // Use intercepted ID
      
      if (currentUsernameRef.current !== callerUsername) {
        return;
      }

      setEmails(mapped);
      if (!background) setSelectedEmail(null);
      setLastSync(new Date());
    } catch (err) {
      if (currentUsernameRef.current !== callerUsername) return;
      console.error("Failed to fetch emails", err);
      if (err instanceof Error) {
        toast.error(`Error fetching emails: ${err.message}`);
      } else {
        toast.error(`Error fetching emails: ${String(err)}`);
      }
      if (!background) setEmails([]);
    } finally {
      setIsLoading(false);
      setIsSyncing(false);
    }
  }, [credentials, mailboxes]);

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

  const handleEmailClick = async (email: Email) => {
    const mailbox = mailboxes.find(m => m.id === email.mailboxId);
    const isScheduled = !!scheduledJobs[email.id];

    // THE FIX: Template Edit Redirection
    const isTemplate = mailbox?.role === 'templates' || mailbox?.name.toLowerCase() === 'templates';
    if (isTemplate) {
      setSubject(email.subject);
      setEmailBody(email.body);
      setEditingTemplateId(email.id);
      setIsComposeOpen(true);
      return;
    }

    // 1. Route Drafts vs View
    if (mailbox?.role === 'drafts' && !isScheduled) {
      setToAddresses(email.to.map(t => t.email));
      setSubject(email.subject);
      setEmailBody(email.body);
      
      // THE FIX: Reset scheduling state for standard drafts
      setIsScheduling(false);
      setScheduleTime("");
      
      setIsComposeOpen(true);
      return;
    }

    // 2. Open Viewer
    setSelectedEmail(email);

    // 3. Mark as Read Logic
    if (!email.read) {
      // A. Optimistic UI update (instantly removes the unread blue line)
      setEmails(prevEmails => 
        prevEmails.map(e => e.id === email.id ? { ...e, read: true } : e)
      );
      
      // B. Update Stalwart via JMAP proxy
      try {
        const client = new JmapClient(credentials);
        await client.request([
          ["Email/set", {
            accountId: credentials.accountId,
            update: {
              [email.id]: {
                "keywords/$seen": true
              }
            }
          }, "0"]
        ]);
      } catch (error) {
        console.error("Failed to mark email as read on server", error);
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
            read: !!newKeywords["$seen"],
            starred: !!newKeywords["$flagged"],
            keywords: newKeywords
          };
        }
        return e;
      }));
      if (selectedEmail?.id === emailId) {
        setSelectedEmail(prev => prev ? { 
          ...prev, 
          read: keywords["$seen"] !== undefined ? !!keywords["$seen"] : prev.read,
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
          "fixed md:static inset-y-0 left-0 z-50 w-[270px] bg-slate-100 dark:bg-[#050505] border-r border-slate-200 dark:border-slate-800/50 transition-transform duration-300 ease-in-out flex flex-col shrink-0",
          !isSidebarOpen ? "-translate-x-full md:translate-x-0" : "translate-x-0"
        )}
      >
        <div className="flex items-center justify-between h-16 px-4 border-b border-slate-200 dark:border-slate-800/50">
          <div className="flex items-center gap-3 font-bold text-xl text-slate-800 dark:text-white pl-2">
            <div className="w-9 h-9 bg-indigo-600 rounded-xl flex items-center justify-center shadow-sm">
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
          <div className="px-3 my-2 mb-4">
            <button 
              onClick={() => {
                setEditingTemplateId(null);
                setSubject('');
                setEmailBody('');
                setIsComposeOpen(true);
                setIsSidebarOpen(false);
              }}
              className="w-full flex items-center justify-center gap-3 px-4 py-3.5 bg-indigo-600 hover:bg-indigo-700 text-white rounded-[14px] font-bold text-lg shadow-sm transition-all duration-200 active:scale-[0.98]"
            >
              <Edit3 className="w-5 h-5" />
              Create
            </button>
          </div>
          {vacationEnabled && (
            <div className="mx-3 mb-4 p-3 bg-orange-50 dark:bg-orange-500/10 border border-orange-100 dark:border-orange-800/50 rounded-xl animate-in fade-in slide-in-from-top-2 duration-300">
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-2">
                  <Sun className="w-4 h-4 text-orange-600 dark:text-orange-400" />
                  <span className="text-xs font-bold text-orange-800 dark:text-orange-300">
                    Vacation responder is active
                  </span>
                </div>
                <button 
                  onClick={() => { setActiveApp('settings'); setIsSettingsSection('vacation'); setIsSidebarOpen(false); }}
                  className="p-1 hover:bg-orange-100 dark:hover:bg-orange-500/20 rounded-lg transition-colors text-orange-600 dark:text-orange-400"
                >
                  <Settings className="w-4 h-4" />
                </button>
              </div>
            </div>
          )}
          <div className="px-4 mt-2 mb-2 text-xs font-bold text-slate-400 dark:text-slate-500 uppercase tracking-widest">
            Folders
          </div>
          <ul className="space-y-1.5 px-3 mb-6">
            {(mailboxes || []).map((mb) => {
              const Icon = iconMap[mb.icon] || Mail;
              const isSelected = selectedMailbox === mb.id;
              return (
                <React.Fragment key={mb.id}>
                  <li>
                    <button
                      onClick={() => {
                        setActiveApp('mail');
                        setSelectedMailbox(mb.id);
                        setIsSidebarOpen(false);
                      }}
                      className={cn(
                        "w-full flex items-center justify-between px-3 py-2.5 rounded-2xl transition-all group",
                        isSelected && activeApp === 'mail'
                          ? "bg-indigo-100 dark:bg-[#1a1c2e] text-indigo-700 dark:text-indigo-300"
                          : "text-slate-600 dark:text-slate-300 hover:bg-slate-200/50 dark:hover:bg-[#11131f]"
                      )}
                    >
                      <div className="flex items-center gap-3.5">
                        <div className={cn(
                          "w-9 h-9 rounded-xl flex items-center justify-center transition-colors",
                          isSelected && activeApp === 'mail'
                            ? "bg-indigo-600 text-white shadow-md shadow-indigo-500/20" 
                            : "bg-slate-200/80 dark:bg-[#11131f] text-slate-500 dark:text-slate-400 group-hover:bg-slate-300 dark:group-hover:bg-[#161827]"
                        )}>
                          <Icon className="w-5 h-5" />
                        </div>
                        <div className="flex flex-col items-start leading-tight">
                          <span className="text-[17px] font-bold tracking-wide">{mb.name}</span>
                          <span className="text-[11px] text-slate-500 font-medium mt-0.5">
                            {mb.unread} unread • {mb.totalEmails || 0} total
                          </span>
                        </div>
                      </div>
                    </button>
                  </li>
                  
                      {/* THE FIX: Inject Scheduled Mailbox under Drafts */}
                  {mb.role === 'drafts' && (
                    <li key="virtual-scheduled">
                      <button
                        onClick={() => {
                          setActiveApp('mail');
                          setSelectedMailbox('virtual-scheduled');
                          setIsSidebarOpen(false);
                        }}
                        className={cn(
                          "w-full flex items-center justify-between px-3 py-2.5 rounded-2xl transition-all group mt-1.5",
                          selectedMailbox === 'virtual-scheduled' && activeApp === 'mail'
                            ? "bg-indigo-100 dark:bg-[#1a1c2e] text-indigo-700 dark:text-indigo-300"
                            : "text-slate-600 dark:text-slate-300 hover:bg-slate-200/50 dark:hover:bg-[#11131f]"
                        )}
                      >
                        <div className="flex items-center gap-3.5">
                          <div className={cn(
                            "w-9 h-9 rounded-xl flex items-center justify-center transition-colors",
                            selectedMailbox === 'virtual-scheduled' && activeApp === 'mail'
                              ? "bg-indigo-600 text-white shadow-md shadow-indigo-500/20" 
                              : "bg-slate-200/80 dark:bg-[#161827] text-slate-500 dark:text-slate-400 group-hover:bg-slate-300 dark:group-hover:bg-[#1c1e30]"
                          )}>
                            <Clock className="w-5 h-5" />
                          </div>
                          <span className="text-[17px] font-bold tracking-wide">Scheduled</span>
                        </div>
                        {Object.keys(scheduledJobs).length > 0 && (
                          <span className={cn(
                            "text-xs py-0.5 px-2 rounded-full font-bold",
                            selectedMailbox === 'virtual-scheduled'
                              ? "bg-indigo-200 dark:bg-indigo-500/30 text-indigo-800 dark:text-indigo-200" 
                              : "bg-slate-200 dark:bg-slate-800 text-slate-600 dark:text-slate-300"
                          )}>
                            {Object.keys(scheduledJobs).filter(id => id !== 'undefined' && id !== 'null').length}
                          </span>
                        )}
                      </button>
                    </li>
                  )}
                </React.Fragment>
              );
            })}
          </ul>

          <div className="px-4 mt-2 mb-2 text-xs font-bold text-slate-400 dark:text-slate-500 uppercase tracking-widest">
            Apps
          </div>
          <ul className="space-y-1.5 px-3">
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
                      "w-full flex items-center gap-3.5 px-3 py-2.5 rounded-2xl text-[17px] font-bold transition-all duration-200 tracking-wide",
                      isSelected 
                        ? "bg-indigo-600 text-white shadow-md shadow-indigo-500/20" 
                        : "text-slate-600 dark:text-slate-400 hover:bg-slate-200/50 dark:hover:bg-[#11131f] hover:text-slate-900 dark:hover:text-white"
                    )}
                  >
                    <Icon className={cn("w-5 h-5", isSelected ? "text-white" : "text-slate-400 dark:text-slate-500")} />
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
                className="w-full pl-11 pr-12 py-2.5 bg-slate-100 dark:bg-slate-900 border border-transparent dark:border-slate-800 focus:bg-white dark:focus:bg-slate-800 focus:border-transparent focus:ring-4 focus:ring-indigo-500/10 dark:focus:ring-indigo-500/20 rounded-full text-base outline-none transition-all dark:text-white shadow-sm"
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
                        { (accounts || []).map((acc: any, idx: number) => (
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
                  "w-full md:w-[350px] lg:w-[420px] border-r border-slate-200 dark:border-slate-800 flex flex-col bg-white dark:bg-[#050505] shrink-0 overflow-hidden",
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
                  <div className="sticky top-0 z-20 border-b border-slate-200 dark:border-slate-800 bg-white/80 dark:bg-[#050505]/80 backdrop-blur-md">
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
                          <h2 className="font-bold text-lg text-slate-800 dark:text-white flex items-center gap-2 truncate max-w-[200px] sm:max-w-none">
                            {selectedMailbox === 'virtual-scheduled' && <Clock className="w-5 h-5 text-indigo-500" />}
                            {selectedMailbox === 'virtual-scheduled' 
                              ? 'Scheduled' 
                              : (mailboxes.find(m => m.id === selectedMailbox)?.name || "Inbox")}
                          </h2>
                          <span className="text-[10px] text-slate-500 dark:text-slate-400 font-medium">
                            {(() => {
                              const mb = mailboxes.find(m => m.id === selectedMailbox);
                              if (selectedMailbox === 'virtual-scheduled') return `${Object.keys(scheduledJobs).length} messages`;
                              if (mb) return `${mb.totalEmails || filteredEmails.length} messages`;
                              return `${filteredEmails.length} messages`;
                            })()}
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
                      <div className="w-16 h-16 bg-slate-50 dark:bg-[#11131f] rounded-full flex items-center justify-center mx-auto mb-4">
                        <Inbox className="w-8 h-8 text-slate-300 dark:text-slate-600" />
                      </div>
                      <p className="font-medium">{searchQuery ? "No matching messages" : "No messages found"}</p>
                      <p className="text-sm mt-1 text-slate-400 dark:text-slate-500">You're all caught up!</p>
                    </div>
                  ) : (
                    <ul className="divide-y divide-slate-100 dark:divide-slate-800/50">
                      { (filteredEmails || []).map((email) => {
                        const folder = mailboxes.find(m => m.id === selectedMailbox);
                        const isTemplateFolder = folder?.role === 'templates' || folder?.name.toLowerCase() === 'templates';
                        
                        return (
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
                                "w-full text-left transition-all relative group cursor-pointer outline-none focus-visible:ring-2 focus-visible:ring-inset focus-visible:ring-indigo-500 flex gap-3",
                                isTemplateFolder ? "p-3" : "p-4",
                                selectedEmail?.id === email.id 
                                  ? "bg-indigo-50/50 dark:bg-[#0f111c]" 
                                  : "bg-white dark:bg-[#050505] hover:bg-slate-50 dark:hover:bg-[#11131f]",
                                selectedEmailIds.includes(email.id) && "bg-indigo-50/30 dark:bg-[#111322]"
                              )}
                            >
                              {/* THE FIX: Gmail-Style Unread Indicator */}
                              {!email.read && (
                                <div className="absolute left-0 top-0 bottom-0 w-[4px] bg-indigo-600 dark:bg-indigo-500 shadow-[0_0_12px_rgba(99,102,241,0.6)]" />
                              )}
                              
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
                                <div className="flex items-start justify-between mb-1 gap-2">
                                  {!isTemplateFolder ? (
                                    <div className="flex flex-col min-w-0 flex-1">
                                      <div className={cn(
                                        "flex items-center gap-2",
                                        !email.read ? "font-bold text-slate-900 dark:text-white" : "font-semibold text-slate-700 dark:text-slate-300"
                                      )}>
                                        <span className="text-sm truncate">
                                          {email.from.name || email.from.email.split('@')[0]}
                                        </span>
                                      </div>
                                    </div>
                                  ) : (
                                    <div className="flex flex-col min-w-0 flex-1">
                                      <span className="text-sm font-bold text-slate-900 dark:text-white truncate">
                                        {email.subject || '(No Subject)'}
                                      </span>
                                    </div>
                                  )}
                                  <div className="flex items-center gap-2 ml-auto">
                                    <span className="text-xs text-slate-500 dark:text-slate-400 whitespace-nowrap mt-0.5 font-medium">
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
                                        <MoreVertical className="w-4 h-4 text-slate-400" />
                                      </button>
                                      {contextMenuEmail?.id === email.id && (
                                        <>
                                          <div className="fixed inset-0 z-[60]" onClick={(e) => { e.stopPropagation(); setContextMenuEmail(null); }} />
                                          <div className="absolute right-0 top-full mt-1 w-48 bg-white dark:bg-[#11131f] border border-slate-200 dark:border-slate-800 rounded-xl shadow-xl z-[70] py-1 animate-in fade-in zoom-in-95 duration-150 overflow-hidden">
                                            <button 
                                              onClick={(e) => { e.stopPropagation(); handleMarkAsRead(email.id); setContextMenuEmail(null); }}
                                              className="w-full px-4 py-2 text-left text-sm hover:bg-slate-50 dark:hover:bg-[#050505] flex items-center gap-2 font-medium"
                                            >
                                              <Mail className="w-4 h-4" /> Mark as read
                                            </button>
                                            <button 
                                              onClick={(e) => { e.stopPropagation(); handleMarkAsUnread(email.id); setContextMenuEmail(null); }}
                                              className="w-full px-4 py-2 text-left text-sm hover:bg-slate-50 dark:hover:bg-[#050505] flex items-center gap-2 font-medium"
                                            >
                                              <Bell className="w-4 h-4" /> Mark as unread
                                            </button>
                                            <button 
                                              onClick={(e) => { e.stopPropagation(); handleArchiveEmail(email.id); setContextMenuEmail(null); }}
                                              className="w-full px-4 py-2 text-left text-sm hover:bg-slate-50 dark:hover:bg-[#050505] flex items-center gap-2 font-medium"
                                            >
                                              <Archive className="w-4 h-4" /> Archive
                                            </button>
                                            <button 
                                              onClick={(e) => { e.stopPropagation(); handleDeleteEmail(email.id); setContextMenuEmail(null); }}
                                              className="w-full px-4 py-2 text-left text-sm hover:bg-red-50 dark:hover:bg-red-900/20 text-red-600 dark:text-red-400 flex items-center gap-2 font-medium"
                                            >
                                              <Trash2 className="w-4 h-4" /> Delete
                                            </button>
                                            <div className="h-px bg-slate-100 dark:bg-slate-800 my-1" />
                                            {mailboxes.find(m => m.id === selectedMailbox)?.role === 'junk' ? (
                                              <button 
                                                onClick={(e) => { e.stopPropagation(); handleMoveToInbox(email.id); setContextMenuEmail(null); }}
                                                className="w-full px-4 py-2 text-left text-sm hover:bg-slate-50 dark:hover:bg-[#050505] flex items-center gap-2 font-medium"
                                              >
                                                <Inbox className="w-4 h-4" /> Move to Inbox
                                              </button>
                                            ) : (
                                              <button 
                                                onClick={(e) => { e.stopPropagation(); handleMoveToJunk(email.id); setContextMenuEmail(null); }}
                                                className="w-full px-4 py-2 text-left text-sm hover:bg-slate-50 dark:hover:bg-[#050505] flex items-center gap-2 font-medium"
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
                                {!isTemplateFolder && (
                                  <div className="flex flex-col mb-1.5 mt-0.5 min-w-0">
                                    <div className={cn(
                                      "flex items-center gap-2", 
                                      !email.read ? "font-bold text-slate-800 dark:text-slate-100" : "font-semibold text-slate-600 dark:text-slate-400"
                                    )}>
                                      <span className="text-sm truncate min-w-0">
                                        {email.subject}
                                      </span>
                                      {scheduledJobs[email.id] && (
                                        <span className="shrink-0 flex items-center gap-1 text-[10px] font-bold text-amber-600 dark:text-amber-400 bg-amber-50 dark:bg-amber-900/20 px-2 py-0.5 rounded-md border border-amber-200 dark:border-amber-800/30">
                                          <Clock className="w-3 h-3" /> Scheduled
                                        </span>
                                      )}
                                    </div>
                                  </div>
                                )}
                                <div className="text-xs text-slate-500 dark:text-slate-400 line-clamp-2 leading-relaxed break-words font-normal">
                                  {email.preview}
                                </div>
                              </div>
                            </div>
                          </li>
                        );
                      })}
                    </ul>
                  )}
                </div>
              </div>

              {/* Email Viewer */}
              <div
                className={cn(
                  "flex-1 flex flex-col bg-white dark:bg-[#050505] min-w-0",
                  !selectedEmail ? "hidden md:flex" : "flex"
                )}
              >
                {selectedEmail ? (
                  <>
                    {/* Viewer Toolbar */}
                    <div className="h-14 border-b border-slate-200 dark:border-slate-800 flex items-center justify-between px-4 shrink-0 bg-white dark:bg-[#050505]">
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
                              <div className="absolute right-0 top-full mt-2 w-48 bg-white dark:bg-[#11131f] border border-slate-200 dark:border-slate-800 rounded-xl shadow-xl z-50 py-1 animate-in fade-in zoom-in-95 duration-150 overflow-hidden">
                                {mailboxes.find(m => m.id === selectedMailbox)?.role === 'junk' ? (
                                  <button 
                                    onClick={() => { handleMoveToInbox(selectedEmail.id); setIsEmailActionsOpen(false); }}
                                    className="w-full px-4 py-2 text-left text-sm hover:bg-slate-50 dark:hover:bg-[#050505] flex items-center gap-2"
                                  >
                                    <Inbox className="w-4 h-4" /> Move to Inbox
                                  </button>
                                ) : (
                                  <button 
                                    onClick={() => { handleMoveToJunk(selectedEmail.id); setIsEmailActionsOpen(false); }}
                                    className="w-full px-4 py-2 text-left text-sm hover:bg-slate-50 dark:hover:bg-[#050505] flex items-center gap-2"
                                  >
                                    <AlertCircle className="w-4 h-4" /> Move to Junk
                                  </button>
                                )}
                                <button 
                                  onClick={() => { handleArchiveEmail(selectedEmail.id); setIsEmailActionsOpen(false); }}
                                  className="w-full px-4 py-2 text-left text-sm hover:bg-slate-50 dark:hover:bg-[#050505] flex items-center gap-2"
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
                    <div className="flex-1 overflow-y-auto overflow-x-hidden p-6 md:p-12 lg:p-16 bg-white dark:bg-[#050505]">
                      <div className="max-w-4xl mx-auto min-w-0 pb-16">
                        <div className="flex items-start justify-between mb-6 group min-w-0">
                          <div className="flex-1 min-w-0 pr-4">
                            <h1 className="text-xl md:text-2xl font-bold text-slate-900 dark:text-white leading-tight break-all md:break-words">
                              {selectedEmail.subject}
                            </h1>
                            <div className="flex flex-wrap items-center gap-2 mt-2">
                              <span className="px-2 py-0.5 bg-slate-100 dark:bg-slate-800 text-slate-500 dark:text-slate-400 text-[10px] font-bold rounded uppercase tracking-wider">
                                {mailboxes.find(m => m.id === selectedMailbox)?.name || "Message"}
                              </span>
                              {selectedEmail.unsubscribeUrl && (
                                <a 
                                  href={selectedEmail.unsubscribeUrl} 
                                  target="_blank" 
                                  rel="noopener noreferrer"
                                  className="flex items-center gap-1.5 px-2.5 py-1 bg-indigo-50 dark:bg-indigo-900/20 text-indigo-600 dark:text-indigo-400 text-xs font-bold rounded-lg border border-indigo-100 dark:border-indigo-800/30 hover:bg-indigo-100 dark:hover:bg-indigo-900/40 transition-colors"
                                >
                                  <ExternalLink className="w-3 h-3" />
                                  Unsubscribe
                                </a>
                              )}
                            </div>
                          </div>
                          <div className="flex items-center gap-2 shrink-0 mt-1">
                            <button className="p-1.5 text-slate-400 hover:text-slate-600 dark:hover:text-slate-200 transition-colors">
                              <Star className={cn("w-4 h-4", selectedEmail.starred && "fill-yellow-400 text-yellow-400")} />
                            </button>
                            <button className="p-1.5 text-slate-400 hover:text-slate-600 dark:hover:text-slate-200 transition-colors md:hidden">
                              <MoreVertical className="w-4 h-4" />
                            </button>
                          </div>
                        </div>

                        {/* THE FIX: Strict ID checking to prevent banner bleeding */}
                        {selectedEmail && selectedEmail.id && scheduledJobs[selectedEmail.id] !== undefined && (
                          <div className="mb-6 p-4 bg-slate-50 dark:bg-[#11131f] rounded-xl flex flex-col sm:flex-row sm:items-center justify-between gap-4 border border-slate-100 dark:border-slate-800/50 animate-in fade-in slide-in-from-top-2 duration-300">
                            <div className="flex items-start sm:items-center gap-3">
                              <div className="mt-0.5 sm:mt-0 text-slate-500 dark:text-slate-400">
                                <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                                  <path strokeLinecap="round" strokeLinejoin="round" d="M12 8v4l3 3m6-3a9 9 0 11-18 0 9 9 0 0118 0z" />
                                </svg>
                              </div>
                              <div className="text-slate-800 dark:text-slate-200 text-sm font-medium">
                                Send scheduled for {format(new Date(scheduledJobs[selectedEmail.id]), "EEEE, h:mm a")}
                              </div>
                            </div>
                            <button 
                              onClick={async () => {
                                try {
                                  await fetch(`/api/schedule-send/${selectedEmail.id}`, { method: 'DELETE' });
                                  const newJobs = { ...scheduledJobs };
                                  delete newJobs[selectedEmail.id];
                                  setScheduledJobs(newJobs);
                                  setSelectedEmail(null); 
                                  toast.success("Scheduled send canceled.");
                                } catch (e) {
                                  toast.error("Failed to cancel scheduled send.");
                                }
                              }}
                              className="text-indigo-600 dark:text-indigo-400 font-bold text-sm uppercase tracking-wide hover:bg-indigo-50 dark:hover:bg-indigo-500/10 px-3 py-1.5 rounded transition-colors self-start sm:self-auto"
                            >
                              Cancel Send
                            </button>
                          </div>
                        )}
                        
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
                                <button 
                                  onClick={() => setIsHeaderExpanded(!isHeaderExpanded)}
                                  className="flex items-center gap-1 hover:text-slate-700 dark:hover:text-slate-200"
                                >
                                  <span>to me</span>
                                  <ChevronDown className={cn("w-3 h-3 transition-transform", isHeaderExpanded && "rotate-180")} />
                                </button>
                              </div>

                              {isHeaderExpanded && (
                                <div className="mt-3 p-3 bg-slate-50 dark:bg-[#11131f] rounded-xl border border-slate-200 dark:border-slate-800 text-xs space-y-2 animate-in fade-in slide-in-from-top-2 duration-200 shadow-inner overflow-hidden">
                                  <div className="grid grid-cols-[60px_minmax(0,1fr)] gap-2">
                                    <span className="text-slate-400 dark:text-slate-500">from:</span>
                                    <span className="text-slate-700 dark:text-slate-300 break-all font-medium">
                                      {selectedEmail.from.name} <span className="text-slate-400 font-normal">&lt;{selectedEmail.from.email}&gt;</span>
                                    </span>
                                  </div>
                                  <div className="grid grid-cols-[60px_minmax(0,1fr)] gap-2">
                                    <span className="text-slate-400 dark:text-slate-500">to:</span>
                                    <span className="text-slate-700 dark:text-slate-300 break-all font-medium">
                                      { selectedEmail?.to?.map(t => `${t.name || ""} <${t.email}>`).join(", ")}
                                    </span>
                                  </div>
                                  <div className="grid grid-cols-[60px_minmax(0,1fr)] gap-2">
                                    <span className="text-slate-400 dark:text-slate-500">date:</span>
                                    <span className="text-slate-700 dark:text-slate-300 font-medium">
                                      {format(new Date(selectedEmail.date), "MMM d, yyyy, h:mm a")}
                                    </span>
                                  </div>
                                  <div className="grid grid-cols-[60px_minmax(0,1fr)] gap-2">
                                    <span className="text-slate-400 dark:text-slate-500">subject:</span>
                                    <span className="text-slate-700 dark:text-slate-300 font-medium break-all">{selectedEmail.subject}</span>
                                  </div>
                                  <div className="grid grid-cols-[60px_minmax(0,1fr)] gap-2">
                                    <span className="text-slate-400 dark:text-slate-500">security:</span>
                                    <div className="flex items-center gap-1.5 text-green-600 dark:text-green-400 font-medium min-w-0">
                                      <Shield className="w-3 h-3 shrink-0" />
                                      <span className="truncate">Standard encryption (TLS)</span>
                                    </div>
                                  </div>
                                </div>
                              )}
                            </div>
                          </div>
                        </div>

                        <div className="mt-8 text-slate-900 dark:text-slate-100 overflow-x-auto max-w-none">
                          <div 
                            className="prose prose-slate max-w-none prose-p:leading-relaxed prose-a:text-indigo-600 prose-img:rounded-lg dark:prose-invert"
                            dangerouslySetInnerHTML={{ __html: DOMPurify.sanitize(selectedEmail.body || "<em>No content</em>") }}
                          />
                        </div>

                        {selectedEmail.attachments && selectedEmail.attachments.length > 0 && (
                          <div className="mt-8">
                            <hr className="my-6 border-slate-200 dark:border-slate-800" />
                            <h3 className="text-xs font-bold text-slate-400 uppercase tracking-widest mb-4">Attachments ({selectedEmail.attachments.length})</h3>
                            <div className="flex flex-wrap gap-4">
                              {selectedEmail.attachments.map((att: any, idx: number) => (
                                <AttachmentRenderer 
                                  key={idx} 
                                  attachment={att} 
                                  client={new JmapClient(credentials)} 
                                />
                              ))}
                            </div>
                          </div>
                        )}
                      </div>
                    </div>
                    
                    {/* Sticky Footer for Reply/Forward */}
                    <div className="shrink-0 p-4 bg-white/90 dark:bg-[#050505]/90 backdrop-blur-md border-t border-slate-100 dark:border-slate-800 flex gap-3 justify-center sm:justify-start">
                      <button 
                        onClick={() => {
                          const email = emails.find(e => e.id === selectedEmail.id);
                          if (email) {
                            setToAddresses([email.from.email]);
                            setSubject(`Re: ${email.subject}`);
                            setEmailBody(`\n\nOn ${format(new Date(email.date), 'MMM d, yyyy')} at ${format(new Date(email.date), 'h:mm a')}, ${email.from.name || email.from.email} wrote:\n> ${email.preview}...`);
                            setIsComposeOpen(true);
                          }
                        }}
                        className="flex items-center gap-2 px-8 py-3 rounded-full bg-slate-100 dark:bg-slate-800 text-slate-800 dark:text-slate-200 hover:bg-slate-200 dark:hover:bg-slate-700 transition-all font-semibold text-sm shadow-sm"
                      >
                        <Reply className="w-4 h-4" /> Reply
                      </button>
                      <button 
                        onClick={() => {
                          const email = emails.find(e => e.id === selectedEmail.id);
                          if (email) {
                            setToAddresses([]);
                            setSubject(`Fwd: ${email.subject}`);
                            setEmailBody(`\n\n---------- Forwarded message ---------\nFrom: ${email.from.name || email.from.email} <${email.from.email}>\nDate: ${format(new Date(email.date), 'MMM d, yyyy')} at ${format(new Date(email.date), 'h:mm a')}\nSubject: ${email.subject}\nTo: ${email.to.map(t => t.email).join(', ')}\n\n${email.body}`);
                            setIsComposeOpen(true);
                          }
                        }}
                        className="flex items-center gap-2 px-8 py-3 rounded-full bg-slate-100 dark:bg-slate-800 text-slate-800 dark:text-slate-200 hover:bg-slate-200 dark:hover:bg-slate-700 transition-all font-semibold text-sm shadow-sm"
                      >
                        <Forward className="w-4 h-4" /> Forward
                      </button>
                    </div>
                  </>
                ) : (
                  <div className="flex-1 flex flex-col items-center justify-center text-slate-400 dark:text-slate-500 bg-white dark:bg-[#050505]">
                    <div className="w-20 h-20 bg-slate-50 dark:bg-[#11131f] rounded-full flex items-center justify-center mb-6">
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
                  <div className="flex flex-wrap items-center gap-2">
                    {selectedContactIds.length > 0 && (
                      <>
                        <button 
                          onClick={handleBulkDeleteContacts}
                          className="px-4 py-2.5 bg-red-50 dark:bg-red-900/20 text-red-600 dark:text-red-400 border border-red-100 dark:border-red-900/30 rounded-xl font-medium hover:bg-red-100 dark:hover:bg-red-900/40 transition-all flex items-center gap-2"
                        >
                          <Trash2 className="w-4 h-4" /> Delete ({selectedContactIds.length})
                        </button>
                        <button 
                          onClick={() => {
                            if (selectedContactIds.length === filteredContacts.length) {
                              setSelectedContactIds([]);
                            } else {
                              setSelectedContactIds(filteredContacts.map(c => c.id));
                            }
                          }}
                          className="px-4 py-2.5 border border-slate-200 dark:border-slate-800 text-slate-600 dark:text-slate-400 rounded-xl font-medium hover:bg-slate-50 dark:hover:bg-slate-900 transition-all flex items-center gap-2"
                        >
                          {selectedContactIds.length === filteredContacts.length ? "Deselect All" : "Select All"}
                        </button>
                      </>
                    )}
                    <button 
                      onClick={async () => {
                        setIsSyncing(true);
                        try {
                          if (!credentials) return;
                          const client = new JmapClient(credentials);
                          const list = await client.getContacts();
                          setContacts(list);
                          toast.success("Contacts refreshed");
                        } catch (e) {
                          toast.error("Failed to refresh contacts");
                        } finally {
                          setIsSyncing(false);
                          setLastSync(new Date());
                        }
                      }}
                      className="p-2.5 text-slate-500 hover:bg-slate-100 dark:hover:bg-slate-900 rounded-xl transition-all"
                      title="Refresh contacts"
                    >
                      <RefreshCw className={cn("w-5 h-5", isSyncing && "animate-spin")} />
                    </button>
                    <button 
                      onClick={() => setIsContactModalOpen(true)}
                      className="px-6 py-2.5 bg-indigo-600 hover:bg-indigo-700 text-white rounded-xl font-medium shadow-lg shadow-indigo-500/20 transition-all active:scale-95 flex items-center gap-2 whitespace-nowrap"
                    >
                      <Plus className="w-4 h-4" /> Create Contact
                    </button>
                  </div>
                </div>
                <div className="p-6">
                  {filteredContacts.length > 0 ? (
                    <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4 gap-4">
                      { (filteredContacts || []).map((contact, idx) => (
                        <div 
                          key={idx} 
                          onClick={() => {
                            setSelectedContact(contact);
                            setIsEditingContact(false);
                          }}
                          className={cn(
                            "group bg-white dark:bg-[#11131f] p-4 rounded-2xl border border-slate-200 dark:border-slate-800 shadow-sm hover:shadow-md hover:border-indigo-500/30 transition-all cursor-pointer relative",
                            selectedContactIds.includes(contact.id) && "ring-2 ring-indigo-500/50 border-indigo-500/50 bg-indigo-50/10"
                          )}
                        >
                          <div className="absolute top-3 right-3 z-10">
                            <input 
                              type="checkbox"
                              checked={selectedContactIds.includes(contact.id)}
                              onClick={(e) => e.stopPropagation()} // Prevent card click
                              onChange={(e) => {
                                if (e.target.checked) {
                                  setSelectedContactIds([...selectedContactIds, contact.id]);
                                } else {
                                  setSelectedContactIds(selectedContactIds.filter(id => id !== contact.id));
                                }
                              }}
                              className="w-4 h-4 rounded border-slate-300 text-indigo-600 focus:ring-indigo-500 cursor-pointer"
                            />
                          </div>
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
                            <button 
                              onClick={(e) => {
                                e.stopPropagation();
                                setIsComposeOpen(true);
                                setToAddresses([getContactEmail(contact)]);
                              }}
                              className="p-1.5 text-slate-400 hover:text-indigo-600 dark:hover:text-indigo-400 hover:bg-indigo-50 dark:hover:bg-indigo-900/20 rounded-lg transition-all"
                            >
                              <Mail className="w-4 h-4" />
                            </button>
                            <button 
                              onClick={(e) => {
                                e.stopPropagation();
                                handleDeleteContact(contact.id);
                              }}
                              className="p-1.5 text-slate-400 hover:text-red-600 dark:hover:text-red-400 hover:bg-red-50 dark:hover:bg-red-900/20 rounded-lg transition-all"
                            >
                              <Trash2 className="w-4 h-4" />
                            </button>
                          </div>
                        </div>
                      ))}
                    </div>
                  ) : (
                    <div className="flex flex-col items-center justify-center py-20 text-slate-400 dark:text-slate-600 text-center bg-white dark:bg-[#11131f] rounded-xl border border-slate-200 dark:border-slate-800">
                      <div className="w-24 h-24 bg-slate-50 dark:bg-[#050505] rounded-3xl flex items-center justify-center mb-6 shadow-xl border border-slate-100 dark:border-slate-800">
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
                    <p className="text-sm text-slate-500 dark:text-slate-400">{format(currentCalendarDate, 'MMMM yyyy')}</p>
                  </div>
                  <div className="flex items-center gap-2">
                    <button 
                      onClick={() => setCurrentCalendarDate(new Date(currentCalendarDate.getFullYear(), currentCalendarDate.getMonth() - 1, 1))}
                      className="p-2 text-slate-500 hover:bg-slate-100 dark:hover:bg-slate-800 rounded-xl transition-all"
                    >
                      <ChevronLeft className="w-5 h-5" />
                    </button>
                    <button 
                      onClick={() => setCurrentCalendarDate(new Date(currentCalendarDate.getFullYear(), currentCalendarDate.getMonth() + 1, 1))}
                      className="p-2 text-slate-500 hover:bg-slate-100 dark:hover:bg-slate-800 rounded-xl transition-all"
                    >
                      <ChevronRight className="w-5 h-5" />
                    </button>
                    <button 
                      onClick={async () => {
                        setIsSyncing(true);
                        try {
                          const client = new JmapClient(credentials);
                          const startOfMonth = new Date(currentCalendarDate.getFullYear(), currentCalendarDate.getMonth(), 1).toISOString();
                          const endOfMonth = new Date(currentCalendarDate.getFullYear(), currentCalendarDate.getMonth() + 1, 0).toISOString();
                          const list = await client.getEvents(startOfMonth, endOfMonth);
                          setEvents(list);
                          toast.success("Calendar refreshed");
                        } catch (e) {
                          toast.error("Failed to refresh calendar");
                        } finally {
                          setIsSyncing(false);
                          setLastSync(new Date());
                        }
                      }}
                      className="p-2 text-slate-500 hover:bg-slate-100 dark:hover:bg-slate-800 rounded-xl transition-all"
                      title="Refresh calendar"
                    >
                      <RefreshCw className={cn("w-5 h-5", isSyncing && "animate-spin")} />
                    </button>
                    <button 
                      onClick={() => setCurrentCalendarDate(new Date())}
                      className="px-4 py-2 bg-white dark:bg-[#11131f] border border-slate-200 dark:border-slate-800 rounded-xl text-sm font-medium hover:bg-slate-50 dark:hover:bg-slate-800 transition-all"
                    >
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
                  <div className="bg-white dark:bg-[#050505] rounded-2xl border border-slate-200 dark:border-slate-800 overflow-hidden shadow-sm">
                    <div className="grid grid-cols-7 border-b border-slate-200 dark:border-slate-800">
                      {['Sun', 'Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat'].map(day => (
                        <div key={day} className="p-3 text-center text-xs font-bold text-slate-400 uppercase tracking-wider border-r border-slate-100 dark:border-slate-800 last:border-0">
                          {day}
                        </div>
                      ))}
                    </div>
                    <div className="grid grid-cols-7 grid-rows-5">
                      {(() => {
                        const startOfMonth = new Date(currentCalendarDate.getFullYear(), currentCalendarDate.getMonth(), 1);
                        const startDay = startOfMonth.getDay();
                        const daysInMonth = new Date(currentCalendarDate.getFullYear(), currentCalendarDate.getMonth() + 1, 0).getDate();
                        const now = new Date();
                        
                        return Array.from({ length: 35 }).map((_, i) => {
                          const dayNum = i - startDay + 1;
                          const isToday = dayNum === now.getDate() && currentCalendarDate.getMonth() === now.getMonth() && currentCalendarDate.getFullYear() === now.getFullYear();
                          const isCurrentMonth = dayNum > 0 && dayNum <= daysInMonth;
                          
                          // Find events for this day
                          const dayEvents = filteredEvents.filter(e => {
                            const eventDate = new Date(e.start || e.startDate);
                            return eventDate.getDate() === dayNum && eventDate.getMonth() === currentCalendarDate.getMonth() && eventDate.getFullYear() === currentCalendarDate.getFullYear();
                          });

                          return (
                            <div 
                              key={i} 
                              onClick={() => {
                                if (isCurrentMonth) {
                                  setSelectedCalendarDate(new Date(currentCalendarDate.getFullYear(), currentCalendarDate.getMonth(), dayNum));
                                }
                              }}
                              className={cn(
                                "min-h-[120px] p-2 border-r border-b border-slate-100 dark:border-slate-800 transition-colors hover:bg-slate-50 dark:hover:bg-[#11131f] cursor-pointer group",
                                !isCurrentMonth && "bg-slate-50/50 dark:bg-black"
                              )}
                            >
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
                              
                              <div className="mt-2 space-y-1 text-left">
                                {dayEvents.map((event, idx) => (
                                  <div 
                                    key={idx} 
                                    onClick={(e) => {
                                      e.stopPropagation();
                                      setSelectedEvent(event);
                                    }}
                                    className="p-1.5 bg-indigo-50 dark:bg-indigo-900/20 border-l-2 border-indigo-500 rounded text-[10px] font-bold text-indigo-700 dark:text-indigo-300 truncate transition-all hover:translate-x-1"
                                  >
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
                      {(calendars || []).map((calendar, idx) => (
                        <div key={idx} className="bg-white dark:bg-[#11131f] p-4 rounded-2xl border border-slate-200 dark:border-slate-800 shadow-sm flex items-center justify-between group hover:border-indigo-500/30 transition-all">
                          <div className="flex items-center gap-4">
                            <div className="w-10 h-10 rounded-xl bg-indigo-100 dark:bg-[#050505] text-indigo-700 dark:text-indigo-400 flex items-center justify-center shrink-0">
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
            <div className="flex-1 flex flex-col md:flex-row bg-slate-50 dark:bg-[#0b0c10] overflow-hidden h-full">
              {/* Settings Sidebar (Desktop) */}
              <div className="w-64 border-r border-slate-200 dark:border-slate-800 bg-white dark:bg-[#14151a] hidden md:flex flex-col p-4 gap-2 overflow-hidden">
                <h2 className="text-xl font-bold text-slate-900 dark:text-white mb-4 px-3 shrink-0">Settings</h2>
                <nav className="flex-col gap-1 flex flex-1 overflow-y-auto pr-2 custom-scrollbar">
                  {[
                    { id: 'account', label: 'Account', icon: User },
                    { id: 'general', label: 'General', icon: Settings },
                    { id: 'notifications', label: 'Notifications', icon: Bell },
                    { id: 'vacation', label: 'Vacation', icon: Reply },
                    { id: 'templates', label: 'Templates', icon: File },
                    { id: 'contacts', label: 'Contacts', icon: Users },
                    { id: 'filters', label: 'Filters', icon: Filter },
                    { id: 'security', label: 'Security', icon: Shield },
                    { id: 'advanced', label: 'Advanced', icon: Key },
                  ].map((item) => (
                    <button 
                      key={item.id}
                      onClick={() => setIsSettingsSection(item.id as any)}
                      className={cn(
                        "flex items-center gap-3 px-4 py-2.5 rounded-xl text-sm font-medium transition-all",
                        isSettingsSection === item.id ? "bg-indigo-50 dark:bg-indigo-500/10 text-indigo-600 dark:text-indigo-400" : "text-slate-600 dark:text-slate-400 hover:bg-slate-50 dark:hover:bg-slate-900"
                      )}
                    >
                      <item.icon className="w-4 h-4" /> {item.label}
                    </button>
                  ))}
                </nav>
                
                <div className="mt-auto pt-4 border-t border-slate-200 dark:border-slate-800">
                  <button 
                    onClick={onLogout}
                    className="w-full flex items-center gap-3 px-4 py-2.5 rounded-xl text-sm font-medium text-red-600 dark:text-red-400 hover:bg-red-50 dark:hover:bg-red-900/20 transition-all"
                  >
                    <LogOut className="w-4 h-4" /> Sign Out
                  </button>
                </div>
              </div>

              {/* Settings Content Area */}
              <div className="flex-1 overflow-y-auto">
                {/* Mobile Settings Header */}
                <div className="sticky top-0 z-20 p-4 border-b border-slate-200 dark:border-slate-800 bg-white/80 dark:bg-black/80 backdrop-blur-md flex items-center justify-between md:p-6">
                  <h1 className="text-xl font-bold text-slate-900 dark:text-white md:text-2xl">
                    {isSettingsSection === 'account' ? 'Account Settings' : 
                     isSettingsSection === 'general' ? 'General Settings' : 
                     isSettingsSection === 'security' ? 'Security & Privacy' : 
                     isSettingsSection === 'vacation' ? 'Vacation Responder' : 
                     isSettingsSection === 'notifications' ? 'Notification Settings' : 
                     isSettingsSection === 'templates' ? 'Template Management' : 
                     isSettingsSection === 'contacts' ? 'Contact Management' : 
                     isSettingsSection === 'filters' ? 'Filters & Rules' : 'Advanced Settings'}
                  </h1>
                  <button 
                    onClick={() => setIsSettingsMenuOpen(true)}
                    className="md:hidden flex items-center gap-2 bg-indigo-50 dark:bg-indigo-500/10 text-indigo-600 dark:text-indigo-400 px-4 py-2 rounded-full text-sm font-bold shadow-sm border border-indigo-100 dark:border-indigo-500/20"
                  >
                    {isSettingsSection === 'account' ? 'Account' : 
                     isSettingsSection === 'general' ? 'General' : 
                     isSettingsSection === 'security' ? 'Security' : 
                     isSettingsSection === 'vacation' ? 'Vacation' : 
                     isSettingsSection === 'notifications' ? 'Notifications' : 
                     isSettingsSection === 'templates' ? 'Templates' : 
                     isSettingsSection === 'contacts' ? 'Contacts' : 
                     isSettingsSection === 'filters' ? 'Filters & Rules' : 'Advanced'}
                    <ChevronDown className="w-4 h-4" />
                  </button>
                </div>

                {/* Mobile Selection Modal */}
                {isSettingsMenuOpen && (
                  <div className="fixed inset-0 z-[100] md:hidden">
                    <div className="absolute inset-0 bg-black/40 backdrop-blur-sm" onClick={() => setIsSettingsMenuOpen(false)} />
                    <div className="absolute inset-x-0 bottom-0 max-h-[80vh] bg-white dark:bg-slate-900 rounded-t-3xl shadow-2xl overflow-hidden animate-in slide-in-from-bottom duration-300 flex flex-col">
                      <div className="p-4 border-b border-slate-100 dark:border-slate-800 flex items-center justify-between shrink-0">
                        <span className="font-bold dark:text-white">Settings Section</span>
                        <button onClick={() => setIsSettingsMenuOpen(false)} className="p-2 rounded-full hover:bg-slate-100 dark:hover:bg-slate-800 dark:text-white">
                          <X className="w-5 h-5" />
                        </button>
                      </div>
                      <div className="p-2 overflow-y-auto flex-1 custom-scrollbar">
                        {[
                          { id: 'account', label: 'Account', icon: User },
                          { id: 'general', label: 'General', icon: Settings },
                          { id: 'notifications', label: 'Notifications', icon: Bell },
                          { id: 'vacation', label: 'Vacation', icon: Reply },
                          { id: 'templates', label: 'Templates', icon: File },
                          { id: 'contacts', label: 'Contacts', icon: Users },
                          { id: 'filters', label: 'Filters & Rules', icon: Filter },
                          { id: 'security', label: 'Security', icon: Shield },
                          { id: 'advanced', label: 'Advanced', icon: Key },
                        ].map((item) => (
                          <button 
                            key={item.id}
                            onClick={() => {
                              setIsSettingsSection(item.id as any);
                              setIsSettingsMenuOpen(false);
                            }}
                            className="w-full flex items-center justify-between px-4 py-4 rounded-2xl hover:bg-slate-50 dark:hover:bg-slate-800 transition-colors"
                          >
                            <div className="flex items-center gap-4">
                              <item.icon className={cn("w-5 h-5", isSettingsSection === item.id ? "text-indigo-600 dark:text-indigo-400" : "text-slate-500")} />
                              <span className={cn("text-lg", isSettingsSection === item.id ? "font-bold text-slate-900 dark:text-white" : "text-slate-600 dark:text-slate-400")}>
                                {item.label}
                              </span>
                            </div>
                            {isSettingsSection === item.id && (
                              <div className="w-6 h-6 rounded-full border-2 border-indigo-600 flex items-center justify-center">
                                <div className="w-3 h-3 rounded-full bg-indigo-600" />
                              </div>
                            )}
                          </button>
                        ))}
                      </div>
                    </div>
                  </div>
                )}

                <div className="p-4 max-w-4xl mx-auto space-y-6 md:p-6">
                  {isSettingsSection === 'account' && (
                    <div className="grid gap-6">
                      <div className="bg-white dark:bg-slate-900 p-6 rounded-2xl border border-slate-200 dark:border-slate-800 shadow-sm relative overflow-hidden group">
                        <div className="flex items-center gap-3 mb-6">
                          <div className="p-2 bg-indigo-100 dark:bg-indigo-500/10 rounded-xl">
                            <User className="w-5 h-5 text-indigo-600 dark:text-indigo-400" />
                          </div>
                          <h2 className="text-xl font-bold text-slate-900 dark:text-white">Account Information</h2>
                        </div>
                        
                        <div className="divide-y divide-slate-200 dark:divide-slate-800">
                          <div className="py-4">
                            <div className="text-slate-500 dark:text-slate-400 text-xs font-bold uppercase tracking-wider mb-1">Username</div>
                            <div className="text-slate-900 dark:text-white font-bold text-lg">{credentials.username}</div>
                          </div>
                          <div className="py-4">
                            <div className="text-slate-500 dark:text-slate-400 text-[10px] font-black uppercase tracking-[0.2em] mb-1.5 opacity-60">Server URL</div>
                            <div className="text-slate-900 dark:text-white font-bold truncate leading-relaxed text-sm sm:text-base pr-4" title={credentials.serverUrl}>{credentials.serverUrl}</div>
                          </div>
                          <div className="py-4">
                            <div className="text-slate-500 dark:text-slate-400 text-[10px] font-black uppercase tracking-[0.2em] mb-1.5 opacity-60">API URL</div>
                            <div className="text-slate-900 dark:text-white font-bold truncate leading-relaxed text-sm sm:text-base pr-4" title={credentials.apiUrl || credentials.serverUrl}>{credentials.apiUrl || credentials.serverUrl}</div>
                          </div>
                        </div>
                      </div>
                      
                      <div className="bg-white dark:bg-slate-900 p-6 rounded-2xl border border-slate-200 dark:border-slate-800 shadow-sm">
                        <div className="flex items-center gap-3 mb-6">
                          <div className="p-2 bg-purple-100 dark:bg-purple-500/10 rounded-xl">
                            <Mail className="w-5 h-5 text-purple-600 dark:text-purple-400" />
                          </div>
                          <h2 className="text-xl font-bold text-slate-900 dark:text-white">Email Identities</h2>
                        </div>

                        <div className="space-y-4">
                          { (identities || []).map((identity) => (
                            <div 
                              key={identity.id}
                              onClick={() => handleSetDefaultIdentity(identity.id)}
                              className={cn(
                                "p-4 rounded-2xl border-2 transition-all cursor-pointer relative group",
                                selectedIdentityId === identity.id 
                                  ? "border-indigo-500 bg-indigo-50/30 dark:bg-indigo-500/5" 
                                  : "border-slate-200 dark:border-slate-800 bg-slate-50/50 dark:bg-slate-900/50 hover:border-indigo-200 dark:hover:border-indigo-900"
                              )}
                            >
                              <div className="flex justify-between items-start">
                                <div>
                                  <div className="font-bold text-slate-900 dark:text-white text-lg">{identity.name}</div>
                                  <div className="text-slate-500 dark:text-slate-400">{identity.email}</div>
                                </div>
                                <div className="flex flex-col items-end gap-2">
                                  {selectedIdentityId === identity.id && (
                                    <span className="bg-indigo-600 text-white text-[10px] font-black px-3 py-1 rounded-full tracking-wider shadow-lg shadow-indigo-600/20">
                                      DEFAULT
                                    </span>
                                  )}
                                  <button
                                    onClick={(e) => {
                                      e.stopPropagation();
                                      handleDeleteIdentity(identity.id);
                                    }}
                                    className="p-1.5 text-slate-400 hover:text-red-500 hover:bg-red-50 dark:hover:bg-red-500/10 rounded-lg transition-colors opacity-0 group-hover:opacity-100"
                                    title="Delete Identity"
                                  >
                                    <Trash2 className="w-4 h-4" />
                                  </button>
                                </div>
                              </div>
                            </div>
                          ))}

                          <div className="pt-2">
                            <button 
                              onClick={() => setIsAddingIdentity(true)}
                              className="w-full py-4 rounded-2xl border-2 border-dashed border-slate-200 dark:border-slate-800 text-slate-400 hover:text-indigo-500 hover:border-indigo-500 hover:bg-slate-50 dark:hover:bg-slate-900 transition-all font-medium flex items-center justify-center gap-2"
                            >
                              <Plus className="w-5 h-5" /> Add Another Identity
                            </button>
                          </div>
                        </div>
                      </div>

                      <button 
                        onClick={onLogout}
                        className="w-full py-4 bg-red-50 dark:bg-red-500/10 text-red-600 dark:text-red-400 font-bold rounded-2xl flex items-center justify-center gap-2 hover:bg-red-100 dark:hover:bg-red-500/20 transition-all border border-red-100 dark:border-red-900/30"
                      >
                        <LogOut className="w-5 h-5" /> Sign Out
                      </button>
                    </div>
                  )}

                  {isSettingsSection === 'general' && (
                    <div className="grid gap-6">
                      <div className="bg-white dark:bg-slate-900 p-6 rounded-2xl border border-slate-200 dark:border-slate-800 shadow-sm">
                        <div className="flex items-center gap-3 mb-6">
                          <div className="p-2 bg-blue-100 dark:bg-blue-500/10 rounded-xl">
                            <Settings className="w-5 h-5 text-blue-600 dark:text-blue-400" />
                          </div>
                          <h2 className="text-xl font-bold text-slate-900 dark:text-white">Appearance</h2>
                        </div>

                        <div className="flex flex-row items-center justify-between gap-4">
                          <div className="flex-1 min-w-0 pr-4">
                            <div className="font-bold text-slate-900 dark:text-white text-lg">Dark Mode</div>
                            <div className="text-sm text-slate-500 dark:text-slate-400">Toggle dark theme across the app</div>
                          </div>
                          <button 
                            onClick={() => setIsDarkMode(!isDarkMode)}
                            className={cn(
                              "relative inline-flex h-8 w-14 items-center rounded-full transition-all ring-offset-2 focus:ring-2 focus:ring-indigo-500 shrink-0",
                              isDarkMode ? "bg-indigo-600" : "bg-slate-200 dark:bg-slate-800"
                            )}
                          >
                            <span className={cn("inline-block h-6 w-6 transform rounded-full bg-white shadow-md transition-transform duration-200", isDarkMode ? "translate-x-7" : "translate-x-1")} />
                          </button>
                        </div>
                      </div>

                      <div className="bg-white dark:bg-slate-900 p-6 rounded-2xl border border-slate-200 dark:border-slate-800 shadow-sm">
                        <div className="flex items-center gap-3 mb-6">
                          <div className="p-2 bg-amber-100 dark:bg-amber-500/10 rounded-xl">
                            <Clock className="w-5 h-5 text-amber-600 dark:text-amber-400" />
                          </div>
                          <h2 className="text-xl font-bold text-slate-900 dark:text-white">Regional</h2>
                        </div>

                        <div className="space-y-6">
                          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
                            <span className="text-slate-600 dark:text-slate-400 font-medium">Language</span>
                            <div className="relative">
                              <select className="appearance-none bg-slate-50 dark:bg-slate-800 border border-slate-200 dark:border-slate-700 rounded-xl px-4 py-2 pr-10 text-sm font-bold dark:text-white outline-none focus:ring-2 focus:ring-indigo-500/20">
                                <option>English (US)</option>
                                <option>English (UK)</option>
                                <option>Spanish</option>
                                <option>French</option>
                              </select>
                              <ChevronDown className="absolute right-3 top-1/2 -translate-y-1/2 w-4 h-4 text-slate-400 pointer-events-none" />
                            </div>
                          </div>
                          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
                            <span className="text-slate-600 dark:text-slate-400 font-medium">Timezone</span>
                            <div className="relative">
                              <select 
                                defaultValue={currentTimeZone}
                                className="appearance-none bg-slate-50 dark:bg-slate-800 border border-slate-200 dark:border-slate-700 rounded-xl px-4 py-2 pr-10 text-sm font-bold dark:text-white outline-none focus:ring-2 focus:ring-indigo-500/20 max-w-[200px] truncate"
                              >
                                <option value={currentTimeZone}>{currentTimeZone}</option>
                                <option value="UTC">UTC (Coordinated Universal Time)</option>
                              </select>
                              <ChevronDown className="absolute right-3 top-1/2 -translate-y-1/2 w-4 h-4 text-slate-400 pointer-events-none" />
                            </div>
                          </div>
                        </div>
                      </div>

                      <button 
                        onClick={onLogout}
                        className="w-full py-4 bg-red-50 dark:bg-red-500/10 text-red-600 dark:text-red-400 font-bold rounded-2xl flex items-center justify-center gap-2 hover:bg-red-100 dark:hover:bg-red-500/20 transition-all border border-red-100 dark:border-red-900/30"
                      >
                        <LogOut className="w-5 h-5" /> Sign Out
                      </button>
                    </div>
                  )}

                  {isSettingsSection === 'notifications' && (
                    <div className="grid gap-6">
                      <div className="bg-white dark:bg-slate-900 p-6 rounded-2xl border border-slate-200 dark:border-slate-800 shadow-sm">
                        <div className="flex items-center gap-3 mb-6">
                          <div className="p-2 bg-rose-100 dark:bg-rose-500/10 rounded-xl">
                            <Bell className="w-5 h-5 text-rose-600 dark:text-rose-400" />
                          </div>
                          <h2 className="text-xl font-bold text-slate-900 dark:text-white">Notifications</h2>
                        </div>

                        <div className="space-y-8">
                          <div className="flex flex-row items-center justify-between gap-4">
                            <div className="flex-1 min-w-0 pr-4">
                              <div className="font-bold text-slate-900 dark:text-white text-lg">Desktop Notifications</div>
                              <div className="text-sm text-slate-500 dark:text-slate-400">Show notifications for new emails</div>
                            </div>
                            <button 
                              onClick={async () => {
                                const newValue = !notificationsEnabled;
                                if (newValue) {
                                  if (!("Notification" in window)) {
                                    toast.error("This browser does not support desktop notifications.");
                                    return;
                                  }
                                  
                                  try {
                                    const perm = await Notification.requestPermission();
                                    if (perm === 'granted') {
                                      setNotificationsEnabled(true);
                                      localStorage.setItem('webmail_notifications', 'true');
                                      toast.success("Notifications enabled!");
                                    } else {
                                      const isIframe = window.self !== window.top;
                                      if (isIframe && perm === 'default') {
                                        toast.error("Notification permission blocked by iFrame. Try opening the app in a new tab.");
                                      } else {
                                        toast.error("Notification permission denied.");
                                      }
                                    }
                                  } catch (err) {
                                    toast.error("Could not request notification permission.");
                                  }
                                } else {
                                  setNotificationsEnabled(false);
                                  localStorage.setItem('webmail_notifications', 'false');
                                }
                              }}
                              className={cn(
                                "relative inline-flex h-8 w-14 items-center rounded-full transition-all ring-offset-2 focus:ring-2 focus:ring-indigo-500 shrink-0",
                                notificationsEnabled ? "bg-indigo-600" : "bg-slate-200 dark:bg-slate-800"
                              )}
                            >
                              <span className={cn("inline-block h-6 w-6 transform rounded-full bg-white shadow-md transition-transform duration-200", notificationsEnabled ? "translate-x-7" : "translate-x-1")} />
                            </button>
                          </div>

                          <div className="flex flex-row items-center justify-between gap-4">
                            <div className="flex-1 min-w-0 pr-4">
                              <div className="font-bold text-slate-900 dark:text-white text-lg">Sound Effects</div>
                              <div className="text-sm text-slate-500 dark:text-slate-400">Play sound when a new message arrives</div>
                            </div>
                            <button 
                              onClick={() => {
                                const newValue = !soundEffectsEnabled;
                                setSoundEffectsEnabled(newValue);
                                localStorage.setItem('webmail_sound_effects', newValue.toString());
                              }}
                              className={cn(
                                "relative inline-flex h-8 w-14 items-center rounded-full transition-all ring-offset-2 focus:ring-2 focus:ring-indigo-500 shrink-0",
                                soundEffectsEnabled ? "bg-indigo-600" : "bg-slate-200 dark:bg-slate-800"
                              )}
                            >
                              <span className={cn("inline-block h-6 w-6 transform rounded-full bg-white shadow-md transition-transform duration-200", soundEffectsEnabled ? "translate-x-7" : "translate-x-1")} />
                            </button>
                          </div>
                        </div>
                      </div>

                      <button 
                        onClick={onLogout}
                        className="w-full py-4 bg-red-50 dark:bg-red-500/10 text-red-600 dark:text-red-400 font-bold rounded-2xl flex items-center justify-center gap-2 hover:bg-red-100 dark:hover:bg-red-500/20 transition-all border border-red-100 dark:border-red-900/30"
                      >
                        <LogOut className="w-5 h-5" /> Sign Out
                      </button>
                    </div>
                  )}

                  {isSettingsSection === 'vacation' && (
                    <div className="bg-white dark:bg-slate-900 p-6 rounded-2xl border border-slate-200 dark:border-slate-800 shadow-sm relative overflow-hidden">
                      <div className="absolute top-0 right-0 w-32 h-32 bg-indigo-500/5 rounded-full -mr-16 -mt-16" />
                      
                      <div className="flex items-center gap-3 mb-6">
                        <div className="p-2 bg-indigo-100 dark:bg-indigo-500/10 rounded-xl">
                          <Reply className="w-5 h-5 text-indigo-600 dark:text-indigo-400" />
                        </div>
                        <h2 className="text-xl font-bold text-slate-900 dark:text-white">Auto-Responder</h2>
                      </div>
                      
                      <div className="flex flex-row items-center justify-between mb-8 p-4 bg-slate-50 dark:bg-slate-800/50 rounded-2xl gap-4">
                        <div className="flex-1 min-w-0 pr-4">
                          <div className="font-bold text-slate-900 dark:text-white text-lg">Enable Auto-Reply</div>
                          <div className="text-sm text-slate-500 dark:text-slate-400">Automatically reply to incoming emails</div>
                        </div>
                        <button 
                          onClick={() => setVacationEnabled(!vacationEnabled)}
                          className={cn(
                            "relative inline-flex h-8 w-14 items-center rounded-full transition-all shrink-0",
                            vacationEnabled ? "bg-indigo-600" : "bg-slate-300 dark:bg-slate-700"
                          )}
                        >
                          <span className={cn("inline-block h-6 w-6 transform rounded-full bg-white shadow-md transition-transform duration-200", vacationEnabled ? "translate-x-7" : "translate-x-1")} />
                        </button>
                      </div>

                      <div className={cn("space-y-6 transition-all duration-300", vacationEnabled ? "opacity-100" : "opacity-40 pointer-events-none")}>
                        <div className="space-y-2">
                          <label className="text-sm font-bold text-slate-700 dark:text-slate-300 ml-1">Subject (Header)</label>
                          <input 
                            type="text"
                            value={vacationSubject}
                            onChange={(e) => setVacationSubject(e.target.value)}
                            className="w-full bg-slate-50 dark:bg-slate-800 border border-slate-200 dark:border-slate-700 rounded-2xl px-5 py-4 text-sm font-medium outline-none focus:ring-2 focus:ring-indigo-500/20 focus:border-indigo-500 dark:text-white transition-all"
                            placeholder="Out of Office"
                          />
                        </div>
                        <div className="space-y-2">
                          <label className="text-sm font-bold text-slate-700 dark:text-slate-300 ml-1">Message (Body)</label>
                          <textarea 
                            value={vacationText}
                            onChange={(e) => setVacationText(e.target.value)}
                            className="w-full h-48 bg-slate-50 dark:bg-slate-800 border border-slate-200 dark:border-slate-700 rounded-2xl px-5 py-4 text-sm font-medium outline-none focus:ring-2 focus:ring-indigo-500/20 focus:border-indigo-500 dark:text-white transition-all resize-none"
                            placeholder="I am currently away..."
                          />
                        </div>
                      </div>
                        
                      <div className="pt-6">
                        <button 
                          onClick={async () => {
                              setIsSavingVacation(true);
                              try {
                                const client = new JmapClient(credentials);
                                await client.setVacationResponse({
                                  isEnabled: vacationEnabled,
                                  subject: vacationSubject,
                                  textBody: vacationText
                                });
                                toast.success("Vacation responder updated!");
                              } catch (e) {
                                toast.error("Failed to save vacation responder.");
                              } finally {
                                setIsSavingVacation(false);
                              }
                            }}
                            disabled={isSavingVacation}
                            className="w-full sm:w-auto px-8 py-4 bg-indigo-600 hover:bg-indigo-700 disabled:opacity-50 text-white font-bold rounded-2xl shadow-lg shadow-indigo-600/20 flex items-center justify-center gap-2 transition-all active:scale-[0.98]"
                          >
                            {isSavingVacation ? <Loader2 className="w-5 h-5 animate-spin" /> : <MailCheck className="w-5 h-5" />}
                            Update Responder
                          </button>
                        </div>
                    </div>
                  )}

                  {isSettingsSection === 'security' && (
                    <div className="grid gap-6">
                      <div className="bg-white dark:bg-slate-900 p-6 rounded-2xl border border-slate-200 dark:border-slate-800 shadow-sm">
                        <div className="flex items-center gap-3 mb-6">
                          <div className="p-2 bg-emerald-100 dark:bg-emerald-500/10 rounded-xl">
                            <Shield className="w-5 h-5 text-emerald-600 dark:text-emerald-400" />
                          </div>
                          <h2 className="text-xl font-bold text-slate-900 dark:text-white">Security & Privacy</h2>
                        </div>
                        
                        <div className="p-6 bg-orange-50 dark:bg-orange-900/10 border border-orange-100 dark:border-orange-800 rounded-2xl mb-8">
                          <div className="flex gap-4 items-start">
                            <AlertCircle className="w-6 h-6 text-orange-500 shrink-0 mt-0.5" />
                            <div>
                              <h4 className="font-bold text-orange-800 dark:text-orange-300 mb-1">External Credential Management</h4>
                              <p className="text-sm text-orange-700 dark:text-orange-400 leading-relaxed">
                                JMAP sessions are managed by your mail provider. To change your primary login password, please visit your provider's main administration console.
                              </p>
                            </div>
                          </div>
                        </div>

                        <div className="space-y-6">
                          <div className="flex justify-between items-center py-4 border-b border-slate-200 dark:border-slate-800 gap-4">
                            <div className="flex-1 min-w-0">
                              <div className="font-bold text-slate-900 dark:text-white">Active Encryption</div>
                              <div className="text-xs text-slate-500 dark:text-slate-400">AES-GCM 256-bit local encryption is active</div>
                            </div>
                            <MailCheck className="w-6 h-6 text-emerald-500 shrink-0" />
                          </div>
                          <div className="flex justify-between items-center py-4 gap-4">
                            <div className="flex-1 min-w-0">
                              <div className="font-bold text-slate-900 dark:text-white">Authentication Method</div>
                              <div className="text-xs text-slate-500 dark:text-slate-400">JMAP Session Authentication</div>
                            </div>
                            <span className="text-xs font-bold px-3 py-1 bg-slate-100 dark:bg-slate-800 rounded-lg text-slate-600 dark:text-slate-400 uppercase tracking-widest shrink-0">Active</span>
                          </div>
                        </div>
                      </div>
                      
                      <button 
                        onClick={onLogout}
                        className="w-full py-4 bg-red-50 dark:bg-red-500/10 text-red-600 dark:text-red-400 font-bold rounded-2xl flex items-center justify-center gap-2 hover:bg-red-100 dark:hover:bg-red-500/20 transition-all border border-red-100 dark:border-red-900/30"
                      >
                        <LogOut className="w-5 h-5" /> Sign Out
                      </button>
                    </div>
                  )}

                  {isSettingsSection === 'templates' && (
                    <div className="bg-white dark:bg-slate-900 p-6 rounded-xl border border-slate-200 dark:border-slate-800 shadow-sm">
                      <h2 className="text-lg font-semibold text-slate-900 dark:text-white mb-4 flex items-center gap-2">
                        <File className="w-5 h-5 text-indigo-500" /> Template Management
                      </h2>
                      <p className="text-sm text-slate-500 dark:text-slate-400 mb-6">
                        Backup your server-side templates to a JSON file, or restore them from a previous backup.
                      </p>
                      <div className="flex gap-4">
                        <button 
                          onClick={handleExportServerTemplates}
                          disabled={isLoading}
                          className="flex-1 px-4 py-3 border border-slate-200 dark:border-slate-700 text-slate-700 dark:text-slate-300 font-bold rounded-xl hover:bg-slate-50 dark:hover:bg-slate-800 transition-all flex items-center justify-center gap-2"
                        >
                          <Download className="w-4 h-4" /> Export Backup
                        </button>
                        <div className="flex-1 relative">
                          <input 
                            type="file" 
                            accept=".json"
                            onChange={handleImportServerTemplates}
                            disabled={isLoading}
                            className="absolute inset-0 w-full h-full opacity-0 cursor-pointer disabled:cursor-not-allowed"
                          />
                          <button 
                            disabled={isLoading}
                            className="w-full px-4 py-3 bg-indigo-600 hover:bg-indigo-700 text-white font-bold rounded-xl shadow-lg shadow-indigo-500/20 transition-all flex items-center justify-center gap-2"
                          >
                            {isLoading ? <Loader2 className="w-4 h-4 animate-spin" /> : <Upload className="w-4 h-4" />}
                            Import from File
                          </button>
                        </div>
                      </div>
                    </div>
                  )}

                  {isSettingsSection === 'contacts' && (
                    <div className="bg-white dark:bg-slate-900 p-6 rounded-xl border border-slate-200 dark:border-slate-800 shadow-sm">
                      <h2 className="text-lg font-semibold text-slate-900 dark:text-white mb-4 flex items-center gap-2">
                        <Users className="w-5 h-5 text-indigo-500" /> Contact Management
                      </h2>
                      <p className="text-sm text-slate-500 dark:text-slate-400 mb-6">
                        Backup your contacts to a vCard file, or restore them from a vCard backup.
                      </p>
                      <div className="flex gap-4">
                        <button 
                          onClick={handleExportContacts}
                          disabled={isLoading}
                          className="flex-1 px-4 py-3 border border-slate-200 dark:border-slate-700 text-slate-700 dark:text-slate-300 font-bold rounded-xl hover:bg-slate-50 dark:hover:bg-slate-800 transition-all flex items-center justify-center gap-2"
                        >
                          <Download className="w-4 h-4" /> Export Contacts
                        </button>
                        <div className="flex-1 relative">
                          <button 
                            onClick={() => setIsImportModalOpen(true)}
                            disabled={isLoading}
                            className="w-full px-4 py-3 bg-indigo-600 hover:bg-indigo-700 text-white font-bold rounded-xl shadow-lg shadow-indigo-500/20 transition-all flex items-center justify-center gap-2"
                          >
                            <Upload className="w-4 h-4" /> Import Contacts
                          </button>
                        </div>
                      </div>
                    </div>
                  )}

                  {isSettingsSection === 'filters' && (
                    <div className="grid gap-6">
                      <div className="bg-white dark:bg-slate-900 p-6 rounded-2xl border border-slate-200 dark:border-slate-800 shadow-sm transition-all duration-300">
                        <div className="flex items-center gap-3 mb-6">
                          <div className="p-2 bg-indigo-100 dark:bg-indigo-500/10 rounded-xl">
                            <Sparkles className="w-5 h-5 text-indigo-600 dark:text-indigo-400" />
                          </div>
                          <div>
                            <h2 className="text-xl font-bold text-slate-900 dark:text-white">Smart Categories</h2>
                            <p className="text-xs text-slate-500 dark:text-slate-400">Automatically sort incoming mail into dedicated folders.</p>
                          </div>
                        </div>

                        <div className="space-y-4">
                          {[
                            { id: 'promotions', label: 'Promotions', description: 'Marketing, newsletters, and promotional emails', active: filterPromotions },
                            { id: 'social', label: 'Social', description: 'Notifications from social networks and media sites', active: filterSocial },
                            { id: 'updates', label: 'Updates', description: 'Transactional emails, receipts, and confirmations', active: filterUpdates },
                          ].map((cat) => (
                            <div key={cat.id} className="flex flex-row items-center justify-between p-4 rounded-2xl bg-slate-50 dark:bg-slate-800/50 border border-slate-100 dark:border-slate-800 transition-colors gap-4">
                              <div className="flex-1 min-w-0 pr-4">
                                <div className="font-bold text-slate-900 dark:text-white text-lg">{cat.label}</div>
                                <div className="text-sm text-slate-500 dark:text-slate-400">{cat.description}</div>
                              </div>
                              <button 
                                onClick={() => {
                                  const newState = !cat.active;
                                  if (cat.id === 'promotions') { setFilterPromotions(newState); localStorage.setItem('webmail_filter_promo', newState.toString()); compileAndPushSieve(newState, filterSocial, filterUpdates); }
                                  if (cat.id === 'social') { setFilterSocial(newState); localStorage.setItem('webmail_filter_social', newState.toString()); compileAndPushSieve(filterPromotions, newState, filterUpdates); }
                                  if (cat.id === 'updates') { setFilterUpdates(newState); localStorage.setItem('webmail_filter_updates', newState.toString()); compileAndPushSieve(filterPromotions, filterSocial, newState); }
                                }}
                                className={cn(
                                  "relative inline-flex h-8 w-14 items-center rounded-full transition-all focus:outline-none focus:ring-2 focus:ring-indigo-500 focus:ring-offset-2 dark:focus:ring-offset-slate-900 shrink-0",
                                  cat.active ? "bg-indigo-600" : "bg-slate-200 dark:bg-slate-800"
                                )}
                              >
                                <span className={cn("inline-block h-6 w-6 transform rounded-full bg-white shadow-md transition-transform duration-200", cat.active ? "translate-x-7" : "translate-x-1")} />
                              </button>
                            </div>
                          ))}
                        </div>
                      </div>

                      <div className="bg-white dark:bg-[#050505] p-6 rounded-2xl border border-slate-200 dark:border-slate-800 shadow-sm overflow-hidden relative">
                        <div className="flex items-center gap-3 mb-6">
                          <div className="p-2 bg-indigo-100 dark:bg-indigo-500/10 rounded-xl">
                            <Filter className="w-5 h-5 text-indigo-600 dark:text-indigo-400" />
                          </div>
                          <div>
                            <h2 className="text-xl font-bold text-slate-900 dark:text-white">Custom Rules</h2>
                            <p className="text-xs text-slate-500 dark:text-slate-400">Create specific Sieve rules to route, flag, or delete incoming messages.</p>
                          </div>
                        </div>

                        <div className="py-12 flex flex-col items-center justify-center text-center border-2 border-dashed border-slate-100 dark:border-slate-800 rounded-3xl bg-slate-50/50 dark:bg-black">
                          <div className="w-16 h-16 bg-slate-100 dark:bg-[#11131f] rounded-2xl flex items-center justify-center mb-4 text-slate-400">
                            <Filter className="w-8 h-8" />
                          </div>
                          <h3 className="text-lg font-bold text-slate-900 dark:text-white mb-2">No custom rules active</h3>
                          <p className="text-sm text-slate-500 dark:text-slate-400 mb-8 max-w-xs">
                            Organize your inbox by setting up automated rules for your incoming messages.
                          </p>
                          <button className="px-8 py-4 bg-indigo-600 hover:bg-indigo-700 text-white font-bold rounded-2xl shadow-lg shadow-indigo-600/20 transition-all active:scale-[0.98]">
                            Create New Rule
                          </button>
                        </div>
                      </div>
                    </div>
                  )}

                  {isSettingsSection === 'advanced' && (
                    <div className="grid gap-6">
                      <div className="bg-white dark:bg-[#050505] p-6 rounded-2xl border border-slate-200 dark:border-slate-800 shadow-sm">
                        <div className="flex items-center gap-3 mb-6">
                          <div className="p-2 bg-indigo-100 dark:bg-indigo-500/10 rounded-xl">
                            <Key className="w-5 h-5 text-indigo-600 dark:text-indigo-400" />
                          </div>
                          <h2 className="text-xl font-bold text-slate-900 dark:text-white">Advanced Settings</h2>
                        </div>
                        
                        <div className="space-y-6">
                          <div className="flex items-center justify-between gap-4">
                            <div className="flex-1 min-w-0">
                              <div className="font-bold text-slate-900 dark:text-white">Developer Mode</div>
                              <div className="text-xs text-slate-500 dark:text-slate-400">Enable advanced API debugging logs</div>
                            </div>
                            <button disabled className="relative inline-flex h-8 w-14 items-center rounded-full bg-slate-100 dark:bg-slate-800 opacity-50 cursor-not-allowed shrink-0">
                              <span className="inline-block h-6 w-6 transform rounded-full bg-white transition-transform translate-x-1 shadow-md" />
                            </button>
                          </div>
                          <div className="flex items-center justify-between gap-4">
                            <div className="flex-1 min-w-0">
                              <div className="font-bold text-slate-900 dark:text-white">Beta Features</div>
                              <div className="text-xs text-slate-500 dark:text-slate-400">Try out experimental UI improvements</div>
                            </div>
                            <button className="relative inline-flex h-8 w-14 items-center rounded-full bg-indigo-600 ring-offset-2 focus:ring-2 focus:ring-indigo-500 shrink-0">
                              <span className="inline-block h-6 w-6 transform rounded-full bg-white transition-transform translate-x-7 shadow-md" />
                            </button>
                          </div>
                        </div>
                      </div>

                      <button 
                        onClick={onLogout}
                        className="w-full py-4 bg-red-50 dark:bg-red-500/10 text-red-600 dark:text-red-400 font-bold rounded-2xl flex items-center justify-center gap-2 hover:bg-red-100 dark:hover:bg-red-500/20 transition-all border border-red-100 dark:border-red-900/30"
                      >
                        <LogOut className="w-5 h-5" /> Sign Out
                      </button>
                    </div>
                  )}
                </div>
              </div>
            </div>
          )}
          
          {/* Floating Action Button (Compose / Create Template) */}
          {((activeApp === 'mail' && !isSidebarOpen)) && (
            <button 
              onClick={() => {
                setEditingTemplateId(null);
                setSubject('');
                setEmailBody('');
                setIsComposeOpen(true);
              }}
              className={cn(
                "fixed bottom-6 right-4 z-40 bg-indigo-600 hover:bg-indigo-700 text-white shadow-xl flex items-center justify-center transition-all active:scale-90 group overflow-hidden md:hidden",
                mailboxes.find(m => m.id === selectedMailbox)?.name.toLowerCase() === 'templates'
                  ? "px-6 py-3.5 rounded-2xl" 
                  : "p-3.5 rounded-full"
              )}
              title={mailboxes.find(m => m.id === selectedMailbox)?.name.toLowerCase() === 'templates' ? "Create a template" : "Compose"}
            >
              <div className="flex items-center gap-2">
                <Edit3 className="w-5 h-5" />
                {mailboxes.find(m => m.id === selectedMailbox)?.name.toLowerCase() === 'templates' && (
                  <span className="font-bold whitespace-nowrap text-sm">Create</span>
                )}
              </div>
            </button>
          )}
        </div>
      </main>

      {/* Identity Addition Modal */}
      {isAddingIdentity && (
        <div className="fixed inset-0 z-[110] flex items-center justify-center p-4">
          <div className="absolute inset-0 bg-black/60 backdrop-blur-sm" onClick={() => setIsAddingIdentity(false)} />
          <div className="relative bg-white dark:bg-slate-900 w-full max-w-md rounded-2xl shadow-2xl p-6 animate-in zoom-in-95 duration-200 border border-slate-200 dark:border-slate-800">
            <h3 className="text-xl font-bold text-slate-900 dark:text-white mb-6">Add New Identity</h3>
            <div className="space-y-4">
              <div>
                <label className="block text-sm font-bold text-slate-700 dark:text-slate-300 mb-1.5 ml-1">Display Name</label>
                <input 
                  type="text"
                  value={newIdentityName}
                  onChange={(e) => setNewIdentityName(e.target.value)}
                  className="w-full bg-slate-50 dark:bg-slate-800 border border-slate-200 dark:border-slate-700 rounded-xl px-4 py-3 text-sm focus:ring-2 focus:ring-indigo-500/20 focus:border-indigo-500 outline-none dark:text-white transition-all font-medium"
                  placeholder="e.g. Sunil Shahid"
                />
              </div>
              <div>
                <label className="block text-sm font-bold text-slate-700 dark:text-slate-300 mb-1.5 ml-1">Email Address</label>
                <input 
                  type="email"
                  value={newIdentityEmail}
                  onChange={(e) => setNewIdentityEmail(e.target.value)}
                  className="w-full bg-slate-50 dark:bg-slate-800 border border-slate-200 dark:border-slate-700 rounded-xl px-4 py-3 text-sm focus:ring-2 focus:ring-indigo-500/20 focus:border-indigo-500 outline-none dark:text-white transition-all font-medium"
                  placeholder="e.g. sunil@example.com"
                />
              </div>
              
              <div className="pt-4 flex gap-3">
                <button 
                  onClick={() => setIsAddingIdentity(false)}
                  className="flex-1 py-3 px-4 rounded-xl text-sm font-bold border border-slate-200 dark:border-slate-700 text-slate-600 dark:text-slate-400 hover:bg-slate-50 dark:hover:bg-slate-800 transition-all active:scale-[0.98]"
                >
                  Cancel
                </button>
                <button 
                   onClick={async () => {
                     await handleCreateIdentity();
                     setIsAddingIdentity(false);
                   }}
                  className="flex-2 py-3 px-4 rounded-xl text-sm font-bold bg-indigo-600 hover:bg-indigo-700 text-white shadow-lg shadow-indigo-600/20 transition-all active:scale-[0.98]"
                >
                  Create Identity
                </button>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Compose Modal */}
      {isComposeOpen && (
        <div 
          style={{ height: viewportHeight }}
          className="fixed inset-0 z-50 flex flex-col bg-[#f8f9fa] dark:bg-black w-full overflow-hidden animate-in fade-in slide-in-from-bottom-4 duration-200"
        >
          <div className="h-16 flex items-center justify-between px-4 shrink-0 bg-transparent">
            <div className="flex items-center gap-4 text-slate-700 dark:text-slate-200">
              <button 
                onClick={() => {
                  setIsComposeOpen(false);
                  setEditingTemplateId(null);
                  setDraftAttachments([]);
                }}
                className="p-1 hover:bg-black/5 dark:hover:bg-white/10 rounded-full transition-colors"
              >
                <ArrowLeft className="w-6 h-6" />
              </button>
              <span className="font-medium text-xl">
                {(() => {
                  const m = mailboxes.find(mb => mb.id === selectedMailbox);
                  const isTemplateFolder = m?.role === 'templates' || m?.name.toLowerCase() === 'templates';
                  if (isTemplateFolder) {
                    return editingTemplateId ? "Edit Template" : "New Template";
                  }
                  return "Compose";
                })()}
              </span>
            </div>
            <button className="p-2 text-slate-500 dark:text-slate-400">
              <MoreVertical className="w-5 h-5" />
            </button>
          </div>

          <div className="flex-1 overflow-y-auto flex flex-col p-6 gap-6 px-4 sm:px-8 relative">
              {(() => {
                const folder = mailboxes.find(m => m.id === selectedMailbox);
                const isTemplateFolder = folder?.role === 'templates' || folder?.name.toLowerCase() === 'templates';
                
                return (
                  <>
                    {!isTemplateFolder && (
                      <div className="flex flex-col gap-0 w-full shrink-0 mt-4">
                        <div className="flex items-center gap-4 border-b border-black/5 dark:border-white/10 pb-4">
                          <span className="text-[11px] font-semibold tracking-widest text-slate-500 uppercase w-12">From</span>
                          <div className="flex-1 relative">
                            <div 
                              onClick={() => setIsIdentityDropdownOpen(!isIdentityDropdownOpen)}
                              className="flex justify-between items-center cursor-pointer"
                            >
                              <div className="flex items-center gap-3">
                                <div className={cn(
                                  "w-6 h-6 rounded-full flex items-center justify-center text-[10px] text-white font-bold shrink-0",
                                  getAccountColor(identities.find(i => i.id === selectedIdentityId)?.email || "")
                                )}>
                                  {(identities.find(i => i.id === selectedIdentityId)?.name || "?").charAt(0).toUpperCase()}
                                </div>
                                <span className="text-[15px] font-medium text-slate-800 dark:text-slate-200">
                                  {identities.find(i => i.id === selectedIdentityId)?.email}
                                </span>
                              </div>
                              <ChevronDown className={cn("w-4 h-4 text-slate-400 transition-transform", isIdentityDropdownOpen && "rotate-180")} />
                            </div>

                            {isIdentityDropdownOpen && (
                              <>
                                <div className="fixed inset-0 z-10" onClick={() => setIsIdentityDropdownOpen(false)} />
                                <div className="absolute top-full left-0 right-0 mt-2 bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-xl shadow-xl z-20 py-2 animate-in fade-in zoom-in-95 duration-150 overflow-hidden">
                                  {(identities || []).map(id => (
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

                        <div className="flex items-center gap-4 border-b border-black/5 dark:border-white/10 py-4 relative">
                          <span className="text-[11px] font-semibold tracking-widest text-slate-500 uppercase w-12">To</span>
                          <div className="flex-1 flex flex-wrap items-center gap-2">
                            <button 
                              onClick={() => setIsContactPickerOpen(true)}
                              className="p-1.5 text-slate-400 hover:text-indigo-600 dark:hover:text-indigo-400 hover:bg-slate-100 dark:hover:bg-slate-800 rounded-full transition-all shrink-0"
                              title="Select from contacts"
                            >
                              <Plus className="w-4 h-4" />
                            </button>
                            {(toAddresses || []).map((email, idx) => (
                              <div key={idx} className="flex items-center gap-1 bg-slate-200/50 dark:bg-slate-800 text-slate-700 dark:text-slate-300 px-3 py-1 rounded-full text-sm font-medium max-w-full">
                                <span className="truncate max-w-[150px] sm:max-w-xs">{email}</span>
                                <button 
                                  onClick={() => setToAddresses(toAddresses.filter((_, i) => i !== idx))} 
                                  className="hover:text-slate-900 dark:hover:text-white ml-1 shrink-0"
                                >
                                  <X className="w-3 h-3" />
                                </button>
                              </div>
                            ))}
                            <input 
                              type="text" 
                              value={toInput}
                              placeholder={toAddresses.length === 0 ? "Add recipients" : ""}
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
                              onKeyDown={(e) => {
                                if (e.key === 'Enter' || e.key === ' ' || e.key === ',') {
                                  e.preventDefault();
                                  const parts = toInput.split(',').map(p => p.trim()).filter(Boolean);
                                  if (parts.length > 0) {
                                    const newAddresses = parts.filter(p => !toAddresses.includes(p));
                                    if (newAddresses.length > 0) {
                                      setToAddresses([...toAddresses, ...newAddresses]);
                                    }
                                    setToInput('');
                                    setContactSuggestions([]);
                                  }
                                } else if (e.key === 'Backspace' && !toInput && toAddresses.length > 0) {
                                  setToAddresses(toAddresses.slice(0, -1));
                                }
                              }}
                              onBlur={() => {
                                setTimeout(() => {
                                  const parts = toInput.split(',').map(p => p.trim()).filter(Boolean);
                                  if (parts.length > 0) {
                                    const newAddresses = parts.filter(p => !toAddresses.includes(p));
                                    if (newAddresses.length > 0) {
                                      setToAddresses([...toAddresses, ...newAddresses]);
                                    }
                                    setToInput('');
                                    setContactSuggestions([]);
                                  }
                                }, 200);
                              }}
                              className="flex-1 min-w-[120px] bg-transparent outline-none text-slate-900 dark:text-white placeholder:text-slate-400 text-[15px]"
                            />
                            <button 
                              onClick={() => setIsContactSelectorModalOpen(true)}
                              className="w-5 h-5 rounded-full bg-purple-700 hover:bg-purple-800 text-white flex items-center justify-center shrink-0 transition-colors"
                            >
                               <Plus className="w-3 h-3" />
                            </button>
                            {contactSuggestions.length > 0 && (
                              <div className="absolute top-full left-0 right-0 mt-1 bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-xl shadow-xl z-30 py-2 animate-in fade-in zoom-in-95 duration-150 overflow-hidden">
                                {(contactSuggestions || []).map((contact, idx) => (
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
                      </div>
                    )}

                    <input 
                      type="text" 
                      placeholder={isTemplateFolder ? "Template Subject" : "Subject"} 
                      value={subject}
                      onChange={(e) => setSubject(e.target.value)}
                      className="w-full border-b border-black/5 dark:border-white/10 pb-6 pt-4 bg-transparent outline-none transition-colors font-extrabold text-4xl text-slate-900 dark:text-white shrink-0 placeholder:text-slate-400 dark:placeholder:text-slate-500 placeholder:font-extrabold"
                    />

                    {isSecureMessage && !isTemplateFolder ? (
                      <div className="bg-indigo-50/50 dark:bg-indigo-500/5 border border-indigo-100 dark:border-indigo-500/20 rounded-2xl p-5 mt-2 animate-in fade-in slide-in-from-top-4 duration-300">
                        <div className="flex items-center gap-3 mb-4">
                          <div className="w-8 h-8 rounded-lg bg-indigo-100 dark:bg-indigo-500/20 flex items-center justify-center">
                            <Lock className="w-4 h-4 text-indigo-600 dark:text-indigo-400" />
                          </div>
                          <span className="font-bold text-indigo-900 dark:text-indigo-100">PrivateBin Encryption</span>
                        </div>

                        {/* Attachment Pills Area */}
                        {(draftAttachments.length > 0 || isUploading) && (
                          <div className="mb-4 flex flex-wrap gap-2 animate-in fade-in slide-in-from-top-2">
                             {draftAttachments.map((att, idx) => (
                               <div key={idx} className="flex items-center gap-2 bg-indigo-100/50 dark:bg-indigo-500/20 border border-indigo-200/50 dark:border-indigo-500/30 px-3 py-1.5 rounded-full group transition-all hover:bg-white dark:hover:bg-slate-800">
                                 <File className="w-3.5 h-3.5 text-indigo-600 dark:text-indigo-400" />
                                 <span className="text-xs font-bold text-indigo-900 dark:text-indigo-100 max-w-[120px] truncate">{att.name}</span>
                                 <span className="text-[10px] text-indigo-500/70 font-medium">{formatFileSize(att.size)}</span>
                                 <button 
                                   onClick={() => setDraftAttachments(prev => prev.filter((_, i) => i !== idx))}
                                   className="w-4 h-4 rounded-full bg-indigo-200 dark:bg-indigo-500/40 flex items-center justify-center hover:bg-red-500 hover:text-white transition-all ml-1"
                                 >
                                   <X className="w-2.5 h-2.5" />
                                 </button>
                               </div>
                             ))}
                             {isUploading && (
                               <div className="flex items-center gap-2 px-3 py-1.5 bg-slate-100 dark:bg-slate-800 rounded-full animate-pulse">
                                 <Loader2 className="w-3 h-3 animate-spin text-indigo-500" />
                                 <span className="text-xs text-slate-500">Uploading...</span>
                               </div>
                             )}
                          </div>
                        )}
                        
                        <textarea 
                          value={emailBody}
                          onChange={(e) => setEmailBody(e.target.value)}
                          placeholder="Type your highly sensitive message here. It will be encrypted in your browser before a link is generated..."
                          className="w-full bg-white dark:bg-slate-900 border border-indigo-100 dark:border-indigo-500/30 rounded-xl p-4 min-h-[150px] outline-none focus:ring-2 focus:ring-indigo-500/20 transition-all text-slate-700 dark:text-slate-200 placeholder:text-slate-400 dark:placeholder:text-slate-500 resize-none"
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
                      <>
                        {/* Attachment Pills Area */}
                        {(draftAttachments.length > 0 || isUploading) && (
                          <div className="mb-2 flex flex-wrap gap-2 animate-in fade-in slide-in-from-top-2">
                             {draftAttachments.map((att, idx) => (
                               <div key={idx} className="flex items-center gap-2 bg-slate-100 dark:bg-slate-800 border border-slate-200 dark:border-slate-700 px-3 py-1.5 rounded-full group transition-all hover:bg-white dark:hover:bg-slate-900">
                                 <File className="w-3.5 h-3.5 text-slate-500" />
                                 <span className="text-xs font-bold text-slate-700 dark:text-slate-300 max-w-[120px] truncate">{att.name}</span>
                                 <span className="text-[10px] text-slate-400 font-medium">{formatFileSize(att.size)}</span>
                                 <button 
                                   onClick={() => setDraftAttachments(prev => prev.filter((_, i) => i !== idx))}
                                   className="w-4 h-4 rounded-full bg-slate-200 dark:bg-slate-700 flex items-center justify-center hover:bg-red-500 hover:text-white transition-all ml-1"
                                 >
                                   <X className="w-2.5 h-2.5" />
                                 </button>
                               </div>
                             ))}
                             {isUploading && (
                               <div className="flex items-center gap-2 px-3 py-1.5 bg-slate-50 dark:bg-slate-900 rounded-full animate-pulse border border-slate-100 dark:border-slate-800">
                                 <Loader2 className="w-3 h-3 animate-spin text-purple-500" />
                                 <span className="text-xs text-slate-500">Uploading...</span>
                               </div>
                             )}
                          </div>
                        )}
                        <textarea 
                          placeholder={isTemplateFolder ? "Type your template body here..." : "Start writing your masterpiece..."} 
                          value={emailBody}
                        onChange={(e) => setEmailBody(e.target.value)}
                        className="w-full flex-1 resize-none outline-none pt-4 bg-transparent text-[15px] leading-relaxed text-slate-900 dark:text-white placeholder:text-slate-300"
                      />
                    </>
                  )}
                </>
              );
            })()}
          </div>
            
            {/* The Floating Bottom Action Pill (Placed relatively at bottom of flex col above keyboard) */}
            <div className="shrink-0 pb-6 pt-2 px-4 flex justify-center w-full z-10">
              <div className="relative w-full max-w-sm">
                {isScheduling && (
                  <div className="absolute bottom-[calc(100%+0.5rem)] left-0 w-full bg-white dark:bg-slate-900 rounded-2xl shadow-xl p-4 border border-slate-200 dark:border-slate-800 animate-in fade-in slide-in-from-bottom-2">
                     <div className="text-sm font-bold text-slate-800 dark:text-slate-200 mb-2">Schedule Send</div>
                     <input
                       type="datetime-local"
                       value={scheduleTime}
                       onChange={(e) => setScheduleTime(e.target.value)}
                       className="w-full px-4 py-2 border border-slate-200 dark:border-slate-700 rounded-xl bg-slate-50 dark:bg-black text-sm outline-none focus:ring-2 focus:ring-purple-500/20 text-slate-900 dark:text-white"
                     />
                  </div>
                )}
                
                <div className="bg-white/80 dark:bg-[#1a1a1a]/80 backdrop-blur-xl rounded-[2rem] shadow-[0_8px_30px_rgb(0,0,0,0.12)] border border-slate-200/50 dark:border-white/10 p-2 flex items-center justify-between px-4 w-full relative z-20">
                  <div className="flex items-center gap-4">
                    <label className={cn(
                      "cursor-pointer p-2 rounded-full transition-colors flex items-center justify-center",
                      isUploading ? "opacity-50 cursor-not-allowed" : "hover:bg-black/5 dark:hover:bg-white/10"
                    )}>
                       <input 
                         type="file" 
                         multiple 
                         onChange={handleFileUpload} 
                         className="hidden" 
                         disabled={isUploading} 
                       />
                       <svg className="w-[18px] h-[18px] text-slate-600 dark:text-slate-300" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round"><path d="m21.44 11.05-9.19 9.19a6 6 0 0 1-8.49-8.49l8.57-8.57A4 4 0 1 1 18 8.84l-8.59 8.57a2 2 0 0 1-2.83-2.83l8.49-8.48"/></svg>
                    </label>
                    <button 
                      type="button" 
                      onClick={() => setIsSecureMessage(!isSecureMessage)}
                      className={cn(
                        "h-10 flex items-center justify-center transition-all duration-300 ease-out",
                        isSecureMessage 
                          ? "w-auto px-5 rounded-full bg-[#ad57ff] text-white shadow-md shadow-purple-500/20" 
                          : "w-10 rounded-full text-slate-600 dark:text-slate-300 hover:text-slate-900 dark:hover:text-white hover:bg-black/5 dark:hover:bg-white/5"
                      )}
                    >
                       <Lock className="w-[18px] h-[18px] shrink-0" strokeWidth={isSecureMessage ? 2.5 : 2} fill={isSecureMessage ? "#fff" : "none"} color={isSecureMessage ? "#fff" : "currentColor"} />
                    </button>
                    <button 
                      type="button" 
                      onClick={() => setIsScheduling(!isScheduling)}
                      className={cn(
                        "transition-colors",
                        isScheduling ? "text-purple-600" : "text-slate-600 dark:text-slate-300 hover:text-slate-900 dark:hover:text-white"
                      )}
                    >
                       <Clock className="w-[18px] h-[18px]" />
                    </button>
                    <button 
                      type="button" 
                      onClick={async () => {
                        setIsTemplateSelectorOpen(true);
                        setIsLoadingTemplates(true);
                        try {
                          const tplMailbox = mailboxes.find(m => m.role === 'templates' || m.name.toLowerCase() === 'templates');
                          if (tplMailbox && credentials) {
                            const client = new JmapClient(credentials);
                            const result = await client.getEmails(tplMailbox.id);
                            setServerTemplates(result);
                          } else {
                            setServerTemplates([]);
                          }
                        } catch (err) {
                          toast.error("Failed to load templates");
                        } finally {
                          setIsLoadingTemplates(false);
                        }
                       }}
                       className="text-slate-600 dark:text-slate-300 hover:text-slate-900 dark:hover:text-white transition-colors"
                    >
                       <File className="w-[18px] h-[18px]" />
                    </button>
                  </div>
                  
                  <div className="flex items-center gap-3">
                     <div className="w-[1px] h-6 bg-slate-200 dark:bg-slate-700"></div>
                     {(() => {
                       const m = mailboxes.find(mb => mb.id === selectedMailbox);
                       const isTemplateFolder = m?.role === 'templates' || m?.name.toLowerCase() === 'templates';
                       if (isTemplateFolder) {
                         return (
                           <button 
                              onClick={handleSaveAsTemplate}
                              disabled={isSending}
                              className="bg-purple-600 hover:bg-purple-700 disabled:opacity-50 text-white px-5 py-2.5 rounded-full font-bold flex items-center gap-2 transition-all active:scale-95 text-sm"
                            >
                              {isSending ? <Loader2 className="w-4 h-4 animate-spin" /> : "SAVE"}
                            </button>
                         );
                       }
                       return (
                         <button 
                           onClick={() => handleSendEmail(false)}
                           disabled={isSending || toAddresses.length === 0}
                           className="bg-[#ad57ff] hover:bg-[#9745e6] disabled:opacity-50 text-white px-5 py-2.5 rounded-[1.25rem] font-bold flex items-center gap-2 transition-all active:scale-95 text-[13px] tracking-wide"
                         >
                           {isSending ? <Loader2 className="w-4 h-4 animate-spin" /> : <>SEND <Send className="w-3.5 h-3.5 ml-1" /></>}
                         </button>
                       );
                     })()}
                  </div>
                </div>
              </div>
            </div>
        </div>
      )}

      {/* Contact Selector Modal */}
      {isContactSelectorModalOpen && (
        <div className="fixed inset-0 z-[120] flex items-center justify-center p-4 bg-black/60 backdrop-blur-sm">
          <div className="bg-white dark:bg-slate-900 w-full max-w-sm rounded-3xl shadow-2xl border border-slate-200 dark:border-slate-800 overflow-hidden animate-in fade-in zoom-in duration-200 flex flex-col max-h-[80vh]">
            <div className="p-6 border-b border-slate-100 dark:border-slate-800 flex items-center justify-between bg-slate-50/50 dark:bg-slate-900/50">
              <div className="flex items-center gap-3">
                <Users className="w-5 h-5 text-purple-500" />
                <h2 className="text-xl font-bold text-slate-900 dark:text-white">Contacts</h2>
              </div>
              <button 
                onClick={() => setIsContactSelectorModalOpen(false)} 
                className="p-2 hover:bg-slate-200 dark:hover:bg-slate-800 rounded-full transition-colors"
              >
                <X className="w-5 h-5 text-slate-500" />
              </button>
            </div>
            <div className="p-2 overflow-y-auto flex-1">
              {(contacts || []).length === 0 ? (
                <div className="py-12 text-center text-slate-500 dark:text-slate-400">
                  <div className="w-16 h-16 bg-slate-100 dark:bg-slate-800 rounded-2xl flex items-center justify-center mx-auto mb-4 text-slate-400">
                    <Users className="w-8 h-8" />
                  </div>
                  No contacts found.
                </div>
              ) : (
                contacts.map((contact, idx) => {
                  const email = getContactEmail(contact);
                  if (!email) return null;
                  const isSelected = toAddresses.includes(email);
                  return (
                    <button
                      key={idx}
                      onClick={() => {
                        if (isSelected) {
                          setToAddresses(toAddresses.filter(e => e !== email));
                        } else {
                          setToAddresses([...toAddresses, email]);
                        }
                      }}
                      className={cn(
                        "w-full px-4 py-3 flex items-center gap-4 hover:bg-slate-50 dark:hover:bg-slate-800 transition-colors text-left rounded-2xl",
                        isSelected && "bg-purple-50 dark:bg-purple-500/10"
                      )}
                    >
                      <div className={cn(
                        "w-10 h-10 rounded-full flex items-center justify-center text-sm text-white font-bold shrink-0",
                        getAccountColor(email || getContactName(contact))
                      )}>
                        {getContactName(contact).charAt(0).toUpperCase()}
                      </div>
                      <div className="flex-1 min-w-0">
                        <div className="text-[15px] font-bold text-slate-900 dark:text-white truncate">{getContactName(contact)}</div>
                        <div className="text-[13px] text-slate-500 dark:text-slate-400 truncate">{email}</div>
                      </div>
                      <div className={cn(
                        "w-5 h-5 rounded-full border-2 flex items-center justify-center shrink-0 transition-colors",
                        isSelected ? "bg-purple-600 border-purple-600" : "border-slate-300 dark:border-slate-600"
                      )}>
                        {isSelected && <Check className="w-3 h-3 text-white" />}
                      </div>
                    </button>
                  );
                })
              )}
            </div>
            <div className="p-4 border-t border-slate-100 dark:border-slate-800 bg-slate-50/50 dark:bg-slate-900/50">
              <button
                onClick={() => setIsContactSelectorModalOpen(false)}
                className="w-full bg-purple-600 hover:bg-purple-700 text-white font-bold py-3 rounded-2xl transition-all"
              >
                Done
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Template Selector Modal */}
      {isTemplateSelectorOpen && (
        <div className="fixed inset-0 z-[120] flex items-center justify-center p-4 bg-black/60 backdrop-blur-sm">
          <div className="bg-white dark:bg-slate-900 w-full max-w-lg rounded-3xl shadow-2xl border border-slate-200 dark:border-slate-800 overflow-hidden animate-in fade-in zoom-in duration-200">
            <div className="p-6 border-b border-slate-100 dark:border-slate-800 flex items-center justify-between bg-slate-50/50 dark:bg-slate-900/50">
              <div className="flex items-center gap-3">
                <File className="w-5 h-5 text-indigo-500" />
                <h2 className="text-xl font-bold text-slate-900 dark:text-white">Choose Template</h2>
              </div>
              <button 
                onClick={() => setIsTemplateSelectorOpen(false)} 
                className="p-2 hover:bg-slate-200 dark:hover:bg-slate-800 rounded-full transition-colors"
              >
                <X className="w-5 h-5 text-slate-500" />
              </button>
            </div>
            <div className="p-6 max-h-[60vh] overflow-y-auto space-y-3">
              {isLoadingTemplates ? (
                <div className="py-12 flex flex-col items-center justify-center gap-3">
                  <Loader2 className="w-8 h-8 text-indigo-500 animate-spin" />
                  <p className="text-sm font-medium text-slate-500">Fetching templates...</p>
                </div>
              ) : serverTemplates.length === 0 ? (
                <div className="py-12 text-center">
                  <div className="w-16 h-16 bg-slate-100 dark:bg-slate-800 rounded-2xl flex items-center justify-center mx-auto mb-4 text-slate-400">
                    <File className="w-8 h-8" />
                  </div>
                  <h3 className="text-lg font-bold text-slate-900 dark:text-white mb-2">No templates found</h3>
                  <p className="text-sm text-slate-500 dark:text-slate-400 max-w-xs mx-auto">
                    Create emails in your "Templates" folder to see them here.
                  </p>
                </div>
              ) : (
                serverTemplates.map((tpl) => (
                  <button
                    key={tpl.id}
                    onClick={() => {
                      setSubject(tpl.subject);
                      setEmailBody(tpl.body);
                      setIsTemplateSelectorOpen(false);
                      toast.success('Template applied');
                    }}
                    className="w-full p-4 rounded-2xl bg-slate-50 dark:bg-slate-800/50 border border-slate-200 dark:border-slate-800 hover:border-indigo-500/50 hover:bg-white dark:hover:bg-slate-800 transition-all text-left group"
                  >
                    <div className="font-bold text-slate-900 dark:text-white mb-1 group-hover:text-indigo-600 dark:group-hover:text-indigo-400 transition-colors">
                      {tpl.subject || "(No Subject)"}
                    </div>
                    <div className="text-xs text-slate-500 dark:text-slate-400 line-clamp-2 leading-relaxed">
                      {tpl.preview || tpl.body}
                    </div>
                  </button>
                ))
              )}
            </div>
            <div className="p-4 bg-slate-50 dark:bg-slate-900/50 border-t border-slate-100 dark:border-slate-800 flex justify-end">
              <button 
                onClick={() => setIsTemplateSelectorOpen(false)}
                className="px-6 py-2 rounded-xl text-sm font-bold bg-slate-200 dark:bg-slate-800 text-slate-700 dark:text-slate-300 hover:bg-slate-300 dark:hover:bg-slate-700 transition-all"
              >
                Close
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
                    className="flex-shrink-0 w-[110px] sm:w-[120px] px-3 py-3 bg-slate-50 dark:bg-slate-800 border-transparent focus:bg-white dark:focus:bg-slate-700 focus:ring-2 focus:ring-indigo-500/20 rounded-xl text-sm outline-none transition-all dark:text-white cursor-pointer"
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
                      className="flex-shrink-0 w-[110px] sm:w-[120px] px-3 py-3 bg-slate-50 dark:bg-slate-800 border-transparent focus:bg-white dark:focus:bg-slate-700 focus:ring-2 focus:ring-indigo-500/20 rounded-xl text-sm outline-none transition-all dark:text-white cursor-pointer"
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
              
              <div className="space-y-1">
                <label className="text-xs font-bold text-slate-400 uppercase tracking-wider">Notes</label>
                <textarea 
                  value={newContact.notes}
                  onChange={e => setNewContact({...newContact, notes: e.target.value})}
                  placeholder="Add any additional notes here..."
                  className="w-full px-4 py-3 bg-slate-50 dark:bg-slate-800 border-transparent focus:bg-white dark:focus:bg-slate-700 focus:ring-2 focus:ring-indigo-500/20 rounded-xl text-sm outline-none transition-all dark:text-white resize-none min-h-[80px]"
                />
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
              {(expirationOptions || []).map((option) => (
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

      {/* Day Details Modal */}
      {selectedCalendarDate && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/40 backdrop-blur-sm">
          <div className="bg-white dark:bg-slate-900 w-full max-w-md rounded-3xl shadow-2xl border border-slate-200 dark:border-slate-800 overflow-hidden animate-in fade-in zoom-in duration-200">
            <div className="p-6 border-b border-slate-100 dark:border-slate-800 flex items-center justify-between">
              <div>
                <h2 className="text-xl font-bold text-slate-900 dark:text-white">{format(selectedCalendarDate, 'EEEE, MMMM do')}</h2>
                <p className="text-sm text-slate-500 dark:text-slate-400">Events for this day</p>
              </div>
              <button onClick={() => setSelectedCalendarDate(null)} className="p-2 hover:bg-slate-100 dark:hover:bg-slate-800 rounded-full">
                <X className="w-5 h-5 text-slate-500" />
              </button>
            </div>
            <div className="p-6 max-h-[60vh] overflow-y-auto space-y-4">
              {events.filter(e => {
                const d = new Date(e.start);
                return d.getDate() === selectedCalendarDate.getDate() && 
                       d.getMonth() === selectedCalendarDate.getMonth() && 
                       d.getFullYear() === selectedCalendarDate.getFullYear();
              }).length > 0 ? (
                events.filter(e => {
                  const d = new Date(e.start);
                  return d.getDate() === selectedCalendarDate.getDate() && 
                         d.getMonth() === selectedCalendarDate.getMonth() && 
                         d.getFullYear() === selectedCalendarDate.getFullYear();
                }).map((event, idx) => (
                  <div 
                    key={idx} 
                    onClick={() => {
                      setSelectedEvent(event);
                      setSelectedCalendarDate(null);
                    }}
                    className="p-4 bg-slate-50 dark:bg-slate-800/50 rounded-2xl border border-slate-100 dark:border-slate-700 hover:border-indigo-500/50 hover:bg-slate-100 dark:hover:bg-slate-800 transition-all cursor-pointer group"
                  >
                    <h3 className="font-bold text-slate-900 dark:text-white group-hover:text-indigo-600 dark:group-hover:text-indigo-400 truncate pr-8">{event.title}</h3>
                    <div className="flex items-center justify-between mt-1">
                      <div className="flex items-center gap-2 text-slate-500 dark:text-slate-400 text-xs">
                        <Clock className="w-3 h-3" />
                        {format(new Date(event.start), 'h:mm a')}
                      </div>
                      <button 
                        onClick={(e) => {
                          e.stopPropagation();
                          handleDeleteEvent(event.id);
                        }}
                        className="p-1 text-slate-400 hover:text-red-500 dark:hover:text-red-400 hover:bg-red-50 dark:hover:bg-red-500/10 rounded-lg transition-all opacity-0 group-hover:opacity-100"
                      >
                        <Trash2 className="w-4 h-4" />
                      </button>
                    </div>
                  </div>
                ))
              ) : (
                <div className="text-center py-8">
                  <Calendar className="w-12 h-12 text-slate-200 dark:text-slate-800 mx-auto mb-3" />
                  <p className="text-slate-500 dark:text-slate-400">No events scheduled</p>
                </div>
              )}
              <button 
                onClick={() => {
                  setNewEvent({
                    ...newEvent, 
                    startDate: format(selectedCalendarDate, 'yyyy-MM-dd'),
                    endDate: format(selectedCalendarDate, 'yyyy-MM-dd')
                  });
                  setIsEventModalOpen(true);
                  setSelectedCalendarDate(null);
                }}
                className="w-full py-3 bg-indigo-600 text-white rounded-xl font-bold flex items-center justify-center gap-2 hover:bg-indigo-700 transition-all"
              >
                <Plus className="w-4 h-4" /> Add Event
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Event Details Modal */}
      {selectedEvent && (
        <div className="fixed inset-0 z-[60] flex items-center justify-center p-4 bg-black/60 backdrop-blur-sm">
          <div className="bg-white dark:bg-slate-900 w-full max-w-md rounded-3xl shadow-2xl border border-slate-200 dark:border-slate-800 overflow-hidden animate-in fade-in zoom-in duration-200">
            <div className="p-6 border-b border-slate-100 dark:border-slate-800 flex items-center justify-between">
              <h2 className="text-xl font-bold text-slate-900 dark:text-white italic">Event Details</h2>
              <button onClick={() => setSelectedEvent(null)} className="p-2 hover:bg-slate-100 dark:hover:bg-slate-800 rounded-full">
                <X className="w-5 h-5 text-slate-500" />
              </button>
            </div>
            <div className="p-8 space-y-8">
              <div>
                <h1 className="text-3xl font-black text-slate-900 dark:text-white tracking-tight leading-tight">{selectedEvent.title}</h1>
                <div className="flex items-center gap-3 mt-4 text-indigo-600 dark:text-indigo-400 font-bold">
                  <Calendar className="w-5 h-5" />
                  {format(new Date(selectedEvent.start), 'MMMM do, yyyy')}
                </div>
              </div>

              <div className="space-y-6">
                <div className="flex gap-4">
                  <div className="w-12 h-12 bg-slate-100 dark:bg-slate-800 rounded-2xl flex items-center justify-center shrink-0">
                    <Clock className="w-6 h-6 text-slate-400" />
                  </div>
                  <div>
                    <div className="text-xs font-black uppercase text-slate-400 tracking-widest mb-1">Time</div>
                    <div className="text-slate-900 dark:text-white font-bold text-lg">
                      {format(new Date(selectedEvent.start), 'h:mm a')}
                    </div>
                  </div>
                </div>

                {selectedEvent.location && (
                  <div className="flex gap-4">
                    <div className="w-12 h-12 bg-slate-100 dark:bg-slate-800 rounded-2xl flex items-center justify-center shrink-0">
                      <Search className="w-6 h-6 text-slate-400" />
                    </div>
                    <div>
                      <div className="text-xs font-black uppercase text-slate-400 tracking-widest mb-1">Location</div>
                      <div className="text-slate-900 dark:text-white font-bold text-lg">{selectedEvent.location}</div>
                    </div>
                  </div>
                )}

                {selectedEvent.description && (
                  <div className="bg-slate-50 dark:bg-slate-800/50 p-6 rounded-3xl border border-slate-100 dark:border-slate-700">
                    <div className="text-xs font-black uppercase text-slate-400 tracking-widest mb-3">Notes</div>
                    <div className="text-slate-700 dark:text-slate-300 whitespace-pre-wrap leading-relaxed">{selectedEvent.description}</div>
                  </div>
                )}
              </div>

              <div className="flex gap-4 pt-4">
                <button 
                  onClick={() => handleDeleteEvent(selectedEvent.id)}
                  className="flex-1 px-4 py-4 bg-red-50 dark:bg-red-500/10 text-red-600 dark:text-red-400 font-bold rounded-2xl border border-red-100 dark:border-red-900/30 hover:bg-red-100 transition-all flex items-center justify-center gap-2"
                >
                  <Trash2 className="w-5 h-5" /> Delete
                </button>
                <button 
                  onClick={() => setSelectedEvent(null)}
                  className="flex-1 px-4 py-4 bg-slate-900 dark:bg-white text-white dark:text-slate-900 font-bold rounded-2xl hover:opacity-90 transition-all"
                >
                  Close
                </button>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Contact Picker Modal */}
      {isContactPickerOpen && (
        <div className="fixed inset-0 z-[100] flex items-center justify-center p-4 bg-black/40 backdrop-blur-sm">
          <div className="bg-white dark:bg-slate-900 w-full max-w-md rounded-3xl shadow-2xl border border-slate-200 dark:border-slate-800 overflow-hidden animate-in fade-in zoom-in duration-200 flex flex-col max-h-[80vh]">
            <div className="p-6 border-b border-slate-100 dark:border-slate-800 flex items-center justify-between shrink-0">
              <h3 className="text-xl font-bold text-slate-900 dark:text-white">Choose Contacts</h3>
              <button onClick={() => setIsContactPickerOpen(false)} className="p-2 hover:bg-slate-100 dark:hover:bg-slate-800 rounded-full">
                <X className="w-5 h-5 text-slate-500" />
              </button>
            </div>
            <div className="p-4 border-b border-slate-100 dark:border-slate-800 shrink-0">
              <div className="relative">
                <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-slate-400" />
                <input 
                  type="text"
                  placeholder="Search contacts..."
                  value={contactPickerSearch}
                  onChange={(e) => setContactPickerSearch(e.target.value)}
                  className="w-full pl-10 pr-4 py-2 bg-slate-50 dark:bg-slate-800 border-none rounded-xl text-sm outline-none ring-2 ring-transparent focus:ring-indigo-500/20"
                />
              </div>
            </div>
            <div className="flex-1 overflow-y-auto p-4 space-y-2">
              {(() => {
                const filtered = contacts.filter(contact => {
                  const name = getContactName(contact).toLowerCase();
                  const emailArr = contact.emails ? (typeof contact.emails === 'object' ? Object.values(contact.emails) : []) : [];
                  const emailsStr = emailArr.map((e: any) => (e.address || '').toLowerCase()).join(' ');
                  const query = contactPickerSearch.toLowerCase();
                  return name.includes(query) || emailsStr.includes(query);
                });

                if (filtered.length > 0) {
                  return filtered.map((contact, idx) => {
                    const email = getContactEmail(contact);
                    if (!email) return null;
                    return (
                      <button
                        key={idx}
                        onClick={() => {
                          if (toAddresses.includes(email)) {
                            setToAddresses(toAddresses.filter(a => a !== email));
                          } else {
                            setToAddresses([...toAddresses, email]);
                          }
                        }}
                        className={cn(
                          "w-full p-3 flex items-center gap-3 rounded-2xl border transition-all text-left group",
                          toAddresses.includes(email) 
                            ? "bg-indigo-50 border-indigo-200 dark:bg-indigo-500/10 dark:border-indigo-500/30" 
                            : "bg-white border-transparent hover:border-slate-200 dark:bg-transparent dark:hover:bg-white/5"
                        )}
                      >
                        <div className="w-10 h-10 rounded-full bg-slate-100 dark:bg-slate-800 flex items-center justify-center font-bold text-slate-500 shrink-0 group-hover:bg-indigo-100 dark:group-hover:bg-indigo-500/20 group-hover:text-indigo-600 dark:group-hover:text-indigo-400 transition-colors">
                          {getContactName(contact).charAt(0).toUpperCase()}
                        </div>
                        <div className="flex-1 min-w-0">
                          <div className="text-sm font-bold text-slate-900 dark:text-white truncate">{getContactName(contact)}</div>
                          <div className="text-xs text-slate-500 dark:text-slate-400 truncate">{email}</div>
                        </div>
                        {toAddresses.includes(email) && <Check className="w-5 h-5 text-indigo-600 dark:text-indigo-400" />}
                      </button>
                    );
                  });
                }
                return (
                  <div className="text-center py-12 text-slate-400">
                    <Search className="w-12 h-12 mx-auto mb-3 opacity-20" />
                    <p>No contacts found matching your search</p>
                  </div>
                );
              })()}
            </div>
            <div className="p-6 border-t border-slate-100 dark:border-slate-800 bg-slate-50/50 dark:bg-slate-900/50 shrink-0">
              <button 
                onClick={() => setIsContactPickerOpen(false)}
                className="w-full py-4 bg-indigo-600 text-white font-bold rounded-2xl shadow-xl shadow-indigo-500/20 hover:bg-indigo-700 transition-all"
              >
                Done
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Contact View/Edit Modal */}
      {selectedContact && (
        <div className="fixed inset-0 z-[110] flex items-center justify-center p-4 bg-black/60 backdrop-blur-sm">
          <div className="bg-white dark:bg-slate-900 w-full max-w-md rounded-3xl shadow-2xl border border-slate-200 dark:border-slate-800 overflow-hidden animate-in fade-in zoom-in duration-200">
            <div className="p-6 border-b border-slate-100 dark:border-slate-800 flex items-center justify-between">
              <h2 className="text-xl font-bold text-slate-900 dark:text-white">
                {isEditingContact ? "Edit Contact" : "Contact Details"}
              </h2>
              <button onClick={() => setSelectedContact(null)} className="p-2 hover:bg-slate-100 dark:hover:bg-slate-800 rounded-full">
                <X className="w-5 h-5 text-slate-500" />
              </button>
            </div>

            <div className="p-8 space-y-6">
              <div className="flex flex-col items-center gap-4 text-center">
                <div className="w-24 h-24 rounded-3xl bg-gradient-to-br from-indigo-500 to-purple-600 text-white flex items-center justify-center font-black text-4xl shadow-xl shadow-indigo-500/20">
                  {getContactName(selectedContact).charAt(0).toUpperCase()}
                </div>
                {!isEditingContact && (
                  <div>
                    <h1 className="text-2xl font-black text-slate-900 dark:text-white tracking-tight leading-tight">
                      {getContactName(selectedContact)}
                    </h1>
                  </div>
                )}
              </div>

              <div className="space-y-4">
                {isEditingContact ? (
                  <>
                    <div>
                      <label className="text-[10px] font-black uppercase text-slate-400 tracking-widest ml-1 mb-1 block">Full Name</label>
                      <input 
                        type="text"
                        value={editingContactData?.fullName}
                        onChange={(e) => setEditingContactData({...editingContactData, fullName: e.target.value})}
                        className="w-full bg-slate-50 dark:bg-slate-800 border-none rounded-2xl px-4 py-3 text-sm focus:ring-2 focus:ring-indigo-500/20 outline-none"
                      />
                    </div>
                    <div>
                      <label className="text-[10px] font-black uppercase text-slate-400 tracking-widest ml-1 mb-1 block">Email</label>
                      <input 
                        type="email"
                        value={editingContactData?.email}
                        onChange={(e) => setEditingContactData({...editingContactData, email: e.target.value})}
                        className="w-full bg-slate-50 dark:bg-slate-800 border-none rounded-2xl px-4 py-3 text-sm focus:ring-2 focus:ring-indigo-500/20 outline-none"
                      />
                    </div>
                    <div>
                      <label className="text-[10px] font-black uppercase text-slate-400 tracking-widest ml-1 mb-1 block">Phone</label>
                      <input 
                        type="text"
                        value={editingContactData?.phone}
                        onChange={(e) => setEditingContactData({...editingContactData, phone: e.target.value})}
                        className="w-full bg-slate-50 dark:bg-slate-800 border-none rounded-2xl px-4 py-3 text-sm focus:ring-2 focus:ring-indigo-500/20 outline-none"
                      />
                    </div>
                    <div>
                      <label className="text-[10px] font-black uppercase text-slate-400 tracking-widest ml-1 mb-1 block">Notes</label>
                      <textarea 
                        value={editingContactData?.notes}
                        onChange={(e) => setEditingContactData({...editingContactData, notes: e.target.value})}
                        rows={3}
                        className="w-full bg-slate-50 dark:bg-slate-800 border-none rounded-2xl px-4 py-3 text-sm focus:ring-2 focus:ring-indigo-500/20 outline-none resize-none"
                      />
                    </div>
                  </>
                ) : (
                  <>
                    <div className="flex gap-4">
                      <div className="w-12 h-12 bg-slate-100 dark:bg-slate-800 rounded-2xl flex items-center justify-center shrink-0">
                        <Mail className="w-6 h-6 text-slate-400" />
                      </div>
                      <div className="min-w-0">
                        <div className="text-[10px] font-black uppercase text-slate-400 tracking-widest mb-1">Email</div>
                        <div className="text-slate-900 dark:text-white font-bold text-lg truncate">{getContactEmail(selectedContact) || "No email"}</div>
                      </div>
                    </div>

                    {(selectedContact.phones && typeof selectedContact.phones === 'object' && Object.keys(selectedContact.phones).length > 0) && (
                      <div className="flex gap-4">
                        <div className="w-12 h-12 bg-slate-100 dark:bg-slate-800 rounded-2xl flex items-center justify-center shrink-0">
                          <Phone className="w-6 h-6 text-slate-400" />
                        </div>
                        <div className="min-w-0">
                          <div className="text-[10px] font-black uppercase text-slate-400 tracking-widest mb-1">Phone</div>
                          <div className="text-slate-900 dark:text-white font-bold text-lg truncate">
                            {(Object.values(selectedContact.phones)[0] as any)?.number || "No phone"}
                          </div>
                        </div>
                      </div>
                    )}

                    {selectedContact.notes && (
                      <div className="bg-slate-50 dark:bg-slate-800/50 p-6 rounded-3xl border border-slate-100 dark:border-slate-700">
                        <div className="text-[10px] font-black uppercase text-slate-400 tracking-widest mb-3">Notes</div>
                        <div className="text-slate-700 dark:text-slate-300 text-sm leading-relaxed">{selectedContact.notes}</div>
                      </div>
                    )}
                  </>
                )}
              </div>

              <div className="flex flex-col sm:flex-row gap-3 pt-4">
                {isEditingContact ? (
                  <>
                    <button 
                      onClick={() => setIsEditingContact(false)}
                      className="flex-1 px-4 py-4 bg-slate-100 dark:bg-slate-800 text-slate-600 dark:text-slate-400 font-bold rounded-2xl border border-slate-200 dark:border-slate-700 hover:bg-slate-200 transition-all"
                    >
                      Cancel
                    </button>
                    <button 
                      onClick={handleUpdateContact}
                      disabled={isLoading}
                      className="flex-1 px-4 py-4 bg-indigo-600 text-white font-bold rounded-2xl shadow-xl shadow-indigo-500/20 hover:bg-indigo-700 transition-all flex items-center justify-center gap-2"
                    >
                      {isLoading ? <Loader2 className="w-5 h-5 animate-spin" /> : <Save className="w-5 h-5" />}
                      Save
                    </button>
                  </>
                ) : (
                  <div className="flex flex-col gap-3 w-full">
                    <button 
                      onClick={() => {
                        setIsComposeOpen(true);
                        setToAddresses([getContactEmail(selectedContact)]);
                        setSelectedContact(null);
                      }}
                      className="w-full px-4 py-4 bg-indigo-600 text-white font-bold rounded-2xl shadow-xl shadow-indigo-500/20 hover:bg-indigo-700 transition-all flex items-center justify-center gap-2"
                    >
                      <Send className="w-5 h-5" /> Message
                    </button>
                    <div className="flex gap-3 w-full">
                      <button 
                        onClick={() => setIsEditingContact(true)}
                        className="flex-1 px-4 py-4 bg-slate-100 dark:bg-slate-800 text-slate-900 dark:text-white font-bold rounded-2xl border border-slate-200 dark:border-slate-700 hover:bg-slate-200 transition-all flex items-center justify-center gap-2"
                      >
                        <Edit2 className="w-5 h-5" /> Edit
                      </button>
                      <button 
                        onClick={async () => {
                          // REMOVED: setSelectedContact(null) from here to prevent the race condition
                          await handleDeleteContact(selectedContact.id);
                        }}
                        className="flex-1 max-w-[80px] px-4 py-4 bg-red-50 dark:bg-red-500/10 text-red-600 dark:text-red-400 font-bold rounded-2xl border border-red-100 dark:border-red-900/30 hover:bg-red-100 transition-all flex items-center justify-center"
                        title="Delete contact"
                      >
                        <Trash2 className="w-5 h-5" />
                      </button>
                    </div>
                  </div>
                )}
              </div>
            </div>
          </div>
        </div>
      )}
      
      {/* Confirm Modal */}
      {confirmDialog.isOpen && (
        <div className="fixed inset-0 z-[9999] flex items-center justify-center">
          <div className="fixed inset-0 bg-slate-900/50 backdrop-blur-sm transition-opacity" onClick={() => setConfirmDialog(prev => ({ ...prev, isOpen: false }))}></div>
          <div className="bg-white dark:bg-[#11131f] border border-slate-200 dark:border-slate-800 rounded-3xl w-full max-w-sm p-6 shadow-2xl relative z-10 animate-in fade-in zoom-in-95 duration-200">
            <div className="flex items-center gap-4 mb-4">
              <div className="w-12 h-12 rounded-full bg-red-50 dark:bg-red-500/10 flex items-center justify-center shrink-0">
                <Trash2 className="w-6 h-6 text-red-600 dark:text-red-400" />
              </div>
              <h2 className="text-xl font-bold text-slate-900 dark:text-white">{confirmDialog.title}</h2>
            </div>
            <p className="text-slate-600 dark:text-slate-400 mb-8">{confirmDialog.message}</p>
            <div className="flex items-center justify-end gap-3">
              <button 
                onClick={() => setConfirmDialog(prev => ({ ...prev, isOpen: false }))}
                className="px-5 py-2.5 text-sm font-semibold rounded-xl text-slate-600 dark:text-slate-400 hover:bg-slate-100 dark:hover:bg-slate-800 transition-colors"
                disabled={isLoading}
              >
                Cancel
              </button>
              <button 
                onClick={async () => {
                  try {
                    await confirmDialog.onConfirm();
                  } finally {
                    setConfirmDialog(prev => ({ ...prev, isOpen: false }));
                  }
                }}
                className="px-5 py-2.5 text-sm font-bold rounded-xl bg-red-600 hover:bg-red-700 text-white shadow-lg shadow-red-500/20 transition-all flex items-center gap-2 disabled:opacity-50"
                disabled={isLoading}
              >
                {isLoading && <RefreshCw className="w-4 h-4 animate-spin" />}
                {confirmDialog.confirmText}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
