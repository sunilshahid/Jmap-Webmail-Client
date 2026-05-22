import React, { useState, useEffect, useCallback, useRef, useMemo } from "react";
import { 
  Inbox, Send, File, AlertCircle, Trash2, Menu, Search, 
  Settings, User, ChevronDown, Star, Archive, MoreVertical,
  Reply, Forward, X, Edit3, Mail, LogOut, Loader2, Server,
  Calendar, Users, RefreshCw, Lock, Clock, Key, Shield, Plus, ExternalLink,
  Sparkles, Download, Upload, Bell, Check, MailCheck, Sun, Filter, ArrowLeft, Paperclip,
  ChevronLeft, ChevronRight, Edit2, Save, Phone, Folder, FileEdit, ShieldAlert, Tag, LayoutTemplate, BarChart3, BellOff, Smile, Camera, Globe, Video, MapPin, Link, Copy, BookOpen
} from "lucide-react";
import { formatDistanceToNow, format } from "date-fns";
import { cn } from "./lib/utils";
import { Toaster, toast } from 'sonner';
import { Mailbox, Email, Identity, Contact, Event, Account } from "./lib/types";
import { JmapClient } from "./lib/jmap-client";
import DOMPurify from 'dompurify';
import { getTranslation } from "./lib/i18n";
import ICAL from 'ical.js';

// Use translation dictionary directly
const t = getTranslation;

export type RuleConditionType = 'subject' | 'from' | 'to' | 'body' | 'header' | 'size' | 'spam_score';
export type RuleMatcher = 'contains' | 'is' | 'regex' | 'starts_with' | 'ends_with' | 'gt' | 'lt';
export type RuleActionType = 'move' | 'forward' | 'reject' | 'mark_read' | 'mark_spam' | 'add_flag';

export interface CustomRuleCondition {
  type: RuleConditionType;
  matcher: RuleMatcher;
  headerName?: string;
  value: string;
}

export interface CustomRuleAction {
  type: RuleActionType;
  value: string;
}

export interface CustomRule {
  id: string;
  name: string;
  active: boolean;
  condition: CustomRuleCondition;
  action: CustomRuleAction;
}

const iconMap: Record<string, React.ElementType> = {
  Inbox, Send, File, AlertCircle, Trash2, Folder, FileEdit, Archive, ShieldAlert, Tag, Users, Bell, LayoutTemplate, Mail, BarChart3
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

  const isImage = (type: string | null | undefined) => type && typeof type === 'string' && type.startsWith('image/');
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
            Return to Stalwart Email
          </button>
        </div>
      </div>
    </div>
  );
}

function HtmlEmailViewer({ htmlContent, attachments, credentials, isDarkMode }: { htmlContent: string, attachments?: any[], credentials?: any, isDarkMode?: boolean }) {
  const iframeRef = useRef<HTMLIFrameElement>(null);

  useEffect(() => {
    if (iframeRef.current) {
      const doc = iframeRef.current.contentDocument || iframeRef.current.contentWindow?.document;
      if (doc) {
        doc.open();
        doc.write(htmlContent);
        doc.close();
        
        const attachTheme = () => {
          let styleEl = doc.getElementById('smart-dark-mode-style');
          if (!styleEl) {
            styleEl = doc.createElement('style');
            styleEl.id = 'smart-dark-mode-style';
            if (doc.head) doc.head.appendChild(styleEl);
          }
          
          if (isDarkMode) {
            // For dark mode, set text white and background transparent
            styleEl.innerHTML = `
              :root {
                color-scheme: dark;
              }
              html {
                background-color: transparent !important;
              }
              body {
                color: #f8fafc !important;
                background-color: transparent !important;
                margin: 0;
                font-family: Inter, system-ui, sans-serif;
                line-height: 1.6;
                word-break: break-word;
              }
              /* Try to prevent white backgrounds on containers in simple emails */
              .markdown-body, .email-content {
                background: transparent !important;
                color: #f8fafc !important;
              }
              div, table, td, th {
                background-color: transparent !important;
                color: inherit !important;
              }
            `;
            // Also override inline bg colors on the body itself just in case
            doc.documentElement.style.backgroundColor = 'transparent';
            doc.body.style.backgroundColor = 'transparent';
            doc.body.style.color = '#f8fafc';
          } else {
            styleEl.innerHTML = `
              :root {
                color-scheme: light;
              }
              html {
                background-color: transparent !important;
              }
              body {
                color: #0f172a !important;
                background-color: transparent !important;
                margin: 0;
                font-family: Inter, system-ui, sans-serif;
                line-height: 1.6;
                word-break: break-word;
              }
            `;
            doc.documentElement.style.backgroundColor = 'transparent';
            doc.body.style.backgroundColor = 'transparent';
            doc.body.style.color = '#0f172a';
          }
        };
        attachTheme();
        
        // Auto-resize
        setTimeout(() => {
          if (iframeRef.current && doc.body) {
             iframeRef.current.style.height = `${doc.body.scrollHeight}px`;
          }
        }, 100);

        // Process inline cid images
        if (credentials && attachments && attachments.length > 0) {
          const resolveInlineImages = async () => {
            const client = new JmapClient(credentials);
            const imgs = doc.querySelectorAll('img');
            for (let i = 0; i < imgs.length; i++) {
              const img = imgs[i];
              const src = img.getAttribute('src');
              if (src && src.startsWith('cid:')) {
                const cid = src.substring(4);
                const attachment = attachments.find((a: any) => a.cid === `<${cid}>` || a.cid === cid);
                if (attachment) {
                  try {
                    const blob = await client.getAttachmentBlob(attachment.blobId, attachment.name, attachment.type);
                    const objectUrl = URL.createObjectURL(blob);
                    img.src = objectUrl;
                    img.onload = () => {
                      if (iframeRef.current && doc.body) {
                        iframeRef.current.style.height = `${doc.body.scrollHeight}px`;
                      }
                    };
                  } catch (e) {
                    console.error("Failed to load inline image", e);
                  }
                }
              }
            }
          };
          resolveInlineImages();
        }
      }
    }
  }, [htmlContent, attachments, credentials, isDarkMode]);

  return (
    <iframe 
      ref={iframeRef} 
      className="w-full border-none bg-transparent transition-all duration-300" 
      style={{ colorScheme: isDarkMode ? 'dark' : 'light' }}
      title="Email Content"
      sandbox="allow-same-origin allow-popups"
    />
  );
}

function AttachmentRenderer({ attachment, credentials, language }: { attachment: any, credentials: any, language: string, key?: any }) {
  const [objectUrl, setObjectUrl] = useState<string | null>(null);
  const [isLoading, setIsLoading] = useState(false);
  const attachmentAction = localStorage.getItem('webmail_read_attachment_action') || 'preview';

  useEffect(() => {
    let currentUrl: string | null = null;
    const fetchBlob = async () => {
      if (!credentials) return;
      const client = new JmapClient(credentials);
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
  }, [attachment, credentials]);

  if (isLoading) {
    return (
      <div className="flex items-center gap-2 px-4 py-2 bg-slate-100 dark:bg-slate-800 rounded-full animate-pulse mt-2">
        <Loader2 className="w-4 h-4 animate-spin text-indigo-500" />
                  <span className="text-xs text-slate-500 font-medium">{t(language, 'loading')}</span>
      </div>
    );
  }

  if (!objectUrl) return null;

  if (attachment.type && typeof attachment.type === 'string' && attachment.type.startsWith('image/')) {
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
      {...(attachmentAction === 'download' ? { download: attachment.name } : { target: "_blank", rel: "noopener noreferrer" })}
      className="inline-flex items-center gap-2 px-4 py-2.5 bg-slate-100 hover:bg-slate-200 dark:bg-slate-800 dark:hover:bg-slate-700 text-slate-800 dark:text-slate-200 rounded-xl text-sm font-semibold transition-all shadow-sm border border-slate-200/50 dark:border-slate-700/50 mt-2 hover:scale-105 active:scale-95"
    >
      <Paperclip className="w-4 h-4 text-indigo-500" /> 
      <span className="max-w-[200px] truncate">{attachment.name}</span>
      <span className="text-[10px] text-slate-400 font-normal">({Math.round(attachment.size / 1024)} KB)</span>
    </a>
  );
}

function getMailboxDisplayName(mb: any, language: string) {
  if (!mb) return getTranslation(language, "inbox");
  const knownRoles = ["inbox", "drafts", "sent", "trash", "archive", "junk", "templates"];
  const knownNames = ["important", "snoozed", "muted", "promotions", "social", "updates", "reports", "scheduled", "outbox"];

  if (mb.role && knownRoles.includes(mb.role.toLowerCase())) {
     if (mb.role.toLowerCase() === 'junk') return getTranslation(language, "spam");
     return getTranslation(language, mb.role.toLowerCase());
  }
  
  if (mb.name) {
     const lowerName = mb.name.toLowerCase();
     if (knownRoles.includes(lowerName)) {
       if (lowerName === 'junk') return getTranslation(language, "spam");
       return getTranslation(language, lowerName);
     }
     if (knownNames.includes(lowerName)) {
       return getTranslation(language, lowerName);
     }
  }
  return mb.name;
}

export const EMAIL_TAGS = [
  { keyword: '$label:red', name: '', color: 'bg-red-500' },
  { keyword: '$label:orange', name: '', color: 'bg-orange-500' },
  { keyword: '$label:yellow', name: '', color: 'bg-yellow-500' },
  { keyword: '$label:green', name: '', color: 'bg-green-500' },
  { keyword: '$label:blue', name: '', color: 'bg-blue-500' },
  { keyword: '$label:purple', name: '', color: 'bg-purple-500' },
  { keyword: '$label:pink', name: '', color: 'bg-pink-500' },
];

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
        setAccounts(prev => {
          const updated = [...prev];
          updated[existingIndex] = newAccount;
          return updated;
        });
        setCurrentAccountIndex(existingIndex);
      } else {
        const nextIndex = accounts.length;
        setAccounts(prev => {
          const updated = [...prev, newAccount];
          return updated;
        });
        setCurrentAccountIndex(nextIndex);
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
            {isAddingAccount ? "Add Another Account" : "Stalwart Email"}
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
  const [isDeveloperMode, setIsDeveloperMode] = useState(() => {
    return localStorage.getItem("webmail_developer_mode") === "true";
  });
  const [isBetaFeaturesEnabled, setIsBetaFeaturesEnabled] = useState(() => {
    return localStorage.getItem("webmail_beta_features") === "true";
  });
  const [mailboxes, setMailboxes] = useState<Mailbox[]>([]);
  const [emails, setEmails] = useState<Email[]>([]);
  const [contacts, setContacts] = useState<any[]>([]);
  const [calendars, setCalendars] = useState<any[]>([]);
  const [events, setEvents] = useState<any[]>([]);
  const [selectedMailbox, setSelectedMailbox] = useState<string>("");
  const [selectedTagId, setSelectedTagId] = useState<string | null>(null);
  const [selectedEmail, setSelectedEmail] = useState<Email | null>(null);
  const [identities, setIdentities] = useState<Identity[]>([]);
  const [selectedIdentityId, setSelectedIdentityId] = useState<string>("");
  const [isAddingIdentity, setIsAddingIdentity] = useState(false);
  const [selectedEmailIds, setSelectedEmailIds] = useState<string[]>([]);
  const [activeApp, setActiveApp] = useState<'mail' | 'contacts' | 'calendar' | 'settings'>('mail');
  const [isSidebarOpen, setIsSidebarOpen] = useState(false);
  const [isTagsExpanded, setIsTagsExpanded] = useState(false);
  const [isComposeOpen, setIsComposeOpen] = useState(false);
  const [editingTemplateId, setEditingTemplateId] = useState<string | null>(null);
  const [language, setLanguage] = useState(() => localStorage.getItem('webmail_language') || "English (US)");
  const [isLanguageDropdownOpen, setIsLanguageDropdownOpen] = useState(false);
  const [timezone, setTimezone] = useState(() => localStorage.getItem('webmail_timezone') || Intl.DateTimeFormat().resolvedOptions().timeZone);
  const [isTimezoneDropdownOpen, setIsTimezoneDropdownOpen] = useState(false);
  const [contextMenuEmail, setContextMenuEmail] = useState<Email | null>(null);
  const [isEmailActionsOpen, setIsEmailActionsOpen] = useState(false);
  const [isTagDropdownOpen, setIsTagDropdownOpen] = useState(false);
  const [isContactModalOpen, setIsContactModalOpen] = useState(false);
  const [isEventModalOpen, setIsEventModalOpen] = useState(false);
  const [isAddCalendarOpen, setIsAddCalendarOpen] = useState(false);
  const [newCalendarName, setNewCalendarName] = useState("");
  const [newCalendarColor, setNewCalendarColor] = useState("#4f46e5");
  const [isAddSubscriptionOpen, setIsAddSubscriptionOpen] = useState(false);
  const [newSubscriptionUrl, setNewSubscriptionUrl] = useState("");
  const [newSubscriptionName, setNewSubscriptionName] = useState("");
  const [newSubscriptionColor, setNewSubscriptionColor] = useState("#22c55e");
  const [isImportModalOpen, setIsImportModalOpen] = useState(false);
  const [importData, setImportData] = useState("");
  const [contactSuggestions, setContactSuggestions] = useState<any[]>([]);
  const [newContact, setNewContact] = useState({ firstName: '', lastName: '', email: '', emailType: 'private', phone: '', phoneType: 'private', organization: '', notes: '', photoUrl: '', birthday: '' });
  const [contactErrors, setContactErrors] = useState<Record<string, string>>({});
  const [newEvent, setNewEvent] = useState({ title: '', description: '', location: '', virtualLocation: '', isAllDay: false, startDate: format(new Date(), 'yyyy-MM-dd'), startTime: '09:00', endDate: format(new Date(), 'yyyy-MM-dd'), endTime: '10:00', timeZone: timezone, recurrence: 'none', invitees: '', calendarId: '', reminder: 'none' });
  const [editingEventId, setEditingEventId] = useState<string | null>(null);
  const [eventModalTab, setEventModalTab] = useState<'details' | 'scheduling'>('details');
  const [eventErrors, setEventErrors] = useState<Record<string, string>>({});
  const [contactSearchQuery, setContactSearchQuery] = useState("");
  const [eventSearchQuery, setEventSearchQuery] = useState("");
  const [isSettingsSection, setIsSettingsSection] = useState<'general' | 'account' | 'security' | 'advanced' | 'notifications' | 'vacation' | 'templates' | 'filters' | 'contacts' | 'tags' | 'calendar' | 'folders' | 'identities' | 'read' | 'compose'>(() => {
    return (localStorage.getItem('webmail_settings_section') as any) || 'account';
  });
  const [isSettingsMenuOpen, setIsSettingsMenuOpen] = useState(false);
  const [vacationEnabled, setVacationEnabled] = useState(false);
  const [vacationSubject, setVacationSubject] = useState("");
  const [vacationText, setVacationText] = useState("");
  const [vacationFromDate, setVacationFromDate] = useState("");
  const [vacationToDate, setVacationToDate] = useState("");
  const [isSavingVacation, setIsSavingVacation] = useState(false);
  const [hasVacationChanges, setHasVacationChanges] = useState(false);
  const [isHeaderExpanded, setIsHeaderExpanded] = useState(false);
  const [isEmojiPickerOpen, setIsEmojiPickerOpen] = useState(false);
  const [isLoading, setIsLoading] = useState(false);
  const [isLoadingMore, setIsLoadingMore] = useState(false);
  const [hasMoreEmails, setHasMoreEmails] = useState(true);
  const [isSyncing, setIsSyncing] = useState(false);

  // Tags State
  const [customTags, setCustomTags] = useState<{keyword: string, name: string, color: string}[]>(() => {
    try {
      const stored = localStorage.getItem('webmail_custom_tags');
      return stored ? JSON.parse(stored) : [];
    } catch {
      return [];
    }
  });
  const [isAddTagModalOpen, setIsAddTagModalOpen] = useState(false);
  const [newTagName, setNewTagName] = useState('');
  const [newTagColor, setNewTagColor] = useState('#3b82f6'); // Default blue

  const allTags = [...EMAIL_TAGS, ...customTags];
  const [selectedCalendarDate, setSelectedCalendarDate] = useState<Date | null>(null);
  const [currentCalendarDate, setCurrentCalendarDate] = useState<Date>(new Date());
  const [calendarView, setCalendarView] = useState<'month' | 'week' | 'day' | 'agenda'>(() => (localStorage.getItem('webmail_cal_default_view') || 'Month').toLowerCase() as 'month' | 'week' | 'day' | 'agenda');
  
  // Calendar Settings States
  const [calShowTimeInMonth, setCalShowTimeInMonth] = useState(() => localStorage.getItem('webmail_cal_show_time') === 'true');
  const [calWeekStartsOn, setCalWeekStartsOn] = useState(() => localStorage.getItem('webmail_cal_week_starts') || 'Monday');
  const [calShowWeekNumbers, setCalShowWeekNumbers] = useState(() => localStorage.getItem('webmail_cal_week_numbers') === 'true');
  const [calEventHoverPreview, setCalEventHoverPreview] = useState(() => localStorage.getItem('webmail_cal_hover') || 'Always');
  const [calContactBirthday, setCalContactBirthday] = useState(() => localStorage.getItem('webmail_cal_birthday') === 'true');
  const [calCompactMonthView, setCalCompactMonthView] = useState(() => localStorage.getItem('webmail_cal_month_compact') === 'true');
  const [calEnableTasks, setCalEnableTasks] = useState(() => localStorage.getItem('webmail_cal_tasks') === 'true');
  const [hiddenCalendars, setHiddenCalendars] = useState<string[]>([]);
  const [calDefaultView, setCalDefaultView] = useState(() => localStorage.getItem('webmail_cal_default_view') || 'Month');
  const [readAutoMark, setReadAutoMark] = useState(() => localStorage.getItem('webmail_read_auto_mark') || 'immediately');
  const [readShowImages, setReadShowImages] = useState(() => localStorage.getItem('webmail_read_show_images') !== 'false');
  const [readNextOnDelete, setReadNextOnDelete] = useState(() => localStorage.getItem('webmail_read_next_on_delete') !== 'false');
  
  const [readDeleteAction, setReadDeleteAction] = useState(() => localStorage.getItem('webmail_read_delete_action') || 'trash');
  const [readArchiveMode, setReadArchiveMode] = useState(() => localStorage.getItem('webmail_read_archive_mode') || 'single');
  const [readAttachmentAction, setReadAttachmentAction] = useState(() => localStorage.getItem('webmail_read_attachment_action') || 'preview');
  const [readEmailsPerPage, setReadEmailsPerPage] = useState(() => parseInt(localStorage.getItem('webmail_read_emails_per_page') || '50', 10));
  
  const [readPermanentDeleteJunk, setReadPermanentDeleteJunk] = useState(() => localStorage.getItem('webmail_read_permanent_delete_junk') === 'true');
  const [readShowPreviewText, setReadShowPreviewText] = useState(() => localStorage.getItem('webmail_read_show_preview_text') !== 'false');
  const [readDisableConvGrouping, setReadDisableConvGrouping] = useState(() => localStorage.getItem('webmail_read_disable_conv_grouping') === 'true');
  const [readPlainTextOnly, setReadPlainTextOnly] = useState(() => localStorage.getItem('webmail_read_plain_text_only') === 'true');
  const [readAttachmentPosition, setReadAttachmentPosition] = useState(() => localStorage.getItem('webmail_read_attachment_position') || 'below_header');
  const [readHideInlineImages, setReadHideInlineImages] = useState(() => localStorage.getItem('webmail_read_hide_inline_images') === 'true');
  const [readQuickHoverActions, setReadQuickHoverActions] = useState<string[]>(() => {
    try {
      return JSON.parse(localStorage.getItem('webmail_read_quick_hover_actions') || '["delete","star","read","archive"]');
    } catch {
      return ["delete","star","read","archive"];
    }
  });
  const [readDisplayMode, setReadDisplayMode] = useState(() => localStorage.getItem('webmail_read_display_mode') || 'inline');
  
  const [composeFormat, setComposeFormat] = useState(() => localStorage.getItem('webmail_compose_format') || 'html');
  const [composeUndoSend, setComposeUndoSend] = useState(() => parseInt(localStorage.getItem('webmail_compose_undo_send') || '5', 10));
  const [composeAutoSave, setComposeAutoSave] = useState(() => parseInt(localStorage.getItem('webmail_compose_auto_save') || '1', 10));
  const [composeAttachmentReminder, setComposeAttachmentReminder] = useState(() => localStorage.getItem('webmail_compose_attachment_reminder') || 'true');
  const [composeAutoSelectIdentity, setComposeAutoSelectIdentity] = useState(() => localStorage.getItem('webmail_compose_auto_select_identity') || 'true');
  
  const [calTimeFormat, setCalTimeFormat] = useState(() => localStorage.getItem('webmail_cal_time_format') || '12-hour');
  const [icalSubscriptions, setICalSubscriptions] = useState<any[]>(() => {
    try {
      return JSON.parse(localStorage.getItem('webmail_ical_subscriptions') || '[]');
    } catch {
      return [];
    }
  });

  const [selectedEvent, setSelectedEvent] = useState<any | null>(null);
  const [selectedContact, setSelectedContact] = useState<any | null>(null);

  const fetchCalendarsAndEvents = useCallback(async () => {
    if (!accounts || accounts.length === 0) return;
    try {
      let allCals: any[] = [];
      let allEvents: any[] = [];
      for (let acc of accounts) {
        try {
          const client = new JmapClient(acc);
          const fetchedCals = await client.getCalendars();
          allCals.push(...fetchedCals.map((c: any) => ({...c, _accountId: acc.username})));
          
          const start = new Date(currentCalendarDate.getFullYear(), currentCalendarDate.getMonth() - 1, 1).toISOString();
          const end = new Date(currentCalendarDate.getFullYear(), currentCalendarDate.getMonth() + 2, 0).toISOString();
          
          const fetchedEvents = await client.getEvents(start, end);
          allEvents.push(...fetchedEvents.map((e: any) => ({...e, _accountId: acc.username})));
        } catch (innerErr) {
          console.error(`Failed to load calendars/events for ${acc.username}:`, innerErr);
        }
      }

      if (calContactBirthday && contacts && contacts.length > 0) {
        const birthdayCalId = "virtual-birthdays";
        allCals.push({
          id: birthdayCalId,
          name: "Birthdays",
          color: "#f43f5e", // Rose
          _accountId: accounts[0]?.username,
          isVirtual: true
        });

        // Find birthdays in current range
        const startYear = currentCalendarDate.getFullYear() - 1;
        const endYear = currentCalendarDate.getFullYear() + 1;
        
        contacts.forEach((c: any) => {
          if (c.anniversaries && typeof c.anniversaries === 'object') {
            Object.values(c.anniversaries).forEach((ann: any) => {
              if (ann.kind === 'birth' && ann.date) {
                // date might be "1990-05-15" or "--05-15"
                const match = ann.date.match(/(?:(\d{4}))?-(\d{2})-(\d{2})/);
                if (match) {
                  const [_, yearStr, monthStr, dayStr] = match;
                  // Add this birthday for each year in range
                  for (let y = startYear; y <= endYear; y++) {
                    const eventDate = new Date(y, parseInt(monthStr)-1, parseInt(dayStr));
                    const currentAge = yearStr ? y - parseInt(yearStr) : null;
                    const contactName = c.name?.components?.join(' ') || c.name?.prefix || "Unknown Contact";
                    allEvents.push({
                      id: `birthday-${c.id}-${y}`,
                      calendarId: birthdayCalId,
                      title: `${contactName}'s Birthday${currentAge ? ` (${currentAge})` : ''}`,
                      start: eventDate.toISOString(),
                      isAllDay: true,
                      _accountId: accounts[0]?.username,
                      isVirtual: true
                    });
                  }
                }
              }
            });
          }
        });
      }

      // Fetch external iCal subscriptions
      for (const sub of icalSubscriptions) {
        if (!allCals.find(c => c.id === sub.calendarId)) {
          allCals.push({
            id: sub.calendarId,
            name: sub.name,
            role: undefined,
            _accountId: "external",
            _color: sub.color || "#22c55e",
            isVirtual: true
          } as any);
        }

        try {
          const proxyUrl = `/api/ical?url=${encodeURIComponent(sub.url)}`;
          const response = await fetch(proxyUrl);
          if (response.ok) {
            const text = await response.text();
            const jcalData = ICAL.parse(text);
            const comp = new ICAL.Component(jcalData);
            const vevents = comp.getAllSubcomponents("vevent");
            
            for (const vevent of vevents) {
              try {
                const event = new ICAL.Event(vevent);
                allEvents.push({
                  id: `ext-${sub.id}-${event.uid}`,
                  title: event.summary,
                  description: event.description,
                  location: event.location,
                  start: event.startDate?.toJSDate().toISOString() || new Date().toISOString(),
                  end: event.endDate?.toJSDate().toISOString(),
                  isAllDay: event.startDate?.isDate,
                  calendarId: sub.calendarId,
                  _accountId: sub.id,
                  isExternal: true
                });
              } catch (evErr) {}
            }
          }
        } catch (e) {
          console.error("Failed fetching external calendar", sub.name, e);
        }
      }

      setCalendars(allCals);
      setEvents(allEvents);
    } catch (e) {
      console.error("Failed to load calendars/events:", e);
    }
  }, [accounts, currentCalendarDate, calContactBirthday, contacts, icalSubscriptions]);

  useEffect(() => {
    if (activeApp === 'calendar') {
      fetchCalendarsAndEvents();
    }
  }, [activeApp, currentCalendarDate, fetchCalendarsAndEvents]);
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
  const [filterReports, setFilterReports] = useState(() => localStorage.getItem('webmail_filter_reports') === 'true');
  const [filterOnlyContacts, setFilterOnlyContacts] = useState(() => localStorage.getItem('webmail_filter_only_contacts') === 'true');
  const [customRules, setCustomRules] = useState<CustomRule[]>(() => {
    const saved = localStorage.getItem('webmail_custom_rules');
    return saved ? JSON.parse(saved) : [];
  });
  const [isRuleModalOpen, setIsRuleModalOpen] = useState(false);
  const [editingRule, setEditingRule] = useState<Partial<CustomRule>>({
    name: '',
    active: true,
    condition: { type: 'subject', matcher: 'contains', value: '' },
    action: { type: 'move', value: 'Trash' }
  });
  
  const [vacationData, setVacationData] = useState<any>(null);

  const compileAndPushSieve = async (promo: boolean, social: boolean, updates: boolean, reports: boolean, onlyContacts: boolean, rules: CustomRule[] = customRules) => {
    if (!credentials) return;

    
    try {
      const client = new JmapClient(credentials);
      
      // 1. Explicitly create necessary virtual/custom folders immediately
      const neededFolders = new Set<string>();
      if (promo) neededFolders.add("Promotions");
      if (social) neededFolders.add("Social");
      if (updates) neededFolders.add("Updates");
      if (reports) neededFolders.add("Reports");
      rules.filter(r => r.active).forEach(rule => {
        if (rule.action.type === 'move' && !['Trash', 'Spam', 'Archive', 'Inbox'].includes(rule.action.value)) {
           neededFolders.add(rule.action.value);
        }
      });
      
      const createData: Record<string, any> = {};
      let needsCreation = false;
      let cId = 0;
      
      for (const folderName of neededFolders) {
        if (!mailboxes.find(m => m.name.toLowerCase() === folderName.toLowerCase())) {
          createData[`newbox${cId++}`] = { name: folderName };
          needsCreation = true;
        }
      }
      
      if (needsCreation) {
        await client.call([
          ["Mailbox/set", { accountId: credentials.accountId, create: createData }, "0"]
        ]);
        // Refresh mailboxes so they show up in the UI right away
        await fetchMailboxes();
      }

      // Get actual mailbox exact string names for Sieve Fallbacks
      const mboxTrash = mailboxes.find(m => m.role === 'trash')?.name || "Trash";
      const mboxJunk = mailboxes.find(m => m.role === 'junk')?.name || "Junk Mail";
      const mboxArchive = mailboxes.find(m => m.role === 'archive')?.name || "Archive";

      let script = 'require ["fileinto", "special-use", "envelope", "body", "reject", "regex", "relational", "comparator-i;ascii-numeric", "copy", "imap4flags"];\n\n';

      if (onlyContacts) {
        try {
          const contacts = await client.getContacts();
          let contactEmails: string[] = [];
          contacts.forEach(c => {
            if (c.emails) {
              Object.values(c.emails).forEach((e: any) => {
                if (e.address) contactEmails.push(e.address);
              });
            }
          });
          if (contactEmails.length > 0) {
            const emailsStr = contactEmails.map(e => `"${e}"`).join(", ");
            script += `if not address :is "from" [${emailsStr}] { fileinto :specialuse "\\\\Junk" "${mboxJunk}"; stop; }\n`;
          }
        } catch (e) {
          console.error("Failed to fetch contacts for sieve compilation", e);
        }
      }
      
      rules.filter(r => r.active).forEach(rule => {
        let condition = '';
        const cType = rule.condition.type;
        const cMatcher = rule.condition.matcher;
        const cVal = rule.condition.value.replace(/"/g, '\\"');
        const cHeader = rule.condition.headerName?.replace(/"/g, '\\"') || cType;

        if (cType === 'size') {
           const sizeVal = parseInt(cVal) || 0;
           if (cMatcher === 'gt') condition = `size :over ${sizeVal}`;
           else condition = `size :under ${sizeVal}`;
        } else if (cType === 'spam_score') {
           condition = `header :value "ge" :comparator "i;ascii-numeric" "X-Spam-Score" "${cVal}"`;
        } else {
           let target = '';
           if (cType === 'body') target = 'body :text';
           else if (cType === 'from') target = 'address "from"';
           else if (cType === 'to') target = 'address "to"';
           else target = `header "${cType === 'header' ? cHeader : cType}"`;

           if (cMatcher === 'contains') condition = `${target} :contains "${cVal}"`;
           else if (cMatcher === 'is') condition = `${target} :is "${cVal}"`;
           else if (cMatcher === 'starts_with') condition = `${target} :matches "${cVal}*"`;
           else if (cMatcher === 'ends_with') condition = `${target} :matches "*${cVal}"`;
           else if (cMatcher === 'regex') condition = `${target} :regex "${cVal}"`;
           else condition = `${target} :contains "${cVal}"`; // fallback
        }
        
        let actionStr = '';
        const aType = rule.action.type;
        const aVal = rule.action.value.replace(/"/g, '\\"');
        
        if (aType === 'move') {
           if (aVal === 'Trash') actionStr = `fileinto :specialuse "\\\\Trash" "${mboxTrash}";`;
           else if (aVal === 'Spam') actionStr = `fileinto :specialuse "\\\\Junk" "${mboxJunk}";`;
           else if (aVal === 'Archive') actionStr = `fileinto :specialuse "\\\\Archive" "${mboxArchive}";`;
           else if (aVal === 'Inbox') actionStr = `fileinto "INBOX";`;
           else actionStr = `fileinto "${aVal}";`;
        } else if (aType === 'forward') {
           actionStr = `redirect "${aVal}"; keep;`;
        } else if (aType === 'reject') {
           actionStr = `reject "${aVal}";`;
        } else if (aType === 'mark_read') {
           actionStr = `addflag "\\\\Seen"; keep;`;
        } else if (aType === 'mark_spam') {
           actionStr = `fileinto :specialuse "\\\\Junk" "${mboxJunk}";`;
        } else if (aType === 'add_flag') {
           actionStr = `addflag "${aVal}"; keep;`;
        }

        script += `if ${condition} { ${actionStr} stop; }\n`;
      });

      if (promo) script += 'if exists "List-Unsubscribe" { fileinto "Promotions"; stop; }\n';
      if (social) script += 'if address :domain :is "from" ["linkedin.com", "twitter.com", "facebook.com", "instagram.com", "pinterest.com", "tiktok.com"] { fileinto "Social"; stop; }\n';
      if (updates) script += 'if header :contains "subject" ["receipt", "invoice", "order", "tracking", "purchase"] { fileinto "Updates"; stop; }\n';
      if (reports) script += 'if header :contains "subject" ["report", "dmarc", "postmaster", "aggregated", "forensic"] { fileinto "Reports"; stop; }\n';
      
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
            ...(/<[a-z][\s\S]*>/i.test(tpl.body || "") ? { htmlBody: [{ partId: "1", type: "text/html" }] } : { textBody: [{ partId: "1", type: "text/plain" }] })
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
  const [isSubAddressModalOpen, setIsSubAddressModalOpen] = useState(false);
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
  const [isAdvancedSearchOpen, setIsAdvancedSearchOpen] = useState(false);
  const [advancedSearch, setAdvancedSearch] = useState({
    from: "",
    to: "",
    subject: "",
    body: "",
    mailboxId: "all",
    after: "",
    before: "",
    title: "",
    location: "",
    name: "",
    email: "",
    organization: ""
  });
  const [pullDistance, setPullDistance] = useState(0);
  const [isPulling, setIsPulling] = useState(false);
  const [startY, setStartY] = useState(0);

  // THE FIX: Reset compose states on modal close to prevent state bleeding between drafts
  useEffect(() => {
    if (!isComposeOpen) {
      setIsScheduling(false);
      setScheduleTime("");
      setComposeSubAddress("");
    }
  }, [isComposeOpen]);

  // Settings & Vacation State
  const [notificationTone, setNotificationTone] = useState(() => {
    return localStorage.getItem('webmail_notification_tone') || 'relax';
  });
  const [emailNotificationsEnabled, setEmailNotificationsEnabled] = useState(() => {
    return localStorage.getItem('webmail_email_notifications') === 'true' || localStorage.getItem('webmail_notifications') === 'true';
  });
  const [emailSoundEnabled, setEmailSoundEnabled] = useState(() => {
    return localStorage.getItem('webmail_email_sound') === 'true' || localStorage.getItem('webmail_sound_effects') === 'true';
  });
  const [calendarNotificationsEnabled, setCalendarNotificationsEnabled] = useState(() => {
    return localStorage.getItem('webmail_calendar_notifications') === 'true';
  });
  const [notifiedEventIds, setNotifiedEventIds] = useState<Set<string>>(new Set());
  const [calendarSoundEnabled, setCalendarSoundEnabled] = useState(() => {
    return localStorage.getItem('webmail_calendar_sound') === 'true';
  });
  const [parseEmailInvitations, setParseEmailInvitations] = useState(() => {
    return localStorage.getItem('webmail_parse_invitations') !== 'false';
  });

  const previousInboxUnreadRef = useRef<number | null>(null);

  const getNotificationAudio = useCallback(() => {
    const toneUrls: Record<string, string> = {
      'relax': 'https://cdn.pixabay.com/download/audio/2021/08/04/audio_0625c1539c.mp3?filename=message-incoming-132126.mp3',
      'chime': 'https://cdn.pixabay.com/download/audio/2022/03/15/audio_c8b7cb60f1.mp3?filename=chime-sound-7143.mp3',
      'ding': 'https://cdn.pixabay.com/download/audio/2022/03/10/audio_510b64d4b2.mp3?filename=correct-2-46134.mp3'
    };
    return new Audio(toneUrls[notificationTone] || toneUrls['relax']);
  }, [notificationTone]);

  const triggerNewEmailNotification = useCallback((email?: any) => {
    if (emailSoundEnabled) {
      const audio = getNotificationAudio();
      audio.volume = 0.8;
      audio.play().catch(e => console.log("Audio play blocked", e));
    }
    if (emailNotificationsEnabled && "Notification" in window && Notification.permission === "granted") {
      try {
        const title = email ? `New email from ${email.from?.name || email.from?.email || 'Unknown'}` : "New Email";
        const body = email ? `${email.subject}\n${email.preview}` : "You have a new message in your Inbox.";
        new Notification(title, {
          body: body,
          icon: "data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 24 24' fill='none' stroke='%234f46e5' stroke-width='2' stroke-linecap='round' stroke-linejoin='round'%3E%3Crect width='20' height='16' x='2' y='4' rx='2'/%3E%3Cpath d='m22 7-8.97 5.7a1.94 1.94 0 0 1-2.06 0L2 7'/%3E%3C/svg%3E"
        });
      } catch (e) {
        console.error("Failed to show notification:", e);
      }
    }
  }, [emailSoundEnabled, emailNotificationsEnabled, getNotificationAudio]);

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
    localStorage.setItem('webmail_language', language);
  }, [language]);

  useEffect(() => {
    localStorage.setItem('webmail_timezone', timezone);
  }, [timezone]);


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

  const getContactPhoto = (contact: any): string => {
    if (!contact) return "";
    if (contact.avatar) return contact.avatar;
    if (contact.photoUrl) return contact.photoUrl;
    if (contact.photos && typeof contact.photos === 'object') {
      const firstPhoto = Object.values(contact.photos)[0] as any;
      return firstPhoto?.url || firstPhoto?.uri || "";
    }
    return "";
  };

  const filteredEmails = useMemo(() => emails.filter(email => {
    // 1. Advanced Search Filters
    if (advancedSearch.from && !(email.from?.name?.toLowerCase().includes(advancedSearch.from.toLowerCase()) || email.from?.email?.toLowerCase().includes(advancedSearch.from.toLowerCase()))) return false;
    if (advancedSearch.to && !email.to?.some((t: any) => t.name?.toLowerCase().includes(advancedSearch.to.toLowerCase()) || t.email?.toLowerCase().includes(advancedSearch.to.toLowerCase()))) return false;
    if (advancedSearch.subject && !(email.subject || "").toLowerCase().includes(advancedSearch.subject.toLowerCase())) return false;
    if (advancedSearch.body && !(email.body || "").toLowerCase().includes(advancedSearch.body.toLowerCase())) return false;
    if (advancedSearch.mailboxId !== "all" && !email.mailboxIds?.[advancedSearch.mailboxId]) return false;
    if (advancedSearch.after && new Date(email.date) < new Date(advancedSearch.after)) return false;
    if (advancedSearch.before && new Date(email.date) > new Date(advancedSearch.before)) return false;

    // 2. Simple Search Filter
    const query = searchQuery.toLowerCase();
    if (query) {
      const matchesSearch = (
        (email.subject || "").toLowerCase().includes(query) ||
        (email.from?.name || "").toLowerCase().includes(query) ||
        (email.from?.email || "").toLowerCase().includes(query) ||
        (email.body || "").toLowerCase().includes(query)
      );
      if (!matchesSearch) return false;
    }

    // 3. Virtual Folder Segregation
    const draftsId = mailboxes.find(m => m.role === 'drafts')?.id;
    const isScheduled = !!scheduledJobs[email.id];

    if (selectedMailbox === 'virtual-scheduled') {
      return isScheduled; // Show ONLY scheduled items
    }
    if (selectedMailbox === draftsId) {
      return !isScheduled; // HIDE scheduled items from standard drafts
    }
    
    return true;
  }), [emails, advancedSearch, searchQuery, mailboxes, scheduledJobs, selectedMailbox]);

  const filteredContacts = contacts.filter(contact => {
    if (advancedSearch.name && !getContactName(contact).toLowerCase().includes(advancedSearch.name.toLowerCase())) return false;
    if (advancedSearch.email && !getContactEmail(contact).toLowerCase().includes(advancedSearch.email.toLowerCase())) return false;
    if (advancedSearch.organization && !(contact as any).organization?.toLowerCase().includes(advancedSearch.organization.toLowerCase())) return false;

    const query = contactSearchQuery.toLowerCase();
    if (!query) return true;
    return (
      getContactName(contact).toLowerCase().includes(query) ||
      getContactEmail(contact).toLowerCase().includes(query)
    );
  });

  const allActiveEvents = useMemo(() => {
    let output = [...events];
    if (calContactBirthday && contacts && contacts.length > 0) {
       const currentYear = new Date().getFullYear();
       contacts.forEach((c: any) => {
          if (c.anniversaries) {
             Object.values(c.anniversaries).filter((a: any) => a.kind === 'birth').forEach((ann: any) => {
                let month, day, year;
                if (!ann.date) return;
                
                if (typeof ann.date === 'string' && ann.date.startsWith('--')) {
                   const m = ann.date.match(/^--(\d{2})-(\d{2})/);
                   if (m) { month = parseInt(m[1]); day = parseInt(m[2]); }
                } else if (typeof ann.date === 'string') {
                  const d = new Date(ann.date);
                  if (!isNaN(d.getTime())) { 
                    month = d.getMonth() + 1; 
                    day = d.getDate(); 
                    year = d.getFullYear();
                  }
                }
                if (month && day) {
                   for (let y = currentYear - 1; y <= currentYear + 2; y++) {
                      let title = `🎂 ${getContactName(c)}`;
                      if (year) {
                        title += ` (${y - year})`;
                      }
                      output.push({
                         id: `birthday-${c.id}-${y}`,
                         calendarIds: { 'birthday-cal': true },
                         title,
                         start: `${y}-${String(month).padStart(2,'0')}-${String(day).padStart(2,'0')}T00:00:00`,
                         showWithoutTime: true,
                         color: '#eab308' 
                      });
                   }
                }
             });
          }
       });
    }
    return output;
  }, [events, contacts, calContactBirthday]);

  const filteredEvents = allActiveEvents.filter(event => {
    // Filter hidden calendars
    const eventCalId = event.calendarId || (event.calendarIds && Object.keys(event.calendarIds)[0]);
    if (eventCalId && hiddenCalendars.includes(eventCalId)) return false;

    if (advancedSearch.title && !(event.title || "").toLowerCase().includes(advancedSearch.title.toLowerCase())) return false;
    if (advancedSearch.location && !(event.location || "").toLowerCase().includes(advancedSearch.location.toLowerCase())) return false;
    if (advancedSearch.body && !(event.description || "").toLowerCase().includes(advancedSearch.body.toLowerCase())) return false;
    if (advancedSearch.after && new Date(event.start || event.startDate) < new Date(advancedSearch.after)) return false;
    if (advancedSearch.before && new Date(event.start || event.startDate) > new Date(advancedSearch.before)) return false;

    const query = eventSearchQuery.toLowerCase();
    if (!query) return true;
    return (
      (event.title || "").toLowerCase().includes(query) ||
      (event.description || "").toLowerCase().includes(query)
    );
  });

  useEffect(() => {
    if (!calendarNotificationsEnabled || allActiveEvents.length === 0) return;

    if (Notification.permission !== 'granted') return;

    const checkAlerts = () => {
      const now = Date.now();
      const upcomingThreshold = 10 * 60 * 1000; // 10 minutes

      allActiveEvents.forEach((event: any) => {
        if (!event.start && !event.startDate) return;
        const startMs = new Date(event.start || event.startDate).getTime();
        if (isNaN(startMs)) return;

        // Check if event starts between now and threshold
        const timeDiff = startMs - now;
        
        if (timeDiff > 0 && timeDiff <= upcomingThreshold) {
          const alertId = `${event.id}-${startMs}`;
          if (!notifiedEventIds.has(alertId)) {
            // Found a new upcoming event to alert for
            new Notification(`Upcoming: ${event.title}`, {
              body: `Starting in ${Math.ceil(timeDiff / 60000)} minutes`,
              icon: '/favicon.ico' // fallback icon
            });
            
            setNotifiedEventIds(prev => {
              const next = new Set(prev);
              next.add(alertId);
              return next;
            });
          }
        }
      });
    };

    // Check immediately then every minute
    checkAlerts();
    const timer = setInterval(checkAlerts, 60000);
    return () => clearInterval(timer);
  }, [allActiveEvents, calendarNotificationsEnabled, notifiedEventIds]);

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
      const createdContact = await client.createContact({
        firstName: newContact.firstName.trim(),
        lastName: newContact.lastName.trim(),
        email: newContact.email.trim(),
        emailType: newContact.emailType,
        phone: newContact.phone.trim(),
        phoneType: newContact.phoneType,
        organization: newContact.organization.trim(),
        notes: newContact.notes,
        avatarUrl: newContact.photoUrl,
        birthday: newContact.birthday
      });

      setContacts(prev => [...prev, createdContact]);
      setIsContactModalOpen(false);
      setNewContact({ firstName: '', lastName: '', email: '', emailType: 'private', phone: '', phoneType: 'private', organization: '', notes: '', photoUrl: '', birthday: '' });
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
          const ev = events.find(e => e.id === eventId);
          const accToUse = ev ? accounts.find(a => a.username === ev._accountId) || credentials : credentials;
          const client = new JmapClient(accToUse);
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
      
      let birthday = "";
      if (selectedContact.anniversaries) {
        const bd = Object.values(selectedContact.anniversaries).find((a: any) => a.kind === "birth");
        if (bd) birthday = (bd as any).date;
      }
      
      setEditingContactData({
        fullName: getContactName(selectedContact),
        email: email,
        phone: phone,
        organization: (selectedContact.organizations?.[0]?.name || selectedContact.company) || "",
        notes: selectedContact.notes || "",
        photoUrl: getContactPhoto(selectedContact),
        birthday: birthday
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
      
      if (editingContactData.organization) {
        patches.organizations = {
          "org1": { name: editingContactData.organization.trim() }
        };
      }
      
      if (editingContactData.photoUrl !== undefined) {
        const photoKey = (selectedContact.photos && typeof selectedContact.photos === 'object' && Object.keys(selectedContact.photos)[0]) || "ph1";
        patches.photos = {
          ...selectedContact.photos,
          [photoKey]: {
            ...(selectedContact.photos?.[photoKey] || {}),
             url: editingContactData.photoUrl.trim(),
             kind: "photo"
          }
        };
      }
      
      if (editingContactData.birthday) {
        const birthKey = (selectedContact.anniversaries && typeof selectedContact.anniversaries === 'object' && Object.keys(selectedContact.anniversaries).find((k) => selectedContact.anniversaries[k].kind === "birth")) || "a1";
        patches.anniversaries = {
          ...selectedContact.anniversaries,
          [birthKey]: {
             ...(selectedContact.anniversaries?.[birthKey] || {}),
             date: editingContactData.birthday.trim(),
             kind: "birth"
          }
        };
      }
      
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
      
      const calendarId = newEvent.calendarId || calendars[0]?.id || "b"; 
      const selectedCal = calendars.find(c => c.id === calendarId);
      const accToUse = selectedCal ? accounts.find(a => a.username === selectedCal._accountId) || credentials : credentials;
      const client = new JmapClient(accToUse);

      // FIXED: Generate mandatory UID
      const uid = window.crypto && window.crypto.randomUUID ? window.crypto.randomUUID() : `event-${Date.now()}`;

      // FIXED: Calculate ISO 8601 Duration (e.g. "PT1H")
      let startObj, endObj, diffMins, durationStr, startStr;
      
      if (newEvent.isAllDay) {
        startObj = new Date(newEvent.startDate);
        endObj = new Date(newEvent.endDate);
        // Duration in days
        let diffDays = Math.round((endObj.getTime() - startObj.getTime()) / (1000 * 60 * 60 * 24));
        if (diffDays <= 0) diffDays = 1;
        durationStr = `P${diffDays}D`;
        startStr = `${newEvent.startDate}T00:00:00`;
      } else {
        startObj = new Date(`${newEvent.startDate}T${newEvent.startTime}`);
        endObj = new Date(`${newEvent.endDate}T${newEvent.endTime}`);
        diffMins = Math.floor((endObj.getTime() - startObj.getTime()) / 60000);
        if (diffMins <= 0) diffMins = 60; // Default 1 hr
        const hours = Math.floor(diffMins / 60);
        const mins = diffMins % 60;
        durationStr = `PT${hours > 0 ? hours + 'H' : ''}${mins > 0 ? mins + 'M' : ''}`;
        startStr = `${newEvent.startDate}T${newEvent.startTime}:00`;
      }

      let finalDescription = newEvent.description || "";
      let virtualLocationsObj: any = undefined;
      if (newEvent.virtualLocation) {
        virtualLocationsObj = {
          "vl_1": {
            "@type": "VirtualLocation",
            "name": "Meeting Link",
            "uri": newEvent.virtualLocation
          }
        };
      }

      let participantsObj: any = undefined;
      if (newEvent.invitees) {
        participantsObj = {};
        newEvent.invitees.split(',').forEach((email, idx) => {
          participantsObj[`p_${idx}`] = {
            "@type": "Participant",
            "name": email.trim(),
            "email": email.trim(),
            "roles": { "attendee": true },
            "participationStatus": "needs-action"
          };
        });
      }

      let recurrenceRules = undefined;
      if (newEvent.recurrence && newEvent.recurrence !== 'none' && newEvent.recurrence !== 'custom') {
        recurrenceRules = [{
          "@type": "RecurrenceRule",
          frequency: newEvent.recurrence
        }];
      }

      let alertsObj: any = undefined;
      if (newEvent.reminder && newEvent.reminder !== 'none') {
        alertsObj = {
          "a_1": {
            "@type": "Alert",
            "trigger": {
              "@type": "OffsetTrigger",
              "offset": `-PT${newEvent.reminder}M`
            }
          }
        };
      }

      const isEditing = !!editingEventId;
      const payloadFields: any = {
        calendarIds: { [calendarId]: true },
        title: newEvent.title,
        description: newEvent.description || "",
        start: startStr,
        duration: durationStr,               // FIXED: Mandatory duration
        showWithoutTime: newEvent.isAllDay,
        recurrenceRules: recurrenceRules
      };

      if (!newEvent.isAllDay) {
        payloadFields.timeZone = newEvent.timeZone || "UTC";
      } else {
        payloadFields.timeZone = null;
      }

      if (!isEditing) {
        payloadFields.uid = uid; // uid cannot be updated
      }

      if (newEvent.location) {
        payloadFields.locations = {
          "loc1": { "@type": "Location", name: newEvent.location }
        };
      } else {
        payloadFields.locations = null; // unset if empty
      }

      if (virtualLocationsObj) payloadFields.virtualLocations = virtualLocationsObj;
      if (participantsObj) payloadFields.participants = participantsObj;
      if (alertsObj) payloadFields.alerts = alertsObj;

      if (editingEventId) {
        await client.updateEvent(editingEventId, payloadFields);
        setEvents(prev => prev.map(e => e.id === editingEventId ? { ...e, ...payloadFields, id: editingEventId } : e));
        setSelectedEvent({ ...selectedEvent, ...payloadFields });
        toast.success("Event updated successfully");
      } else {
        const createdEvent = await client.createEvent(payloadFields);
        setEvents(prev => [...prev, createdEvent]);
        toast.success("Event created successfully");
      }

      setIsEventModalOpen(false);
      setEditingEventId(null);
      setNewEvent({ title: '', description: '', location: '', virtualLocation: '', isAllDay: false, startDate: format(new Date(), 'yyyy-MM-dd'), startTime: '09:00', endDate: format(new Date(), 'yyyy-MM-dd'), endTime: '10:00', timeZone: timezone, recurrence: 'none', invitees: '', calendarId: '' });
      setEventErrors({});
    } catch (error: any) {
      console.error(editingEventId ? "Failed to update event:" : "Failed to create event:", error);
      toast.error(editingEventId ? `Failed to update event: ${error.message}` : `Failed to create event: ${error.message}`);
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

  const handleEmailListScroll = (e: React.UIEvent<HTMLDivElement>) => {
    const target = e.target as HTMLDivElement;
    // Load more when user is within 100px of the bottom
    if (target.scrollHeight - target.scrollTop - target.clientHeight < 100) {
      if (hasMoreEmails && !isLoadingMore && filteredEmails.length >= 50) {
        loadMoreEmails();
      }
    }
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
  const [composeSubAddress, setComposeSubAddress] = useState<string>('');
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

    if (composeAttachmentReminder === 'true' && draftAttachments.length === 0) {
      const lowerBody = emailBody.toLowerCase();
      const lowerSub = subject.toLowerCase();
      if ((lowerBody.includes('attach') || lowerSub.includes('attach')) && 
          !window.confirm('You mentioned an attachment but there are no files attached. Send anyway?')) {
        return;
      }
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

        const fromEmail = composeSubAddress && identity.email
          ? `${identity.email.split('@')[0]}+${composeSubAddress}@${identity.email.split('@')[1]}`
          : identity.email;

        // 2. Safely create the draft (Secure emails have NO standard attachments)
        const actualDraftId = await client.createDraft(
          finalToAddresses,           // to
          finalSubject,               // subject
          finalBody,                  // body
          undefined,                  // cc
          undefined,                  // bcc
          identityId,                 // identityId
          fromEmail,             // fromEmail
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
        composeSubAddress,
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

      const fromEmail = emailData.composeSubAddress && identity.email
        ? `${identity.email.split('@')[0]}+${emailData.composeSubAddress}@${identity.email.split('@')[1]}`
        : identity.email;

      await client.sendEmail(
        emailData.toAddresses,
        finalSubject,
        finalBody,
        undefined, // cc
        undefined, // bcc
        identityId, // identityId
        fromEmail, // <-- THE FIX: Pass the actual email address
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

  const handleEmojiReply = async (email: Email, emoji: string) => {
    if (!credentials) return;
    try {
      setIsEmojiPickerOpen(false);
      const client = new JmapClient(credentials);
      const identity = identities[0];
      if (!identity) throw new Error("No identity found");
      
      const toAddresses = [email.from.email];
      const replySubject = `Re: ${email.subject.replace(/^Re:\s*/i, '')}`;
      const replyBody = `<p style="font-size: 24px; margin: 0;">${emoji}</p><br/><br/><div class="gmail_quote">On ${format(new Date(email.date), 'MMM d, yyyy')} at ${format(new Date(email.date), 'h:mm a')}, ${email.from.name || email.from.email} wrote:<br><blockquote style="margin:0 0 0 .8ex;border-left:1px #ccc solid;padding-left:1ex">${email.preview}...</blockquote></div>`;

      await client.sendEmail(
        toAddresses,
        replySubject,
        replyBody,
        undefined,
        undefined,
        identity.id,
        identity.email,
        undefined,
        identity.name,
        []
      );
      
      toast.success(`Replied to ${email.from.name || email.from.email} with ${emoji}`);
    } catch (e: any) {
      toast.error(`Failed to send emoji reply: ${e.message}`);
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
          setVacationText(vacation.htmlBody || vacation.textBody || "");
          if (vacation.fromDate) {
            setVacationFromDate(vacation.fromDate.substring(0, 16));
          }
          if (vacation.toDate) {
            setVacationToDate(vacation.toDate.substring(0, 16));
          }
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
      
      const inboxMailbox = mapped.find(m => m.role === 'inbox');
      if (inboxMailbox) {
         if (previousInboxUnreadRef.current !== null && inboxMailbox.unread > previousInboxUnreadRef.current) {
            client.getLatestEmail(inboxMailbox.id).then(latestEmail => {
              if (latestEmail) triggerNewEmailNotification(latestEmail);
            }).catch(e => console.error("Could not fetch latest email for notification", e));
         }
         previousInboxUnreadRef.current = inboxMailbox.unread;
      }
      
      if (mapped.length > 0) {
        setSelectedMailbox(prev => prev || mapped.find((m: any) => m.icon === 'Inbox')?.id || mapped[0].id);
      }
      return mapped;
    } catch (err) {
      console.error("Failed to fetch mailboxes", err);
      toast.error(err instanceof Error ? err.message : String(err));
      throw err;
    }
  }, [credentials, triggerNewEmailNotification]);

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
        if (Notification.permission === 'granted' && localStorage.getItem('webmail_email_notifications') !== 'false') {
          setEmailNotificationsEnabled(true);
        }
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
    const interval = setInterval(fetchJobs, 3000);
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
              ...(/<[a-z][\s\S]*>/i.test(emailBody || "") ? { htmlBody: [{ partId: "1", type: "text/html" }] } : { textBody: [{ partId: "1", type: "text/plain" }] })
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
  const fetchEmails = useCallback(async (mailboxId: string | null, background = false, tagKeyword: string | null = null) => {
    if (!credentials) return;
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
      // Wait, getEmails supports keyword now. Add it here.
      const mapped = await client.getEmails(targetMailboxId, readEmailsPerPage, 0, tagKeyword || undefined, !readDisableConvGrouping); 
      
      if (currentUsernameRef.current !== callerUsername) {
        return;
      }

      setEmails(mapped);
      setHasMoreEmails(mapped.length === 50);
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

  const loadMoreEmails = async () => {
    if ((!selectedMailbox && !selectedTagId) || !credentials || isLoading || isLoadingMore) return;
    
    let targetMailboxId = selectedMailbox;
    if (selectedMailbox === 'virtual-scheduled') {
      const draftsId = mailboxes.find(m => m.role === 'drafts')?.id;
      if (!draftsId) return;
      targetMailboxId = draftsId;
    }

    setIsLoadingMore(true);
    try {
      const client = new JmapClient(credentials);
      const newEmails = await client.getEmails(targetMailboxId || null, readEmailsPerPage, emails.length, selectedTagId || undefined, !readDisableConvGrouping);
      if (newEmails.length > 0) {
        setEmails(prev => [...prev, ...newEmails]);
        setHasMoreEmails(newEmails.length === readEmailsPerPage);
      } else {
        setHasMoreEmails(false);
      }
    } catch (err) {
      console.error("Failed to fetch more emails", err);
      toast.error("Failed to load more emails");
    } finally {
      setIsLoadingMore(false);
    }
  };

  const isSyncingRef = useRef(false);
  const syncRequestedRef = useRef(false);

  const syncMail = async () => {
    if (isSyncingRef.current) {
      syncRequestedRef.current = true;
      return;
    }
    isSyncingRef.current = true;
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
      isSyncingRef.current = false;
      setIsSyncing(false);
      if (syncRequestedRef.current) {
        syncRequestedRef.current = false;
        setTimeout(() => syncMailRef.current(), 1000);
      }
    }
  };

  const syncMailRef = useRef(syncMail);
  useEffect(() => {
    syncMailRef.current = syncMail;
  }, [syncMail]);

  const lastNotifiedEmailIdRef = useRef<string | null>(null);

  // Real-time WebSocket connection
  useEffect(() => {
    if (!credentials) return;
    
    // We instantiate a long-lived client simply for the WebSocket
    const client = new JmapClient(credentials);
    let debounceTimer: any = null;
    
    const connected = client.connectWebSocket((changes) => {
      // Whenever we get a StateChange from the server, we seamlessly fetch updates
      // This eliminates the need for manual refreshing
      
      if (debounceTimer) clearTimeout(debounceTimer);
      debounceTimer = setTimeout(() => {
        syncMailRef.current();
      }, 1500);
    });

    return () => {
      client.disconnectWebSocket();
    };
  }, [credentials]); // only re-bind when credentials change

  // Initial fetch when mailbox or tag changes
  const prevSelectedMailboxRef = useRef<string | null>(null);
  const prevSelectedTagRef = useRef<string | null>(null);
  useEffect(() => {
    if (selectedMailbox && selectedMailbox !== prevSelectedMailboxRef.current) {
      prevSelectedMailboxRef.current = selectedMailbox;
      prevSelectedTagRef.current = null;
      fetchEmails(selectedMailbox, false, null);
    } else if (selectedTagId && selectedTagId !== prevSelectedTagRef.current) {
      prevSelectedTagRef.current = selectedTagId;
      prevSelectedMailboxRef.current = null;
      fetchEmails(null, false, selectedTagId);
    }
  }, [selectedMailbox, selectedTagId, fetchEmails]);

  // We now rely on the backend proxy for WebSockets instead of short polling
  // to avoid sending a stream of HTTP requests.

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
      
      // THE FIX: Optimistic Mailbox Update
      setMailboxes(prev => prev.map(m => m.id === email.mailboxId ? { ...m, unread: Math.max(0, m.unread - 1) } : m));

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
        
        // C. Trigger a background sync to lock in the true server state
        fetchMailboxes();
      } catch (error) {
        console.error("Failed to mark email as read on server", error);
      }
    }
  };

  const handleUpdateEmailKeywords = async (emailId: string, keywords: Record<string, boolean | null>) => {
    if (!credentials) return;
    
    // Optimistic Mailbox Update for toolbar buttons
    const targetEmail = emails.find(e => e.id === emailId);
    if (targetEmail) {
      const wasRead = targetEmail.read;
      const isRead = keywords["$seen"] === true;
      const isUnread = keywords["$seen"] === null;
      
      if (!wasRead && isRead) {
        setMailboxes(prev => prev.map(m => m.id === targetEmail.mailboxId ? { ...m, unread: Math.max(0, m.unread - 1) } : m));
      } else if (wasRead && isUnread) {
        setMailboxes(prev => prev.map(m => m.id === targetEmail.mailboxId ? { ...m, unread: m.unread + 1 } : m));
      }
    }

    const client = new JmapClient(credentials);
    try {
      await client.updateEmailKeywords(emailId, keywords);
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

  const handleMoveEmail = async (emailId: string, targetMailboxRole: string, emailObject?: Email) => {
    if (!credentials) return;
    let targetMailbox = mailboxes.find(m => m.role === targetMailboxRole) || mailboxes.find(m => m.name.toLowerCase().includes(targetMailboxRole));
    
    if (!targetMailbox) {
      // Try to create or ensure the custom mailbox
      const mbId = await ensureCustomMailbox(targetMailboxRole);
      if (mbId) {
        // Fetch mailboxes again locally or trust mbId
        targetMailbox = mailboxes.find(m => m.id === mbId) || { id: mbId, name: targetMailboxRole, role: '' } as any;
      }
      if (!targetMailbox) {
        toast.error(`Target mailbox ${targetMailboxRole} not found`);
        return;
      }
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
         if (readNextOnDelete === 'true' || readNextOnDelete === true as any) {
            const idx = filteredEmails.findIndex(e => e.id === emailId);
            if (idx !== -1) {
              const nextEmail = filteredEmails[idx + 1] || filteredEmails[idx - 1];
              setSelectedEmail(nextEmail || null);
            } else {
              setSelectedEmail(null);
            }
         } else {
           setSelectedEmail(null);
         }
      }
      toast.success(`Moved to ${targetMailbox.name}`);
      
      const currentFolder = mailboxes.find(m => m.id === selectedMailbox);
      // Remove sieve rule if moving back to Inbox from Muted/Important/Snoozed/etc
      if (targetMailboxRole === 'inbox' && emailObject && currentFolder && ['muted', 'important', 'snoozed', 'spam', 'junk'].includes(currentFolder.name.toLowerCase())) {
        const fromEmail = emailObject.from?.[0]?.email;
        if (fromEmail) {
          const ruleToDelete = customRules.find(r => r.name === `${currentFolder.name}: ${fromEmail}`);
          if (ruleToDelete) {
             const updatedRules = customRules.filter(r => r.id !== ruleToDelete.id);
             setCustomRules(updatedRules);
             localStorage.setItem('webmail_custom_rules', JSON.stringify(updatedRules));
             await compileAndPushSieve(filterPromotions, filterSocial, filterUpdates, filterReports, filterOnlyContacts, updatedRules);
             toast.success(`Removed rule for future emails from ${fromEmail}`);
          }
        }
      }
      
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
    
    if (currentMailbox?.role === 'trash' || readDeleteAction === 'permanent' || (currentMailbox?.role === 'junk' && readPermanentDeleteJunk)) {
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
        if (selectedEmail?.id === emailId) {
           if (readNextOnDelete === 'true' || readNextOnDelete === true as any) {
              const idx = filteredEmails.findIndex(e => e.id === emailId);
              if (idx !== -1) {
                const nextEmail = filteredEmails[idx + 1] || filteredEmails[idx - 1];
                setSelectedEmail(nextEmail || null);
              } else {
                setSelectedEmail(null);
              }
           } else {
             setSelectedEmail(null);
           }
        }
        toast.success("Permanently deleted");
      } catch (err) {
        toast.error("Failed to delete email");
      }
    } else {
      handleMoveEmail(emailId, 'trash');
    }
  };

  const handleArchiveEmail = (email: Email) => {
     let target = 'archive';
     if (readArchiveMode === 'year') {
         target = `Archive ${new Date().getFullYear()}`;
     } else if (readArchiveMode === 'month') {
         target = `Archive ${new Date().getFullYear()}-${String(new Date().getMonth() + 1).padStart(2, '0')}`;
     }
     handleMoveEmail(email.id, target, email);
  };
  const handleToggleStar = (email: Email) => handleUpdateEmailKeywords(email.id, { "$flagged": !email.starred });
  const handleBulkUpdateEmailKeywords = async (emailIds: string[], keywords: Record<string, boolean | null>) => {
    if (!credentials || emailIds.length === 0) return;
    const client = new JmapClient(credentials);
    try {
      const update: Record<string, any> = {};
      const patchKeywords: Record<string, boolean | null> = {};
      for (const [key, value] of Object.entries(keywords)) {
        patchKeywords[`keywords/${key}`] = value;
      }
      
      emailIds.forEach(id => {
        update[id] = patchKeywords;
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
    let targetMailbox = mailboxes.find(m => m.role === targetMailboxRole) || mailboxes.find(m => m.name.toLowerCase().includes(targetMailboxRole.toLowerCase()));
    
    if (!targetMailbox) {
      const mbId = await ensureCustomMailbox(targetMailboxRole);
      if (mbId) {
        targetMailbox = mailboxes.find(m => m.id === mbId) || { id: mbId, name: targetMailboxRole, role: '' } as any;
      }
      if (!targetMailbox) {
        toast.error(`Target mailbox ${targetMailboxRole} not found`);
        return;
      }
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
         if (readNextOnDelete === 'true' || readNextOnDelete === true as any) {
           const idx = filteredEmails.findIndex(e => e.id === selectedEmail.id);
           if (idx !== -1) {
              let nextEmail = null;
              for (let i = idx + 1; i < filteredEmails.length; i++) {
                 if (!emailIds.includes(filteredEmails[i].id)) { nextEmail = filteredEmails[i]; break; }
              }
              if (!nextEmail) {
                 for (let i = idx - 1; i >= 0; i--) {
                    if (!emailIds.includes(filteredEmails[i].id)) { nextEmail = filteredEmails[i]; break; }
                 }
              }
              setSelectedEmail(nextEmail);
           } else {
              setSelectedEmail(null);
           }
         } else {
           setSelectedEmail(null);
         }
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
    if (currentMailbox?.role === 'trash' || readDeleteAction === 'permanent') {
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
           if (readNextOnDelete === 'true' || readNextOnDelete === true as any) {
             const idx = filteredEmails.findIndex(e => e.id === selectedEmail.id);
             if (idx !== -1) {
                // Find next one that is NOT in emailIds
                let nextEmail = null;
                for (let i = idx + 1; i < filteredEmails.length; i++) {
                   if (!emailIds.includes(filteredEmails[i].id)) { nextEmail = filteredEmails[i]; break; }
                }
                if (!nextEmail) {
                   for (let i = idx - 1; i >= 0; i--) {
                      if (!emailIds.includes(filteredEmails[i].id)) { nextEmail = filteredEmails[i]; break; }
                   }
                }
                setSelectedEmail(nextEmail);
             } else {
                setSelectedEmail(null);
             }
           } else {
             setSelectedEmail(null);
           }
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
  const handleMoveToJunk = (email: Email) => handleMoveEmail(email.id, 'junk', email);
  const handleMoveToInbox = (email: Email) => handleMoveEmail(email.id, 'inbox', email);

  const ensureCustomMailbox = async (name: string) => {
    if (!credentials) return null;
    const lowerName = name.toLowerCase();
    
    // First, map known roles
    let roleToCheck = '';
    if (lowerName === 'spam' || lowerName === 'junk') roleToCheck = 'junk';
    else if (lowerName === 'trash' || lowerName === 'bin') roleToCheck = 'trash';
    else if (lowerName === 'archive') roleToCheck = 'archive';
    else if (lowerName === 'inbox') roleToCheck = 'inbox';

    let mb = mailboxes.find(m => 
      m.name.toLowerCase() === lowerName || 
      (roleToCheck && m.role === roleToCheck)
    );
    if (mb) return mb.id;
    
    const client = new JmapClient(credentials);
    try {
      const res = await client.call([
        ["Mailbox/set", { accountId: credentials.accountId, create: { "newFolder": { name } } }, "0"]
      ]);
      const created = res.methodResponses[0][1]?.created?.newFolder;
      if (created) {
        await fetchMailboxes();
        return created.id;
      }
    } catch (e) {
      console.error("Failed to create mailbox", e);
    }
    return null;
  };

  const handleCreateRuleAndMove = async (email: Email, targetFolderName: string) => {
    if (!credentials) return;
    const mbId = await ensureCustomMailbox(targetFolderName);
    if (!mbId) {
      toast.error(`Failed to ensure ${targetFolderName} folder exists`);
      return;
    }
    
    const client = new JmapClient(credentials);
    try {
      await client.call([
        ["Email/set", {
          accountId: credentials.accountId,
          update: { [email.id]: { mailboxIds: { [mbId]: true } } }
        }, "0"]
      ]);
      setEmails(prev => prev.filter(e => e.id !== email.id));
      if (selectedEmail?.id === email.id) setSelectedEmail(null);
      toast.success(`Moved to ${targetFolderName} & created rule`);
      
      const fromEmail = email.from?.[0]?.email;
      if (fromEmail) {
        // Find if rule already exists
        if (!customRules.find(r => r.name === `${targetFolderName}: ${fromEmail}`)) {
          const newRule: CustomRule = {
            id: 'rule_' + Date.now(),
            name: `${targetFolderName}: ${fromEmail}`,
            active: true,
            condition: { type: 'from', matcher: 'is', value: fromEmail },
            action: { type: 'move', value: targetFolderName }
          };
          const updatedRules = [...customRules, newRule];
          setCustomRules(updatedRules);
          localStorage.setItem('webmail_custom_rules', JSON.stringify(updatedRules));
          await compileAndPushSieve(filterPromotions, filterSocial, filterUpdates, filterReports, filterOnlyContacts, updatedRules);
        }
      }
      await fetchMailboxes();
    } catch (e) {
      toast.error(`Failed to move to ${targetFolderName}`);
    }
  };

  const handleDeleteMailbox = async (mailboxId: string, name: string) => {
    if (!credentials) return;
    
    const confirmDelete = window.confirm(`Are you sure you want to permanently delete the folder "${name}"?`);
    if (!confirmDelete) return;

    const client = new JmapClient(credentials);
    try {
      await client.call([
        ["Mailbox/set", { accountId: credentials.accountId, destroy: [mailboxId], onDestroyRemoveEmails: true }, "0"]
      ]);
      await fetchMailboxes();
      if (selectedMailbox === mailboxId) {
        setSelectedMailbox(mailboxes[0]?.id);
      }
      toast.success(`Deleted folder "${name}"`);
    } catch (e: any) {
      toast.error(`Failed to delete folder. It might contain subfolders. Error: ${e.message}`);
    }
  };

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
            <span>Email</span>
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
              {t(language, 'compose')}
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
            {getTranslation(language, "folders")}
          </div>
          <ul className="space-y-1.5 px-3 mb-6">
            {isBetaFeaturesEnabled && (
              <li className="mb-2">
                <button
                  className="w-full text-left px-4 py-2 rounded-xl flex items-center gap-3 transition-all duration-200 bg-amber-100 dark:bg-amber-500/10 text-amber-700 dark:text-amber-400 group"
                  onClick={() => toast.info("Beta Dashboard coming soon!")}
                >
                  <Sparkles className="w-5 h-5 text-amber-500 dark:text-amber-400" />
                  <span className="text-[15px] font-bold tracking-wide">Beta Dashboard</span>
                  <span className="ml-auto text-[10px] font-black tracking-wider uppercase bg-amber-500/20 text-amber-700 dark:text-amber-300 px-2 py-0.5 rounded-full">New</span>
                </button>
              </li>
            )}
            {(mailboxes || []).map((mb) => {
              let Icon = iconMap[mb.icon] || Mail;
              const displayName = getMailboxDisplayName(mb, language);

              // Clean up icons
              if (mb.role === 'junk') {
                Icon = ShieldAlert;
              } else if (mb.role === 'trash') {
                Icon = Trash2;
              } else if (mb.role === 'drafts') {
                Icon = FileEdit;
              } else if (mb.role === 'inbox') {
                Icon = Inbox;
              } else if (mb.role === 'archive' || mb.name.toLowerCase() === 'archive') {
                Icon = Archive;
              } else if (mb.role === 'sent') {
                Icon = Send;
              } else if (mb.role === 'outbox' || mb.name.toLowerCase() === 'outbox') {
                Icon = Send;
              } else if (mb.name.toLowerCase().includes('report')) {
                Icon = BarChart3;
              } else if (mb.name.toLowerCase() === 'muted') {
                Icon = BellOff;
              } else if (mb.name.toLowerCase() === 'important') {
                Icon = Star;
              } else if (mb.name.toLowerCase() === 'snoozed') {
                Icon = Clock;
              }

              const isSelected = selectedMailbox === mb.id;
              const isCustomFolder = !mb.role && !['inbox', 'drafts', 'sent', 'trash', 'junk', 'archive', 'outbox'].includes(mb.name.toLowerCase());

              return (
                <React.Fragment key={mb.id}>
                  <li className="relative group/folder">
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
                      <div className="flex items-center gap-3.5 pr-2 truncate">
                        <div className={cn(
                          "w-9 h-9 rounded-xl flex items-center justify-center transition-colors shrink-0",
                          isSelected && activeApp === 'mail'
                            ? "bg-indigo-600 text-white shadow-md shadow-indigo-500/20" 
                            : "bg-slate-200/80 dark:bg-[#11131f] text-slate-500 dark:text-slate-400 group-hover:bg-slate-300 dark:group-hover:bg-[#161827]"
                        )}>
                          <Icon className="w-5 h-5" />
                        </div>
                        <div className="flex flex-col items-start leading-tight truncate">
                          <span className="text-[17px] font-bold tracking-wide truncate">{displayName}</span>
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
                          <span className="text-[17px] font-bold tracking-wide">{getTranslation(language, "scheduled")}</span>
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

          <div 
            className="px-4 mt-4 mb-2 flex items-center justify-between cursor-pointer group"
            onClick={() => setIsTagsExpanded(!isTagsExpanded)}
          >
            <span className="text-sm font-bold text-slate-700 dark:text-slate-300 uppercase tracking-widest transition-colors">
              Tags
            </span>
            <ChevronDown className={cn("w-4 h-4 text-slate-400 dark:text-slate-500 transition-transform duration-200", !isTagsExpanded && "-rotate-90")} />
          </div>
          {isTagsExpanded && (
            <ul className="space-y-1.5 px-3 mb-4">
              {allTags.map((tag) => (
                <li key={tag.keyword}>
                  <button
                    onClick={() => {
                      setSelectedTagId(tag.keyword);
                      setSelectedMailbox("");
                      setActiveApp('mail');
                      setIsSidebarOpen(false);
                    }}
                    className={cn(
                      "w-full flex items-center gap-3 px-3 py-2.5 rounded-2xl transition-all group",
                      selectedTagId === tag.keyword && activeApp === 'mail'
                        ? "bg-indigo-100 dark:bg-[#1a1c2e] text-indigo-700 dark:text-indigo-300"
                        : "text-slate-600 dark:text-slate-300 hover:bg-slate-200/50 dark:hover:bg-[#11131f]"
                    )}
                  >
                    <div className={`w-5 h-5 rounded-full shrink-0 ${tag.color} opacity-80 group-hover:opacity-100 transition-opacity`} style={{ backgroundColor: tag.color.startsWith('#') ? tag.color : undefined }} />
                    <span className="text-[16px] font-bold tracking-wide truncate capitalize">{tag.name || tag.keyword.replace('$label:', '').replace(/-/g, ' ')}</span>
                  </button>
                </li>
              ))}
            </ul>
          )}

          <div className="px-4 mt-2 mb-2 text-xs font-bold text-slate-400 dark:text-slate-500 uppercase tracking-widest">
            Apps
          </div>
          <ul className="space-y-1.5 px-3">
            {[
              { id: 'mail', name: t(language, 'mail'), icon: Mail },
              { id: 'contacts', name: t(language, 'contacts'), icon: Users },
              { id: 'calendar', name: t(language, 'calendar'), icon: Calendar },
              { id: 'settings', name: t(language, 'settings'), icon: Settings },
            ].map((app) => {
              const Icon = app.icon;
              const isSelected = activeApp === app.id;
              return (
                <li key={app.id}>
                  <button 
                    onClick={() => { 
                      setActiveApp(app.id as any); 
                      if (app.id === 'settings') setIsSettingsSection('account');
                      setIsSidebarOpen(false); 
                    }}
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
                    ? t(language, 'searchInContacts') 
                    : activeApp === 'calendar' 
                      ? t(language, 'searchInCalendar') 
                      : t(language, 'searchInMail')
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
                className="w-full pl-11 pr-20 py-2.5 bg-slate-100 dark:bg-slate-900 border border-transparent dark:border-slate-800 focus:bg-white dark:focus:bg-slate-800 focus:border-transparent focus:ring-4 focus:ring-indigo-500/10 dark:focus:ring-indigo-500/20 rounded-full text-base outline-none transition-all dark:text-white shadow-sm"
              />
              <div className="absolute right-2 top-1/2 -translate-y-1/2 flex items-center pr-1">
                {(activeApp === 'contacts' ? contactSearchQuery : activeApp === 'calendar' ? eventSearchQuery : searchQuery) && (
                  <button 
                    onClick={() => {
                      if (activeApp === 'contacts') setContactSearchQuery("");
                      else if (activeApp === 'calendar') setEventSearchQuery("");
                      else setSearchQuery("");
                    }}
                    className={cn("p-1.5 text-slate-400 hover:text-slate-600 dark:hover:text-slate-200 hover:bg-slate-200 dark:hover:bg-slate-700 rounded-full transition-colors mr-1")}
                  >
                    <X className="w-4 h-4" />
                  </button>
                )}
                <button 
                  onClick={() => setIsAdvancedSearchOpen(!isAdvancedSearchOpen)} 
                  className={cn("p-1.5 text-slate-400 hover:text-slate-600 dark:hover:text-slate-200 hover:bg-slate-200 dark:hover:bg-slate-700 rounded-md transition-colors", isAdvancedSearchOpen && "bg-slate-200 dark:bg-slate-700")}
                  title="Advanced Search"
                >
                  <Filter className="w-4 h-4" />
                </button>
              </div>

              {isAdvancedSearchOpen && (
                <div className="absolute top-full left-0 right-0 mt-2 bg-white dark:bg-[#11131f] border border-slate-200 dark:border-slate-800 rounded-xl shadow-2xl p-4 z-50 animate-in fade-in slide-in-from-top-2">
                  <div className="flex justify-between items-center mb-4">
                    <h3 className="text-sm font-semibold text-slate-900 dark:text-white">Advanced Search</h3>
                    <button onClick={() => {
                       setAdvancedSearch({ from: "", to: "", subject: "", body: "", mailboxId: "all", after: "", before: "", title: "", location: "", name: "", email: "", organization: "" });
                    }} className="text-xs text-slate-500 hover:text-slate-700 dark:hover:text-slate-300 flex items-center gap-1">
                      <RefreshCw className="w-3 h-3" /> Clear
                    </button>
                  </div>

                  {activeApp === 'mail' && (
                    <>
                      <div className="grid grid-cols-2 gap-4 mb-4">
                        <div className="space-y-1.5">
                          <label className="text-xs font-medium text-slate-600 dark:text-slate-400">From</label>
                          <input 
                            type="text" 
                            value={advancedSearch.from}
                            onChange={e => setAdvancedSearch({...advancedSearch, from: e.target.value})}
                            placeholder="Sender email or name"
                            className="w-full px-3 py-2 bg-slate-50 dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-lg text-sm outline-none focus:border-indigo-500 dark:text-white"
                          />
                        </div>
                        <div className="space-y-1.5">
                          <label className="text-xs font-medium text-slate-600 dark:text-slate-400">To</label>
                          <input 
                            type="text" 
                            value={advancedSearch.to}
                            onChange={e => setAdvancedSearch({...advancedSearch, to: e.target.value})}
                            placeholder="Recipient email or name"
                            className="w-full px-3 py-2 bg-slate-50 dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-lg text-sm outline-none focus:border-indigo-500 dark:text-white"
                          />
                        </div>
                      </div>

                      <div className="space-y-3 mb-4">
                        <div className="space-y-1.5">
                          <label className="text-xs font-medium text-slate-600 dark:text-slate-400">Subject</label>
                          <input 
                            type="text" 
                            value={advancedSearch.subject}
                            onChange={e => setAdvancedSearch({...advancedSearch, subject: e.target.value})}
                            placeholder="Subject contains..."
                            className="w-full px-3 py-2 bg-slate-50 dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-lg text-sm outline-none focus:border-indigo-500 dark:text-white"
                          />
                        </div>
                        <div className="space-y-1.5">
                          <label className="text-xs font-medium text-slate-600 dark:text-slate-400">Body</label>
                          <input 
                            type="text" 
                            value={advancedSearch.body}
                            onChange={e => setAdvancedSearch({...advancedSearch, body: e.target.value})}
                            placeholder="Body contains..."
                            className="w-full px-3 py-2 bg-slate-50 dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-lg text-sm outline-none focus:border-indigo-500 dark:text-white"
                          />
                        </div>
                      </div>

                      <div className="space-y-1.5 mb-4">
                        <label className="text-xs font-medium text-slate-600 dark:text-slate-400">Folder</label>
                        <select 
                          value={advancedSearch.mailboxId}
                          onChange={e => setAdvancedSearch({...advancedSearch, mailboxId: e.target.value})}
                          className="w-full px-3 py-2 bg-slate-50 dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-lg text-sm outline-none focus:border-indigo-500 dark:text-white"
                        >
                          <option value="all">All folders</option>
                          {mailboxes.filter(m => m.role !== 'drafts' && m.role !== 'trash').map(m => (
                            <option key={m.id} value={m.id}>{m.name}</option>
                          ))}
                        </select>
                      </div>
                    </>
                  )}

                  {activeApp === 'contacts' && (
                    <>
                      <div className="grid grid-cols-2 gap-4 mb-4">
                        <div className="space-y-1.5">
                          <label className="text-xs font-medium text-slate-600 dark:text-slate-400">Name</label>
                          <input 
                            type="text" 
                            value={advancedSearch.name}
                            onChange={e => setAdvancedSearch({...advancedSearch, name: e.target.value})}
                            placeholder="Contact name..."
                            className="w-full px-3 py-2 bg-slate-50 dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-lg text-sm outline-none focus:border-indigo-500 dark:text-white"
                          />
                        </div>
                        <div className="space-y-1.5">
                          <label className="text-xs font-medium text-slate-600 dark:text-slate-400">Email</label>
                          <input 
                            type="text" 
                            value={advancedSearch.email}
                            onChange={e => setAdvancedSearch({...advancedSearch, email: e.target.value})}
                            placeholder="Email address..."
                            className="w-full px-3 py-2 bg-slate-50 dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-lg text-sm outline-none focus:border-indigo-500 dark:text-white"
                          />
                        </div>
                      </div>
                      <div className="space-y-1.5 mb-4">
                        <label className="text-xs font-medium text-slate-600 dark:text-slate-400">Organization</label>
                        <input 
                          type="text" 
                          value={advancedSearch.organization}
                          onChange={e => setAdvancedSearch({...advancedSearch, organization: e.target.value})}
                          placeholder="Company or organization..."
                          className="w-full px-3 py-2 bg-slate-50 dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-lg text-sm outline-none focus:border-indigo-500 dark:text-white"
                        />
                      </div>
                    </>
                  )}

                  {activeApp === 'calendar' && (
                    <>
                      <div className="grid grid-cols-2 gap-4 mb-4">
                        <div className="space-y-1.5">
                          <label className="text-xs font-medium text-slate-600 dark:text-slate-400">Title</label>
                          <input 
                            type="text" 
                            value={advancedSearch.title}
                            onChange={e => setAdvancedSearch({...advancedSearch, title: e.target.value})}
                            placeholder="Event title..."
                            className="w-full px-3 py-2 bg-slate-50 dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-lg text-sm outline-none focus:border-indigo-500 dark:text-white"
                          />
                        </div>
                        <div className="space-y-1.5">
                          <label className="text-xs font-medium text-slate-600 dark:text-slate-400">Location</label>
                          <input 
                            type="text" 
                            value={advancedSearch.location}
                            onChange={e => setAdvancedSearch({...advancedSearch, location: e.target.value})}
                            placeholder="Location..."
                            className="w-full px-3 py-2 bg-slate-50 dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-lg text-sm outline-none focus:border-indigo-500 dark:text-white"
                          />
                        </div>
                      </div>
                      <div className="space-y-1.5 mb-4">
                        <label className="text-xs font-medium text-slate-600 dark:text-slate-400">Description</label>
                        <input 
                          type="text" 
                          value={advancedSearch.body}
                          onChange={e => setAdvancedSearch({...advancedSearch, body: e.target.value})}
                          placeholder="Event description..."
                          className="w-full px-3 py-2 bg-slate-50 dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-lg text-sm outline-none focus:border-indigo-500 dark:text-white"
                        />
                      </div>
                    </>
                  )}

                  <div className="grid grid-cols-2 gap-4">
                    <div className="space-y-1.5">
                      <label className="text-xs font-medium text-slate-600 dark:text-slate-400">After</label>
                      <input 
                        type="date"
                        value={advancedSearch.after}
                        onChange={e => setAdvancedSearch({...advancedSearch, after: e.target.value})}
                        className="w-full px-3 py-2 bg-slate-50 dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-lg text-sm outline-none focus:border-indigo-500 dark:text-white"
                      />
                    </div>
                    <div className="space-y-1.5">
                      <label className="text-xs font-medium text-slate-600 dark:text-slate-400">Before</label>
                      <input 
                        type="date"
                        value={advancedSearch.before}
                        onChange={e => setAdvancedSearch({...advancedSearch, before: e.target.value})}
                        className="w-full px-3 py-2 bg-slate-50 dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-lg text-sm outline-none focus:border-indigo-500 dark:text-white"
                      />
                    </div>
                  </div>
                </div>
              )}
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
                  "border-slate-200 dark:border-slate-800 flex flex-col bg-white dark:bg-[#050505] shrink-0 overflow-hidden transition-all duration-300",
                  readDisplayMode === 'floating' 
                    ? "w-full border-r-0"
                    : "w-full md:w-[350px] lg:w-[420px] border-r",
                  selectedEmail && readDisplayMode !== 'floating' ? "hidden md:flex" : "flex"
                )}
              >
                <div 
                  className="flex-1 overflow-y-auto relative"
                  onTouchStart={handleTouchStart}
                  onTouchMove={handleTouchMove}
                  onTouchEnd={handleTouchEnd}
                  onScroll={handleEmailListScroll}
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
                            onClick={() => {
                               let target = 'archive';
                               if (readArchiveMode === 'year') {
                                   target = `Archive ${new Date().getFullYear()}`;
                               } else if (readArchiveMode === 'month') {
                                   target = `Archive ${new Date().getFullYear()}-${String(new Date().getMonth() + 1).padStart(2, '0')}`;
                               }
                               handleBulkMoveEmail(selectedEmailIds, target);
                            }}
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
                            {selectedTagId && (
                                <div className={`w-3 h-3 rounded-full flex items-center justify-center shrink-0 ${allTags.find(t => t.keyword === selectedTagId)?.color} text-white font-bold text-[8px]`} style={{ backgroundColor: allTags.find(t => t.keyword === selectedTagId)?.color.startsWith('#') ? allTags.find(t => t.keyword === selectedTagId)?.color : undefined }}>
                                  {allTags.find(t => t.keyword === selectedTagId)?.name}
                                </div>
                            )}
                            {selectedTagId
                              ? allTags.find(t => t.keyword === selectedTagId)?.keyword.replace('$label:', '') || 'Tag'
                              : selectedMailbox === 'virtual-scheduled' 
                                ? getTranslation(language, "scheduled") 
                                : getMailboxDisplayName(mailboxes.find(m => m.id === selectedMailbox), language)}
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
                      <p className="font-medium">{searchQuery ? (t(language, 'noMatchingMessages') === 'noMatchingMessages' ? 'No matching messages' : t(language, 'noMatchingMessages')) : t(language, 'noMessages')}</p>
                      <p className="text-sm mt-1 text-slate-400 dark:text-slate-500">{t(language, 'youReAllCaughtUp') === 'youReAllCaughtUp' ? "You're all caught up!" : t(language, 'youReAllCaughtUp')}</p>
                    </div>
                  ) : (
                    <>
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
                              
                              <div className="pt-1 shrink-0 flex flex-col gap-2">
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
                                <button
                                  onClick={(e) => {
                                    e.stopPropagation();
                                    handleToggleStar(email);
                                  }}
                                  className={cn(
                                    "w-5 h-5 flex items-center justify-center transition-colors",
                                    email.starred ? "text-yellow-400" : "text-slate-300 dark:text-slate-700 hover:text-yellow-400/50"
                                  )}
                                >
                                  <Star className={cn("w-4 h-4", email.starred && "fill-current")} />
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
                                  <div className="flex items-center gap-2 ml-auto relative">
                                    {allTags.filter(tag => email.keywords?.[tag.keyword]).map(tag => (
                                      <div key={tag.keyword} className={`w-3 h-3 rounded-full flex items-center justify-center shrink-0 ${tag.color} text-white font-bold text-[8px] opacity-80`} style={{ backgroundColor: tag.color.startsWith('#') ? tag.color : undefined }} title={tag.keyword}>
                                        {tag.name}
                                      </div>
                                    ))}
                                    <span className="text-xs text-slate-500 dark:text-slate-400 whitespace-nowrap mt-0.5 font-medium group-hover:opacity-0 transition-opacity">
                                      {formatDistanceToNow(new Date(email.date), { addSuffix: true })}
                                    </span>
                                      
                                    <div className="absolute right-0 top-1/2 -translate-y-1/2 opacity-0 group-hover:opacity-100 transition-all flex items-center bg-white dark:bg-[#050505] shadow-sm rounded-lg border border-slate-200 dark:border-slate-800 p-0.5 translate-x-2 group-hover:translate-x-0 z-10 hidden sm:flex">
                                      {readQuickHoverActions.includes('delete') && (
                                        <button onClick={(e) => { e.stopPropagation(); handleDeleteEmail(email.id); }} className="p-1.5 hover:bg-red-50 dark:hover:bg-red-900/20 hover:text-red-600 dark:hover:text-red-400 rounded-md transition-colors text-slate-400" title="Delete">
                                          <Trash2 className="w-3.5 h-3.5" />
                                        </button>
                                      )}
                                      {readQuickHoverActions.includes('star_unstar') && (
                                        <button onClick={(e) => { e.stopPropagation(); handleToggleStar(email); }} className="p-1.5 hover:bg-yellow-50 dark:hover:bg-yellow-900/20 hover:text-yellow-600 dark:hover:text-yellow-400 rounded-md transition-colors text-slate-400" title={email.starred ? "Unstar" : "Star"}>
                                          <Star className={cn("w-3.5 h-3.5", email.starred ? "fill-yellow-400 text-yellow-400" : "")} />
                                        </button>
                                      )}
                                      {readQuickHoverActions.includes('archive') && (
                                        <button onClick={(e) => { e.stopPropagation(); handleArchiveEmail(email); }} className="p-1.5 hover:bg-slate-100 dark:hover:bg-slate-800 hover:text-slate-700 dark:hover:text-slate-300 rounded-md transition-colors text-slate-400" title="Archive">
                                          <Archive className="w-3.5 h-3.5" />
                                        </button>
                                      )}
                                      {readQuickHoverActions.includes('mark_read_unread') && (
                                        <button onClick={(e) => { e.stopPropagation(); email.read ? handleMarkAsUnread(email.id) : handleMarkAsRead(email.id); }} className="p-1.5 hover:bg-slate-100 dark:hover:bg-slate-800 hover:text-slate-700 dark:hover:text-slate-300 rounded-md transition-colors text-slate-400" title={email.read ? "Mark as unread" : "Mark as read"}>
                                          {email.read ? <Mail className="w-3.5 h-3.5" /> : <MailCheck className="w-3.5 h-3.5" />}
                                        </button>
                                      )}
                                      {readQuickHoverActions.includes('tag') && (
                                        <button onClick={(e) => { e.stopPropagation(); setContextMenuEmail(contextMenuEmail?.id === email.id ? null : email); }} className="p-1.5 hover:bg-slate-100 dark:hover:bg-slate-800 hover:text-slate-700 dark:hover:text-slate-300 rounded-md transition-colors text-slate-400" title="Tag">
                                          <Tag className="w-3.5 h-3.5" />
                                        </button>
                                      )}
                                      {readQuickHoverActions.includes('mark_as_spam') && (
                                        <button onClick={(e) => { e.stopPropagation(); handleMoveToJunk(email); }} className="p-1.5 hover:bg-orange-50 dark:hover:bg-orange-900/20 hover:text-orange-600 dark:hover:text-orange-400 rounded-md transition-colors text-slate-400" title="Mark as Spam">
                                          <AlertCircle className="w-3.5 h-3.5" />
                                        </button>
                                      )}
                                    </div>

                                    <div className="relative group/more">
                                      <button 
                                        onClick={(e) => {
                                          e.stopPropagation();
                                          setContextMenuEmail(contextMenuEmail?.id === email.id ? null : email);
                                        }}
                                        className="p-1 hover:bg-slate-200 dark:hover:bg-slate-800 rounded-full transition-colors sm:opacity-0 sm:group-hover:opacity-100 opacity-100"
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
                                              onClick={(e) => { e.stopPropagation(); handleArchiveEmail(email); setContextMenuEmail(null); }}
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
                                            {mailboxes.find(m => m.id === selectedMailbox)?.role !== 'inbox' && (
                                              <button 
                                                onClick={(e) => { e.stopPropagation(); handleMoveToInbox(email); setContextMenuEmail(null); }}
                                                className="w-full px-4 py-2 text-left text-sm hover:bg-slate-50 dark:hover:bg-[#050505] flex items-center gap-2 font-medium"
                                              >
                                                <Inbox className="w-4 h-4" /> Move to Inbox
                                              </button>
                                            )}
                                            {mailboxes.find(m => m.id === selectedMailbox)?.role !== 'junk' && (
                                              <button 
                                                onClick={(e) => { e.stopPropagation(); handleMoveToJunk(email); setContextMenuEmail(null); }}
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
                                {readShowPreviewText && (
                                  <div className="text-xs text-slate-500 dark:text-slate-400 line-clamp-2 leading-relaxed break-words font-normal">
                                    {email.preview}
                                  </div>
                                )}
                              </div>
                            </div>
                          </li>
                        );
                      })}
                    </ul>
                    {hasMoreEmails && filteredEmails.length >= 50 && (
                      <div className="p-6 flex justify-center">
                        {isLoadingMore && <Loader2 className="w-6 h-6 animate-spin text-indigo-500" />}
                      </div>
                    )}
                    </>
                  )}
                </div>
              </div>

              {/* Email Viewer */}
              <div
                className={cn(
                  "flex flex-col min-w-0",
                  !selectedEmail && readDisplayMode !== 'floating' ? "hidden md:flex" : "",
                  !selectedEmail && readDisplayMode === 'floating' ? "hidden" : "",
                  selectedEmail && readDisplayMode !== 'floating' ? "flex" : "",
                  readDisplayMode === 'floating' && selectedEmail
                    ? "fixed right-4 top-[80px] bottom-4 w-[600px] max-w-[calc(100vw-32px)] z-40 rounded-2xl shadow-2xl shadow-black/20 border border-slate-200 dark:border-slate-800 bg-white dark:bg-[#050505] overflow-hidden"
                    : "flex-1 bg-white dark:bg-[#050505]"
                )}
              >
                {selectedEmail ? (
                  <>
                    {/* Viewer Toolbar */}
                    <div className="h-14 border-b border-slate-200 dark:border-slate-800 flex items-center justify-between px-4 shrink-0 bg-white dark:bg-[#050505]">
                      <div className="flex items-center gap-1">
                        <button 
                          className={cn("p-2 -ml-2 text-slate-500 dark:text-slate-400 hover:bg-slate-100 dark:hover:bg-slate-800 rounded-lg mr-2 transition-colors", readDisplayMode === 'floating' ? "flex" : "md:hidden")}
                          onClick={() => setSelectedEmail(null)}
                        >
                          {readDisplayMode === 'floating' ? <X className="w-5 h-5" /> : <ChevronDown className="w-5 h-5 rotate-90" />}
                        </button>
                        <button 
                          onClick={() => mailboxes.find(m => m.id === selectedMailbox)?.role !== 'inbox' ? handleMoveToInbox(selectedEmail) : handleArchiveEmail(selectedEmail)}
                          className="p-1.5 text-slate-500 dark:text-slate-400 hover:text-slate-700 dark:hover:text-slate-200 hover:bg-slate-100 dark:hover:bg-slate-800 rounded-lg transition-colors" 
                          title={mailboxes.find(m => m.id === selectedMailbox)?.role !== 'inbox' ? "Move to Inbox" : "Archive"}
                        >
                          {mailboxes.find(m => m.id === selectedMailbox)?.role !== 'inbox' ? <Inbox className="w-[18px] h-[18px]" /> : <Archive className="w-[18px] h-[18px]" />}
                        </button>
                        <button 
                          onClick={() => handleCreateRuleAndMove(selectedEmail, 'Spam')}
                          className="p-1.5 text-slate-500 dark:text-slate-400 hover:text-slate-700 dark:hover:text-slate-200 hover:bg-slate-100 dark:hover:bg-slate-800 rounded-lg transition-colors" 
                          title="Report Spam"
                        >
                          <ShieldAlert className="w-[18px] h-[18px]" />
                        </button>
                        <button 
                          onClick={() => handleDeleteEmail(selectedEmail.id)}
                          className="p-1.5 text-slate-500 dark:text-slate-400 hover:text-red-600 dark:hover:text-red-400 hover:bg-red-50 dark:hover:bg-red-900/20 rounded-lg transition-colors" 
                          title="Delete"
                        >
                          <Trash2 className="w-[18px] h-[18px]" />
                        </button>

                        <div className="w-px h-5 bg-slate-200 dark:bg-slate-700 mx-1.5" />

                        <button 
                          onClick={() => selectedEmail.read ? handleMarkAsUnread(selectedEmail.id) : handleMarkAsRead(selectedEmail.id)}
                          className="p-1.5 text-slate-500 dark:text-slate-400 hover:text-slate-700 dark:hover:text-slate-200 hover:bg-slate-100 dark:hover:bg-slate-800 rounded-lg transition-colors" 
                          title={selectedEmail.read ? "Mark as unread" : "Mark as read"}
                        >
                          {selectedEmail.read ? <Mail className="w-[18px] h-[18px]" /> : <MailCheck className="w-[18px] h-[18px]" />}
                        </button>
                        <button 
                          onClick={() => handleCreateRuleAndMove(selectedEmail, 'Snoozed')}
                          className="p-1.5 text-slate-500 dark:text-slate-400 hover:text-slate-700 dark:hover:text-slate-200 hover:bg-yellow-50 dark:hover:bg-yellow-900/20 rounded-lg transition-colors" 
                          title="Snooze"
                        >
                          <Clock className="w-[18px] h-[18px]" />
                        </button>

                        <div className="w-px h-5 bg-slate-200 dark:bg-slate-700 mx-1.5" />

                        <button 
                          onClick={() => handleCreateRuleAndMove(selectedEmail, 'Important')}
                          className="p-1.5 text-slate-500 dark:text-slate-400 hover:text-indigo-600 dark:hover:text-indigo-400 hover:bg-indigo-50 dark:hover:bg-indigo-900/20 rounded-lg transition-colors" 
                          title="Mark as Important"
                        >
                          <Star className="w-[18px] h-[18px]" />
                        </button>
                        <button 
                          onClick={() => handleCreateRuleAndMove(selectedEmail, 'Muted')}
                          className="p-1.5 text-slate-500 dark:text-slate-400 hover:text-slate-700 dark:hover:text-slate-200 hover:bg-slate-100 dark:hover:bg-slate-800 rounded-lg transition-colors" 
                          title="Mute Sender"
                        >
                          <BellOff className="w-[18px] h-[18px]" />
                        </button>

                        <div className="relative inline-block text-left">
                          <button
                            onClick={() => setIsTagDropdownOpen(!isTagDropdownOpen)}
                            className="p-1.5 text-slate-500 dark:text-slate-400 hover:text-slate-700 dark:hover:text-slate-200 hover:bg-slate-100 dark:hover:bg-slate-800 rounded-lg transition-colors relative"
                            title="Tags"
                          >
                            <Tag className="w-[18px] h-[18px]" />
                          </button>
                          
                          {isTagDropdownOpen && (
                            <>
                              <div className="fixed inset-0 z-40" onClick={() => setIsTagDropdownOpen(false)} />
                              <div className="absolute right-0 top-full mt-2 w-48 bg-white dark:bg-[#11131f] border border-slate-200 dark:border-slate-800 rounded-xl shadow-xl z-50 py-2 animate-in fade-in zoom-in-95 duration-150">
                                <div className="px-3 pb-2 text-xs font-bold text-slate-400 dark:text-slate-500 uppercase tracking-widest border-b border-slate-100 dark:border-slate-800 mb-2">
                                  Apply Tags
                                </div>
                                {allTags.map((tag) => {
                                  const isActive = selectedEmail.keywords?.[tag.keyword] === true;
                                  return (
                                    <button
                                      key={tag.keyword}
                                      onClick={() => {
                                        handleUpdateEmailKeywords(selectedEmail.id, { [tag.keyword]: isActive ? null : true });
                                        setIsTagDropdownOpen(false);
                                      }}
                                      className="w-full px-4 py-2 text-left text-sm hover:bg-slate-50 dark:hover:bg-[#050505] flex items-center justify-between"
                                    >
                                      <div className="flex items-center gap-3">
                                        <div className={`w-3 h-3 rounded-full flex items-center justify-center shrink-0 ${tag.color} text-white font-bold text-[8px]`} style={{ backgroundColor: tag.color.startsWith('#') ? tag.color : undefined }}>
                                          {tag.name}
                                        </div>
                                        <span className="font-mono text-slate-700 dark:text-slate-300">{tag.keyword.replace('$label:', '')}</span>
                                      </div>
                                      {isActive && <Check className="w-4 h-4 text-indigo-500" />}
                                    </button>
                                  );
                                })}
                              </div>
                            </>
                          )}
                        </div>
                      </div>
                      <div className="flex items-center gap-1">
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
                                {mailboxes.find(m => m.id === selectedMailbox)?.role !== 'inbox' && (
                                  <button 
                                    onClick={() => { handleMoveToInbox(selectedEmail); setIsEmailActionsOpen(false); }}
                                    className="w-full px-4 py-2 text-left text-sm hover:bg-slate-50 dark:hover:bg-[#050505] flex items-center gap-2"
                                  >
                                    <Inbox className="w-4 h-4" /> Move to Inbox
                                  </button>
                                )}
                                {mailboxes.find(m => m.id === selectedMailbox)?.role !== 'junk' && (
                                  <button 
                                    onClick={() => { handleMoveToJunk(selectedEmail); setIsEmailActionsOpen(false); }}
                                    className="w-full px-4 py-2 text-left text-sm hover:bg-slate-50 dark:hover:bg-[#050505] flex items-center gap-2"
                                  >
                                    <AlertCircle className="w-4 h-4" /> Move to Junk
                                  </button>
                                )}
                                <button 
                                  onClick={() => { handleArchiveEmail(selectedEmail); setIsEmailActionsOpen(false); }}
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
                              {allTags.filter(tag => selectedEmail.keywords?.[tag.keyword]).map(tag => (
                                <span key={tag.keyword} className={`px-2 py-0.5 ${tag.color} text-white text-[10px] font-bold rounded uppercase tracking-wider flex items-center gap-1 opacity-90`} style={{ backgroundColor: tag.color.startsWith('#') ? tag.color : undefined }} title={tag.keyword}>
                                  {tag.name && <span className="mr-0.5">{tag.name}</span>}
                                  {tag.keyword.replace('$label:', '')}
                                </span>
                              ))}
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

                        {readAttachmentPosition === 'below_header' && (() => {
                          const displayAttachments = readHideInlineImages && selectedEmail.attachments
                            ? selectedEmail.attachments.filter((a: any) => !a.cid && !a.contentId && !a.isInline)
                            : selectedEmail.attachments;
                          
                          if (!displayAttachments || displayAttachments.length === 0) return null;
                          return (
                            <div className="mb-8 bg-slate-50 dark:bg-slate-900/50 p-4 rounded-xl border border-slate-200 dark:border-slate-800">
                              <h3 className="text-xs font-bold text-slate-400 uppercase tracking-widest mb-4">
                                Attachments ({displayAttachments.length})
                              </h3>
                              <div className="flex flex-wrap gap-4">
                                {displayAttachments.map((att: any, idx: number) => (
                                  <AttachmentRenderer 
                                    key={idx} 
                                    attachment={att} 
                                    credentials={credentials} 
                                    language={language}
                                  />
                                ))}
                              </div>
                            </div>
                          );
                        })()}

                        <div className="mt-8 overflow-x-auto max-w-none">
                          <HtmlEmailViewer 
  htmlContent={DOMPurify.sanitize(selectedEmail.body || "<em>No content</em>", { WHOLE_DOCUMENT: true, ADD_TAGS: ['style', 'head', 'html', 'meta', 'title', 'body'], ADD_ATTR: ['target', 'style', 'class'] })} 
  attachments={selectedEmail.attachments}
  credentials={credentials}
  isDarkMode={isDarkMode}
/>
                        </div>

                        {readAttachmentPosition !== 'below_header' && (() => {
                          const displayAttachments = readHideInlineImages && selectedEmail.attachments
                            ? selectedEmail.attachments.filter((a: any) => !a.cid && !a.contentId && !a.isInline)
                            : selectedEmail.attachments;

                          if (!displayAttachments || displayAttachments.length === 0) return null;
                          return (
                            <div className="mt-8">
                              <hr className="my-6 border-slate-200 dark:border-slate-800" />
                              <h3 className="text-xs font-bold text-slate-400 uppercase tracking-widest mb-4">Attachments ({displayAttachments.length})</h3>
                              <div className="flex flex-wrap gap-4">
                                {displayAttachments.map((att: any, idx: number) => (
                                  <AttachmentRenderer 
                                    key={idx} 
                                    attachment={att} 
                                    credentials={credentials} 
                                    language={language}
                                  />
                                ))}
                              </div>
                            </div>
                          );
                        })()}
                      </div>
                    </div>
                    
                    {/* Sticky Footer for Reply/Forward */}
                    <div className="shrink-0 p-3 sm:p-4 bg-white/90 dark:bg-[#050505]/90 backdrop-blur-md border-t border-slate-100 dark:border-slate-800 flex flex-nowrap gap-2 sm:gap-3 justify-center sm:justify-start overflow-visible min-w-0">
                      <button 
                        onClick={() => {
                          const email = emails.find(e => e.id === selectedEmail.id);
                          if (email) {
                            setToAddresses([email.from.email]);
                            setSubject(`Re: ${email.subject}`);
                            setEmailBody(`\n\nOn ${format(new Date(email.date), 'MMM d, yyyy')} at ${format(new Date(email.date), 'h:mm a')}, ${email.from.name || email.from.email} wrote:\n> ${email.preview}...`);
                            if (composeAutoSelectIdentity === 'true') {
                               const toEmails = email.to.map((t: any) => t.email.toLowerCase());
                               const matchedIdentity = identities.find(i => toEmails.includes(i.email.toLowerCase()));
                               if (matchedIdentity) setSelectedIdentityId(matchedIdentity.id);
                            }
                            setIsComposeOpen(true);
                          }
                        }}
                        className="flex-1 sm:flex-none flex items-center justify-center gap-2 px-4 sm:px-8 py-3 rounded-full bg-slate-100 dark:bg-slate-800 text-slate-800 dark:text-slate-200 hover:bg-slate-200 dark:hover:bg-slate-700 transition-all font-semibold text-[13px] sm:text-sm shadow-sm whitespace-nowrap"
                      >
                        <Reply className="w-4 h-4 shrink-0" /> Reply
                      </button>
                      <button 
                        onClick={() => {
                          const email = emails.find(e => e.id === selectedEmail.id);
                          if (email) {
                            setToAddresses([]);
                            setSubject(`Fwd: ${email.subject}`);
                            setEmailBody(`\n\n---------- Forwarded message ---------\nFrom: ${email.from.name || email.from.email} <${email.from.email}>\nDate: ${format(new Date(email.date), 'MMM d, yyyy')} at ${format(new Date(email.date), 'h:mm a')}\nSubject: ${email.subject}\nTo: ${email.to.map(t => t.email).join(', ')}\n\n${email.body}`);
                            if (composeAutoSelectIdentity === 'true') {
                               const toEmails = email.to.map((t: any) => t.email.toLowerCase());
                               const matchedIdentity = identities.find(i => toEmails.includes(i.email.toLowerCase()));
                               if (matchedIdentity) setSelectedIdentityId(matchedIdentity.id);
                            }
                            setIsComposeOpen(true);
                          }
                        }}
                        className="flex-1 sm:flex-none flex items-center justify-center gap-2 px-4 sm:px-8 py-3 rounded-full bg-slate-100 dark:bg-slate-800 text-slate-800 dark:text-slate-200 hover:bg-slate-200 dark:hover:bg-slate-700 transition-all font-semibold text-[13px] sm:text-sm shadow-sm whitespace-nowrap"
                      >
                        <Forward className="w-4 h-4 shrink-0" /> Forward
                      </button>
                      
                      <div className="relative shrink-0">
                        <button 
                          onClick={() => setIsEmojiPickerOpen(!isEmojiPickerOpen)}
                          className="flex items-center justify-center w-[44px] sm:w-[46px] h-[44px] sm:h-[46px] rounded-full bg-indigo-50 dark:bg-indigo-500/10 text-indigo-600 dark:text-indigo-400 hover:bg-indigo-100 dark:hover:bg-indigo-500/20 transition-all shadow-sm"
                          title="Quick Emoji Reply"
                        >
                          <Smile className="w-5 h-5" />
                        </button>
                        {isEmojiPickerOpen && (
                          <>
                            <div className="fixed inset-0 z-40" onClick={() => setIsEmojiPickerOpen(false)} />
                            <div className="absolute bottom-full mb-2 right-0 sm:right-0 bg-white dark:bg-[#11131f] border border-slate-200 dark:border-slate-800 rounded-full shadow-lg p-2 z-[60] flex gap-1 animate-in fade-in slide-in-from-bottom-2 duration-200">
                              {['👍', '❤️', '😂', '🎉', '😢', '🔥'].map(emoji => (
                                <button 
                                  key={emoji}
                                  onClick={() => handleEmojiReply(selectedEmail, emoji)}
                                  className="w-10 h-10 flex items-center justify-center text-xl hover:bg-slate-100 dark:hover:bg-slate-800 rounded-full transition-colors hover:scale-110 active:scale-95"
                                >
                                  {emoji}
                                </button>
                              ))}
                            </div>
                          </>
                        )}
                      </div>
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
                            {getContactPhoto(contact) ? (
                              <img src={getContactPhoto(contact)} alt={getContactName(contact)} className="w-12 h-12 rounded-2xl object-cover shadow-inner shrink-0" />
                            ) : (
                              <div className="w-12 h-12 rounded-2xl bg-gradient-to-br from-indigo-500 to-purple-600 text-white flex items-center justify-center font-bold text-xl shrink-0 shadow-inner">
                                {getContactName(contact).charAt(0).toUpperCase()}
                              </div>
                            )}
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
            <div className="flex-1 flex flex-col md:flex-row bg-slate-50 dark:bg-black overflow-hidden h-full">
              {/* Calendar Sidebar (Desktop) */}
              <div className="w-64 lg:w-72 border-r border-slate-200 dark:border-slate-800 bg-white dark:bg-[#14151a] hidden md:flex flex-col p-5 overflow-y-auto shrink-0">
                <button 
                  onClick={() => setIsEventModalOpen(true)}
                  className="w-full flex items-center justify-center gap-2 bg-[#ad57ff] hover:bg-[#9745e6] text-white font-bold py-3 px-4 rounded-xl shadow-sm transition-all active:scale-95 mb-8"
                >
                  <Plus className="w-5 h-5" /> New Event
                </button>
                
                <div className="mb-8">
                  <div className="flex items-center justify-between mb-4 px-1">
                    <span className="font-bold text-[15px] text-slate-800 dark:text-white">
                      {format(currentCalendarDate, 'MMMM yyyy')}
                    </span>
                    <div className="flex gap-1">
                      <button 
                        className="p-1.5 hover:bg-slate-100 dark:hover:bg-slate-800 rounded-lg text-slate-500 transition-colors" 
                        onClick={() => setCurrentCalendarDate(new Date(currentCalendarDate.getFullYear(), currentCalendarDate.getMonth() - 1, 1))}
                      >
                        <ChevronLeft className="w-4 h-4" />
                      </button>
                      <button 
                        className="p-1.5 hover:bg-slate-100 dark:hover:bg-slate-800 rounded-lg text-slate-500 transition-colors" 
                        onClick={() => setCurrentCalendarDate(new Date(currentCalendarDate.getFullYear(), currentCalendarDate.getMonth() + 1, 1))}
                      >
                        <ChevronRight className="w-4 h-4" />
                      </button>
                    </div>
                  </div>
                  
                  {/* Mini Calendar Grid (Static visual) */}
                  <div className={cn("grid gap-1 text-center mb-2", calShowWeekNumbers ? "grid-cols-8" : "grid-cols-7")}>
                    {calShowWeekNumbers && <div className="text-[10px] font-bold text-slate-300 dark:text-slate-600">W</div>}
                    {['S', 'M', 'T', 'W', 'T', 'F', 'S'].map((day, i) => {
                       const showDay = calWeekStartsOn === 'Monday' ? ['M', 'T', 'W', 'T', 'F', 'S', 'S'][i] : day;
                       return <div key={i} className="text-[10px] font-bold text-slate-400">{showDay}</div>
                    })}
                  </div>
                  <div className={cn("grid gap-1 text-center", calShowWeekNumbers ? "grid-cols-8" : "grid-cols-7")}>
                    {(() => {
                      const startOfMonth = new Date(currentCalendarDate.getFullYear(), currentCalendarDate.getMonth(), 1);
                      let startDay = startOfMonth.getDay();
                      if (calWeekStartsOn === 'Monday') {
                        startDay = startDay === 0 ? 6 : startDay - 1;
                      }
                      const daysInMonth = new Date(currentCalendarDate.getFullYear(), currentCalendarDate.getMonth() + 1, 0).getDate();
                      const now = new Date();
                      
                      const totalCells = Math.ceil((startDay + daysInMonth) / 7) * 7;
                      return Array.from({ length: totalCells }).map((_, i) => {
                        const dayNum = i - startDay + 1;
                        const isCurrentMonth = dayNum > 0 && dayNum <= daysInMonth;
                        const isToday = isCurrentMonth && dayNum === now.getDate() && currentCalendarDate.getMonth() === now.getMonth() && currentCalendarDate.getFullYear() === now.getFullYear();
                        
                        // Week number is at the start of each row (i % 7 === 0)
                        const showWeekNum = calShowWeekNumbers && i % 7 === 0;

                        return (
                          <React.Fragment key={i}>
                            {showWeekNum && (
                              <div className="aspect-square flex items-center justify-center text-[9px] font-bold text-slate-300 dark:text-slate-600">
                                {Math.floor(i / 7) + 1}
                              </div>
                            )}
                            {!isCurrentMonth ? (
                               <div className="aspect-square"></div>
                            ) : (
                              <button 
                                onClick={() => setSelectedCalendarDate(new Date(currentCalendarDate.getFullYear(), currentCalendarDate.getMonth(), dayNum))}
                                className={cn(
                                  "aspect-square flex items-center justify-center text-[11px] rounded-full hover:bg-slate-100 dark:hover:bg-slate-800 transition-colors",
                                  isToday ? "bg-purple-600 text-white font-bold hover:bg-purple-700 dark:hover:bg-purple-500" : "text-slate-700 dark:text-slate-300"
                                )}
                              >
                                {dayNum}
                              </button>
                            )}
                          </React.Fragment>
                        );
                      });
                    })()}
                  </div>
                </div>

                <div className="flex-1 w-full border-t border-slate-100 dark:border-slate-800/60 pt-4 overflow-y-auto custom-scrollbar pr-2 pb-6">
                  <div className="mb-6">
                    <h3 className="text-[11px] font-bold text-slate-400 uppercase tracking-wider mb-2 px-2 flex justify-between items-center group transition-colors hover:text-slate-500">
                      My Calendars
                      <button 
                        onClick={() => setIsAddCalendarOpen(true)}
                        className="hover:text-purple-500 p-1 rounded-md hover:bg-slate-200 dark:hover:bg-slate-700/50 transition-colors opacity-0 group-hover:opacity-100 focus:opacity-100" 
                        title="Add calendar"
                      >
                        <Plus className="w-3.5 h-3.5" />
                      </button>
                    </h3>
                    <div className="space-y-0.5">
                      {(calendars || []).filter((c: any) => !icalSubscriptions.some(sub => sub.calendarId === c.id)).map((calendar, idx) => {
                        const isHidden = hiddenCalendars.includes(calendar.id);
                        return (
                          <div key={idx} onClick={() => setHiddenCalendars(prev => isHidden ? prev.filter(id => id !== calendar.id) : [...prev, calendar.id])} className={cn("flex items-center gap-3 px-2 py-1.5 rounded-lg hover:bg-slate-100 dark:hover:bg-slate-800/50 cursor-pointer group transition-colors", isHidden ? "opacity-50" : "")}>
                            <div className="w-4 h-4 rounded-md flex items-center justify-center shrink-0 transition-transform group-active:scale-90" style={{ backgroundColor: isHidden ? 'transparent' : (calendar.color || '#9333ea'), border: `2px solid ${calendar.color || '#9333ea'}` }}>
                              {!isHidden && <Check className="w-3 h-3 text-white" />}
                            </div>
                            <span className="text-[13px] font-medium text-slate-700 dark:text-slate-300 truncate tracking-wide">{calendar.name || "Calendar"}</span>
                          </div>
                        );
                      })}
                      {calContactBirthday && (
                        <div className="flex items-center gap-3 px-2 py-1.5 rounded-lg hover:bg-slate-100 dark:hover:bg-slate-800/50 cursor-pointer group transition-colors">
                          <div className="w-4 h-4 rounded-full flex items-center justify-center shrink-0 transition-transform group-active:scale-90 bg-yellow-500">
                          </div>
                          <span className="text-[13px] font-medium text-slate-700 dark:text-slate-300 truncate tracking-wide">Birthdays</span>
                        </div>
                      )}
                      {!(calendars || []).filter((c: any) => !icalSubscriptions.some(sub => sub.calendarId === c.id)).length && !calContactBirthday && (
                        <div className="text-xs text-slate-500 px-2 py-2">No calendars found.</div>
                      )}
                    </div>
                  </div>

                  <div className="mb-6">
                    <h3 className="text-[11px] font-bold text-slate-400 uppercase tracking-wider mb-2 px-2 flex justify-between items-center group cursor-pointer transition-colors hover:text-slate-500" title="CalDAV Discovery">
                      Shared (CalDAV)
                      <button className="hover:text-indigo-500 p-1 rounded-md hover:bg-slate-200 dark:hover:bg-slate-700/50 transition-colors opacity-0 group-hover:opacity-100 focus:opacity-100">
                        <Plus className="w-3.5 h-3.5" />
                      </button>
                    </h3>
                    <div className="space-y-0.5">
                      <div className="flex items-center gap-3 px-2 py-1.5 rounded-lg hover:bg-slate-100 dark:hover:bg-slate-800/50 cursor-pointer group transition-colors">
                        <div className="w-4 h-4 rounded border-2 border-emerald-500 flex items-center justify-center shrink-0 transition-transform group-active:scale-90">
                        </div>
                        <span className="text-[13px] font-medium text-slate-700 dark:text-slate-300 truncate tracking-wide opacity-80">Team Events</span>
                      </div>
                    </div>
                  </div>

                  <div>
                    <h3 className="text-[11px] font-bold text-slate-400 uppercase tracking-wider mb-2 px-2 flex justify-between items-center group cursor-pointer transition-colors hover:text-slate-500" title="iCal/Webcal Batch Import">
                      Subscriptions
                    </h3>
                    <div className="space-y-0.5">
                      {icalSubscriptions.map((sub, idx) => {
                        const isHidden = hiddenCalendars.includes(sub.calendarId);
                        return (
                          <div key={idx} onClick={() => setHiddenCalendars(prev => isHidden ? prev.filter(id => id !== sub.calendarId) : [...prev, sub.calendarId])} className={cn("flex items-center gap-3 px-2 py-1.5 rounded-lg hover:bg-slate-100 dark:hover:bg-slate-800/50 cursor-pointer group transition-colors", isHidden ? "opacity-50" : "")}>
                            <div className="w-4 h-4 rounded-md flex items-center justify-center shrink-0 transition-transform group-active:scale-90" style={{ backgroundColor: isHidden ? 'transparent' : (sub.color || '#f97316'), border: `2px solid ${sub.color || '#f97316'}` }}>
                              {!isHidden && <Check className="w-3 h-3 text-white" />}
                            </div>
                            <span className="text-[13px] font-medium text-slate-700 dark:text-slate-300 truncate tracking-wide opacity-80">{sub.name}</span>
                          </div>
                        );
                      })}
                      {icalSubscriptions.length === 0 && (
                        <div className="px-2 py-1 text-xs text-slate-500">No subscriptions</div>
                      )}
                    </div>
                  </div>
                </div>
              </div>

              {/* Main Calendar View */}
              <div className="flex-1 flex flex-col bg-white dark:bg-black overflow-hidden relative">
                <div className="sticky top-0 z-20 px-3 py-3 md:px-6 md:py-4 border-b border-slate-200 dark:border-slate-800 bg-white/95 dark:bg-black/95 backdrop-blur-md flex flex-col gap-3 md:gap-4 shrink-0">
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-1 sm:gap-2">
                      <button 
                        onClick={() => {
                          if (calendarView === 'month') {
                            setCurrentCalendarDate(new Date(currentCalendarDate.getFullYear(), currentCalendarDate.getMonth() - 1, 1));
                          } else if (calendarView === 'week') {
                            setCurrentCalendarDate(new Date(currentCalendarDate.getFullYear(), currentCalendarDate.getMonth(), currentCalendarDate.getDate() - 7));
                          } else if (calendarView === 'day' || calendarView === 'agenda') {
                            setCurrentCalendarDate(new Date(currentCalendarDate.getFullYear(), currentCalendarDate.getMonth(), currentCalendarDate.getDate() - 1));
                          }
                        }}
                        className="p-1.5 md:p-2 text-slate-500 hover:bg-slate-100 dark:hover:bg-slate-800 rounded-full transition-all"
                      >
                        <ChevronLeft className="w-5 h-5 md:w-6 md:h-6" />
                      </button>
                      <h1 className="text-[19px] md:text-2xl font-bold text-slate-900 dark:text-white pointer-events-none">
                        {format(currentCalendarDate, calendarView === 'day' || calendarView === 'agenda' ? 'MMM d, yyyy' : 'MMMM yyyy')}
                      </h1>
                      <button 
                        onClick={() => {
                          if (calendarView === 'month') {
                            setCurrentCalendarDate(new Date(currentCalendarDate.getFullYear(), currentCalendarDate.getMonth() + 1, 1));
                          } else if (calendarView === 'week') {
                            setCurrentCalendarDate(new Date(currentCalendarDate.getFullYear(), currentCalendarDate.getMonth(), currentCalendarDate.getDate() + 7));
                          } else if (calendarView === 'day' || calendarView === 'agenda') {
                            setCurrentCalendarDate(new Date(currentCalendarDate.getFullYear(), currentCalendarDate.getMonth(), currentCalendarDate.getDate() + 1));
                          }
                        }}
                        className="p-1.5 md:p-2 text-slate-500 hover:bg-slate-100 dark:hover:bg-slate-800 rounded-full transition-all"
                      >
                        <ChevronRight className="w-5 h-5 md:w-6 md:h-6" />
                      </button>
                    </div>
                    
                    <div className="flex items-center gap-2">
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
                        className="p-2 md:p-2.5 text-slate-500 hover:bg-slate-100 dark:hover:bg-slate-800 hover:text-indigo-600 rounded-xl transition-all hidden sm:block"
                        title="Refresh calendar"
                      >
                        <RefreshCw className={cn("w-5 h-5", isSyncing && "animate-spin")} />
                      </button>
                      <button 
                        onClick={() => setIsEventModalOpen(true)}
                        className="w-9 h-9 md:w-10 md:h-10 flex items-center justify-center bg-indigo-100 dark:bg-indigo-500/20 text-indigo-700 dark:text-indigo-300 hover:bg-indigo-200 dark:hover:bg-indigo-500/30 rounded-xl md:hidden transition-colors"
                      >
                        <Plus className="w-5 h-5" />
                      </button>
                    </div>
                  </div>
                  
                  <div className="flex items-center gap-3">
                    <div className="flex items-center bg-slate-100 dark:bg-slate-800/80 rounded-xl p-1 flex-1 overflow-x-auto no-scrollbar shadow-inner">
                       <button onClick={() => setCalendarView('month')} className={cn("flex-1 px-3 py-1.5 md:py-2 text-[13px] md:text-sm font-bold rounded-lg transition-colors whitespace-nowrap outline-none", calendarView === 'month' ? "shadow-sm bg-white dark:bg-slate-700 text-slate-900 dark:text-white" : "text-slate-500 hover:text-slate-700 dark:hover:text-slate-300")}>Month</button>
                       <button onClick={() => setCalendarView('week')} className={cn("flex-1 px-3 py-1.5 md:py-2 text-[13px] md:text-sm font-bold rounded-lg transition-colors whitespace-nowrap outline-none", calendarView === 'week' ? "shadow-sm bg-white dark:bg-slate-700 text-slate-900 dark:text-white" : "text-slate-500 hover:text-slate-700 dark:hover:text-slate-300")}>Week</button>
                       <button onClick={() => setCalendarView('day')} className={cn("flex-1 px-3 py-1.5 md:py-2 text-[13px] md:text-sm font-bold rounded-lg transition-colors whitespace-nowrap outline-none", calendarView === 'day' ? "shadow-sm bg-white dark:bg-slate-700 text-slate-900 dark:text-white" : "text-slate-500 hover:text-slate-700 dark:hover:text-slate-300")}>Day</button>
                       <button onClick={() => setCalendarView('agenda')} className={cn("flex-1 px-3 py-1.5 md:py-2 text-[13px] md:text-sm font-bold rounded-lg transition-colors whitespace-nowrap outline-none", calendarView === 'agenda' ? "shadow-sm bg-white dark:bg-slate-700 text-slate-900 dark:text-white" : "text-slate-500 hover:text-slate-700 dark:hover:text-slate-300")}>Agenda</button>
                       {calEnableTasks && (
                         <button onClick={() => setCalendarView('tasks' as any)} className={cn("flex-1 px-3 py-1.5 md:py-2 text-[13px] md:text-sm font-bold rounded-lg transition-colors whitespace-nowrap outline-none", calendarView === 'tasks' as any ? "shadow-sm bg-white dark:bg-slate-700 text-slate-900 dark:text-white" : "text-slate-500 hover:text-slate-700 dark:hover:text-slate-300")}>Tasks</button>
                       )}
                    </div>
                    
                    <button 
                      onClick={() => setCurrentCalendarDate(new Date())}
                      className="px-4 py-1.5 md:py-2 border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-800 text-slate-700 dark:text-slate-300 hover:bg-slate-50 dark:hover:bg-slate-700 rounded-xl text-[13px] md:text-sm font-bold transition-all shadow-sm shrink-0 outline-none"
                    >
                      Today
                    </button>
                  </div>
                </div>
                
                <div className="flex-1 flex flex-col min-h-0 p-2 md:p-6 bg-slate-50/80 dark:bg-[#050505]">
                  <div className="bg-white dark:bg-[#0d0e15] rounded-3xl border border-slate-200/60 dark:border-slate-800/60 shadow-sm flex flex-col flex-1 min-h-0 overflow-hidden">
                    
                    {calendarView === 'month' && (
                      <div className="flex flex-col flex-1 min-h-0">
                        <div className="grid grid-cols-7 border-b border-slate-200/60 dark:border-slate-800/60 bg-slate-50/30 dark:bg-black/20 shrink-0">
                          {['Sun', 'Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat'].map((day, i) => {
                            const showDay = calWeekStartsOn === 'Monday' ? ['Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun'][i] : day;
                            const isWeekend = showDay === 'Sun' || showDay === 'Sat';
                            return (
                              <div key={showDay} className={cn(
                                "py-3 text-center text-xs font-bold uppercase tracking-wider border-r border-slate-200/60 dark:border-slate-800/60 last:border-0",
                                isWeekend ? "text-slate-400 dark:text-slate-500" : "text-slate-500 dark:text-slate-400"
                              )}>
                                {showDay}
                              </div>
                            );
                          })}
                        </div>
                        <div className="flex-1 overflow-y-auto custom-scrollbar min-h-0">
                          <div className="grid grid-cols-7 bg-slate-200/40 dark:bg-slate-800/40 gap-px border-b border-transparent min-h-full" style={{ gridTemplateRows: `repeat(${Math.ceil((new Date(currentCalendarDate.getFullYear(), currentCalendarDate.getMonth(), 1).getDay() + (calWeekStartsOn === 'Monday' && new Date(currentCalendarDate.getFullYear(), currentCalendarDate.getMonth(), 1).getDay() === 0 ? 6 : calWeekStartsOn === 'Monday' ? -1 : 0) + new Date(currentCalendarDate.getFullYear(), currentCalendarDate.getMonth() + 1, 0).getDate()) / 7)}, minmax(120px, 1fr))` }}>
                          {(() => {
                            const startOfMonth = new Date(currentCalendarDate.getFullYear(), currentCalendarDate.getMonth(), 1);
                            let startDay = startOfMonth.getDay();
                            if (calWeekStartsOn === 'Monday') {
                              startDay = startDay === 0 ? 6 : startDay - 1;
                            }
                            const daysInMonth = new Date(currentCalendarDate.getFullYear(), currentCalendarDate.getMonth() + 1, 0).getDate();
                            const totalDays = startDay + daysInMonth;
                            const numRows = Math.ceil(totalDays / 7);
                            const now = new Date();
                            
                            return Array.from({ length: numRows * 7 }).map((_, i) => {
                              const dayNum = i - startDay + 1;
                              const isToday = dayNum === now.getDate() && currentCalendarDate.getMonth() === now.getMonth() && currentCalendarDate.getFullYear() === now.getFullYear();
                              const isCurrentMonth = dayNum > 0 && dayNum <= daysInMonth;
                              
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
                                  onDoubleClick={() => {
                                    if (isCurrentMonth) {
                                      setNewEvent({ ...newEvent, startDate: format(new Date(currentCalendarDate.getFullYear(), currentCalendarDate.getMonth(), dayNum), 'yyyy-MM-dd'), endDate: format(new Date(currentCalendarDate.getFullYear(), currentCalendarDate.getMonth(), dayNum), 'yyyy-MM-dd') });
                                      setIsEventModalOpen(true);
                                    }
                                  }}
                                  className={cn(
                                    "min-h-[120px] p-2 bg-white dark:bg-[#0d0e15] hover:bg-slate-50 dark:hover:bg-[#151722] transition-colors cursor-pointer group flex flex-col",
                                    !isCurrentMonth && "bg-slate-50/50 dark:bg-[#0a0a0f]"
                                  )}
                                >
                                  <div className="flex justify-between items-start mb-1">
                                    <span className={cn(
                                      "text-[13px] font-semibold w-7 h-7 flex items-center justify-center rounded-full transition-all",
                                      isToday ? "bg-indigo-600 text-white shadow-md shadow-indigo-500/20" : "text-slate-700 dark:text-slate-300 group-hover:text-indigo-600 dark:group-hover:text-indigo-400",
                                      !isCurrentMonth && "font-normal opacity-30 text-slate-400"
                                    )}>
                                      {isCurrentMonth ? dayNum : ""}
                                    </span>
                                  </div>
                                  
                                  {calCompactMonthView ? (
                                    <div className="flex flex-wrap items-center justify-start gap-1.5 p-1 mt-1 overflow-hidden">
                                      {dayEvents.map((event: any, eIdx: number) => {
                                        const cal = calendars.find((c: any) => c.id === (event.calendarId || (event.calendarIds && Object.keys(event.calendarIds)[0])) && c._accountId === event._accountId);
                                        const isExt = icalSubscriptions.some(sub => sub.calendarId === event.calendarId);
                                        const calColor = isExt ? (icalSubscriptions.find(s => s.calendarId === event.calendarId)?.color || '#22c55e') : (cal?._color || cal?.color || '#6366f1');
                                        return (
                                          <div key={`${event.id}-${eIdx}`} className="w-2.5 h-2.5 rounded-full shadow-sm cursor-pointer hover:scale-125 transition-transform" style={{backgroundColor: calColor}} title={event.title} onClick={(e) => { e.stopPropagation(); setSelectedEvent(event); }} />
                                        );
                                      })}
                                    </div>
                                  ) : (
                                    <div className="flex-1 space-y-1 overflow-y-auto no-scrollbar">
                                      {dayEvents.slice(0, 4).map((event, idx) => {
                                        const cal = calendars.find((c: any) => c.id === (event.calendarId || (event.calendarIds && Object.keys(event.calendarIds)[0])) && c._accountId === event._accountId);
                                        const isExt = icalSubscriptions.some(sub => sub.calendarId === event.calendarId);
                                        const calColor = isExt ? (icalSubscriptions.find(s => s.calendarId === event.calendarId)?.color || '#22c55e') : (cal?._color || cal?.color || '#6366f1');
                                        return (
                                          <div 
                                            key={idx} 
                                            onClick={(e) => {
                                              e.stopPropagation();
                                              setSelectedEvent(event);
                                            }}
                                            className="px-2 py-1 bg-indigo-50/80 dark:bg-indigo-500/10 border-l-[3px] rounded-r text-[11px] font-semibold text-indigo-700 dark:text-indigo-300 truncate transition-all hover:bg-slate-100 dark:hover:bg-slate-800 shadow-sm"
                                            title={calEventHoverPreview === 'None' ? undefined : event.title}
                                            style={{ borderLeftColor: calColor }}
                                          >
                                            {calShowTimeInMonth && !event.isAllDay && !event.showWithoutTime && format(new Date(event.start || event.startDate), calTimeFormat === '24-hour' ? 'HH:mm' : 'h:mm a')} {event.title}
                                          </div>
                                        );
                                      })}
                                      {dayEvents.length > 4 && (
                                        <div className="px-2 py-0.5 text-[10px] font-bold text-slate-500 dark:text-slate-400">
                                          +{dayEvents.length - 4} more
                                        </div>
                                      )}
                                    </div>
                                  )}
                                </div>
                              );
                            });
                          })()}
                        </div>
                      </div>
                    </div>
                  )}

                  {calendarView === 'week' && (
                      <div className="flex-1 overflow-auto custom-scrollbar relative bg-white dark:bg-[#0d0e15] min-h-0">
                        <div className="min-w-[1000px] flex flex-col relative">
                          <div className="flex flex-col sticky top-0 z-50 bg-white dark:bg-[#0d0e15] shadow-sm">
                            <div className="flex border-b border-slate-200/60 dark:border-slate-800/60 bg-slate-50/90 dark:bg-[#0d0e15]/90 backdrop-blur-md shrink-0">
                              <div className="w-[80px] border-r border-slate-200/60 dark:border-slate-800/60 p-2 flex items-center justify-center sticky left-0 bg-slate-50/90 dark:bg-[#0d0e15]/90 z-50 backdrop-blur-md shrink-0">
                                <span className="text-[10px] sm:text-xs font-bold text-slate-400 uppercase tracking-wider">Time</span>
                              </div>
                              <div className="flex-1 flex">
                                {Array.from({ length: 7 }).map((_, i) => {
                                  const date = new Date(currentCalendarDate);
                                  const startOfWeek = date.getDate() - date.getDay();
                                  date.setDate(startOfWeek + i);
                                  const isToday = date.getDate() === new Date().getDate() && date.getMonth() === new Date().getMonth() && date.getFullYear() === new Date().getFullYear();
                                  
                                  return (
                                    <div key={i} className="flex-1 py-2 flex flex-col items-center justify-center border-r border-slate-200/60 dark:border-slate-800/60 last:border-0">
                                      <span className={cn("text-[10px] sm:text-xs font-bold uppercase tracking-wider mb-1", isToday ? "text-indigo-600 dark:text-indigo-400" : "text-slate-500")}>
                                        {format(date, 'eee')}
                                      </span>
                                      <span className={cn("text-sm sm:text-lg font-bold w-6 h-6 sm:w-8 sm:h-8 flex items-center justify-center rounded-full", isToday ? "bg-indigo-600 text-white" : "text-slate-800 dark:text-white")}>
                                        {date.getDate()}
                                      </span>
                                    </div>
                                  );
                                })}
                              </div>
                            </div>
                            
                            {(() => {
                              // Extract all day events for the current week
                              const allDayWeekEvents = Array.from({ length: 7 }).map((_, dayIndex) => {
                                const date = new Date(currentCalendarDate);
                                const startOfWeek = date.getDate() - date.getDay();
                                date.setDate(startOfWeek + dayIndex);
                                
                                return filteredEvents.filter(e => {
                                  const eventDate = new Date(e.start || e.startDate);
                                  return e.showWithoutTime && eventDate.getDate() === date.getDate() && eventDate.getMonth() === date.getMonth() && eventDate.getFullYear() === date.getFullYear();
                                });
                              });
                              
                              const hasAnyAllDayEvents = allDayWeekEvents.some(events => events.length > 0);

                              return hasAnyAllDayEvents && (
                                <div className="flex border-b border-slate-200/60 dark:border-slate-800/60 bg-white dark:bg-[#0d0e15] shrink-0">
                                  <div className="w-[80px] flex flex-col justify-center items-center border-r border-slate-200/60 dark:border-slate-800/60 sticky left-0 bg-white dark:bg-[#0d0e15] z-50 shrink-0 text-[10px] font-bold text-slate-400 uppercase tracking-wider py-2 shadow-[2px_0_4px_-2px_rgba(0,0,0,0.1)]">
                                    All day
                                  </div>
                                  <div className="flex-1 flex relative">
                                    {Array.from({ length: 7 }).map((_, dayIndex) => (
                                      <div key={dayIndex} className="flex-1 border-r border-slate-200/60 dark:border-slate-800/60 last:border-0 relative p-1 overflow-y-auto max-h-[100px] custom-scrollbar flex flex-col gap-1">
                                        {allDayWeekEvents[dayIndex].map((event, idx) => (
                                          <div 
                                            key={idx}
                                            onClick={() => setSelectedEvent(event)}
                                            className="p-1 px-1.5 bg-indigo-100 dark:bg-indigo-500/20 border-l-[3px] border-indigo-500 rounded text-[10px] font-bold text-indigo-900 dark:text-indigo-100 cursor-pointer truncate transition-all hover:bg-indigo-200 dark:hover:bg-indigo-500/30"
                                          >
                                            {event.title}
                                          </div>
                                        ))}
                                      </div>
                                    ))}
                                  </div>
                                </div>
                              );
                            })()}
                          </div>
                          
                          <div className="flex flex-col flex-1 shrink-0">
                            {(() => {
                              const allDayWeekEvents = Array.from({ length: 7 }).map((_, dayIndex) => {
                                const date = new Date(currentCalendarDate);
                                const startOfWeek = date.getDate() - date.getDay();
                                date.setDate(startOfWeek + dayIndex);
                                return filteredEvents.filter(e => {
                                  const eventDate = new Date(e.start || e.startDate);
                                  return e.showWithoutTime && eventDate.getDate() === date.getDate() && eventDate.getMonth() === date.getMonth() && eventDate.getFullYear() === date.getFullYear();
                                });
                              });
                              return (
                                <>
                                  <div className="flex-1 relative border-t border-slate-200/60 dark:border-slate-800/60 pb-16">
                                    <div className="flex relative" style={{ height: '1536px' }}>
                                      <div className="w-[80px] flex flex-col border-r border-slate-200/60 dark:border-slate-800/60 shrink-0 sticky left-0 z-20 bg-white dark:bg-[#0d0e15] shadow-[2px_0_4px_-2px_rgba(0,0,0,0.1)]">
                                        {Array.from({ length: 24 }).map((_, i) => (
                                          <div key={i} className="h-16 border-b border-transparent flex items-start justify-center pr-2 py-1">
                                            <span className="text-[10px] sm:text-[11px] font-bold text-slate-400 uppercase tracking-wider">{calTimeFormat === '24-hour' ? `${i.toString().padStart(2, '0')}:00` : (i === 0 ? '12 AM' : i < 12 ? `${i} AM` : i === 12 ? '12 PM' : `${i - 12} PM`)}</span>
                                          </div>
                                        ))}
                                      </div>
                                      <div className="flex-1 flex relative">
                                        {Array.from({ length: 24 }).map((_, h) => (
                                          <div key={h} className="absolute left-0 right-0 border-b border-slate-100 dark:border-slate-800/40 pointer-events-none" style={{ top: `${h * 64}px`, height: '64px' }}></div>
                                        ))}
                                        
                                        {(() => {
                                          const now = new Date();
                                          const isCurrentWeek = Array.from({ length: 7 }).some((_, dayIndex) => {
                                            const date = new Date(currentCalendarDate);
                                            const startOfWeek = date.getDate() - date.getDay();
                                            date.setDate(startOfWeek + dayIndex);
                                            return date.getDate() === now.getDate() && date.getMonth() === now.getMonth() && date.getFullYear() === now.getFullYear();
                                          });
                                          
                                          if (!isCurrentWeek) return null;
                                          const top = now.getHours() * 64 + (now.getMinutes() / 60) * 64;
                                          return (
                                            <div className="absolute left-0 right-0 border-b-[2px] border-red-500/80 z-20 pointer-events-none shadow-[0_1px_4px_rgba(239,68,68,0.3)]" style={{ top: `${top}px` }}>
                                              <div className="absolute -left-1.5 -top-[5px] w-2.5 h-2.5 rounded-full bg-red-500/80"></div>
                                            </div>
                                          );
                                        })()}
          
                                        {Array.from({ length: 7 }).map((_, dayIndex) => {
                                          const date = new Date(currentCalendarDate);
                                          const startOfWeek = date.getDate() - date.getDay();
                                          date.setDate(startOfWeek + dayIndex);
                                          
                                          const dayEvents = filteredEvents.filter(e => {
                                            const eventDate = new Date(e.start || e.startDate);
                                            return !e.showWithoutTime && eventDate.getDate() === date.getDate() && eventDate.getMonth() === date.getMonth() && eventDate.getFullYear() === date.getFullYear();
                                          }).sort((a, b) => new Date(a.start || a.startDate).getTime() - new Date(b.start || b.startDate).getTime());
                                          
                                          // Simple overlap layout
                                          const columns: any[][] = [];
                                          const layouts = dayEvents.map(event => {
                                            const start = new Date(event.start || event.startDate).getTime();
                                            const end = event.endDate ? new Date(event.endDate).getTime() : start + 60 * 60 * 1000;
                                            let colIdx = 0;
                                            for (let i = 0; i < columns.length; i++) {
                                              const lastEvent = columns[i][columns[i].length - 1];
                                              const lastEnd = lastEvent.endDate ? new Date(lastEvent.endDate).getTime() : new Date(lastEvent.start || lastEvent.startDate).getTime() + 60 * 60 * 1000;
                                              if (start >= lastEnd) {
                                                columns[i].push(event);
                                                colIdx = i;
                                                break;
                                              }
                                              if (i === columns.length - 1) {
                                                columns.push([event]);
                                                colIdx = columns.length - 1;
                                                break;
                                              }
                                            }
                                            if (columns.length === 0) {
                                              columns.push([event]);
                                            }
                                            return { event, colIdx };
                                          });

                                          return (
                                            <div 
                                              key={dayIndex} 
                                              className="flex-1 relative border-r border-slate-100 dark:border-slate-800/40 last:border-0 h-[1536px] cursor-text"
                                              onDoubleClick={(e) => {
                                                 const rect = e.currentTarget.getBoundingClientRect();
                                                 const y = e.clientY - rect.top;
                                                 const hour = Math.floor(y / 64);
                                                 const clickDate = new Date(date);
                                                 clickDate.setHours(hour, 0, 0, 0);
                                                 setNewEvent({ ...newEvent, startDate: format(clickDate, 'yyyy-MM-dd'), startTime: format(clickDate, 'HH:mm'), endDate: format(clickDate, 'yyyy-MM-dd'), endTime: format(new Date(clickDate.getTime() + 3600000), 'HH:mm') });
                                                 setIsEventModalOpen(true);
                                              }}
                                            >
                                              {layouts.map(({ event, colIdx }, idx) => {
                                                const eventDate = new Date(event.start || event.startDate);
                                                const startTokens = event.startTime ? event.startTime.split(':') : [];
                                                const endTokens = event.endTime ? event.endTime.split(':') : [];
                                                
                                                const startHours = startTokens.length ? parseInt(startTokens[0]) : eventDate.getHours();
                                                const startMins = startTokens.length ? parseInt(startTokens[1]) : eventDate.getMinutes();
                                                const top = startHours * 64 + (startMins / 60) * 64;
                                                
                                                let height = 48; // default approx 45 mins
                                                if (event.startDate && event.endDate && event.startTime && event.endTime && event.startDate === event.endDate) {
                                                  const endHours = parseInt(endTokens[0] || '0');
                                                  const endMins = parseInt(endTokens[1] || '0');
                                                  const diffMins = (endHours * 60 + endMins) - (startHours * 60 + startMins);
                                                  if (diffMins > 0) height = (diffMins / 60) * 64;
                                                }
                                                
                                                const widthPct = columns.length > 0 ? 100 / columns.length : 100;
                                                const leftPct = widthPct * colIdx;
                                                // Adjust color to match calendar theme
                                                const calColor = calendars.find(c => c.id === event.calendarId)?._color || 'rgb(99 102 241)';
                                                
                                                return (
                                                  <div 
                                                    key={idx}
                                                    onClick={() => setSelectedEvent(event)}
                                                    className="absolute p-2 bg-indigo-50/90 dark:bg-indigo-500/10 border-l-[4px] border-indigo-500 rounded-md text-[11px] sm:text-xs font-semibold text-indigo-900 dark:text-indigo-100 cursor-pointer overflow-hidden shadow-sm hover:shadow-md transition-all z-10 backdrop-blur-sm"
                                                    style={{ 
                                                      top: `${top}px`, 
                                                      height: `${height}px`,
                                                      left: `calc(${leftPct}% + 1px)`,
                                                      width: `calc(${widthPct}% - 2px)`,
                                                      borderLeftColor: calColor,
                                                    }}
                                                  >
                                                    <div className="truncate leading-tight mb-0.5">{event.title}</div>
                                                    <div className="text-[9px] sm:text-[10px] opacity-70 font-medium truncate">
                                                      {format(eventDate, calTimeFormat === '24-hour' ? 'HH:mm' : 'h:mm a')}
                                                    </div>
                                                  </div>
                                                );
                                              })}
                                            </div>
                                          );
                                        })}
                                      </div>
                                    </div>
                                  </div>
                                </>
                              );
                            })()}
                          </div>
                        </div>
                      </div>
                    )}

                    {calendarView === 'day' && (
                      <div className="flex flex-col flex-1 h-full min-h-0">
                        <div className="border-b border-slate-200/60 dark:border-slate-800/60 bg-slate-50/30 dark:bg-black/20 p-4 shrink-0 flex items-center justify-between">
                          <div className="flex items-center gap-4">
                            <div className="w-14 h-14 md:w-16 md:h-16 rounded-2xl bg-indigo-50 dark:bg-indigo-500/10 border border-indigo-100 dark:border-indigo-500/20 flex flex-col items-center justify-center text-indigo-600 dark:text-indigo-400">
                              <span className="text-[10px] md:text-xs font-bold uppercase">{format(currentCalendarDate, 'MMM')}</span>
                              <span className="text-xl md:text-2xl font-bold leading-none">{format(currentCalendarDate, 'd')}</span>
                            </div>
                            <div>
                              <h2 className="text-lg md:text-xl font-bold text-slate-900 dark:text-white">{format(currentCalendarDate, 'EEEE')}</h2>
                              <p className="text-xs md:text-sm text-slate-500 dark:text-slate-400">{format(currentCalendarDate, 'MMMM d, yyyy')}</p>
                            </div>
                          </div>
                        </div>
                        <div className="flex-1 flex flex-col min-h-0">
                          {(() => {
                            const dayEvents = filteredEvents.filter(e => {
                              const eventDate = new Date(e.start || e.startDate);
                              return eventDate.getDate() === currentCalendarDate.getDate() && eventDate.getMonth() === currentCalendarDate.getMonth() && eventDate.getFullYear() === currentCalendarDate.getFullYear();
                            });
                            
                            const allDayEvents = dayEvents.filter(e => e.showWithoutTime);
                            const timedEvents = dayEvents.filter(e => !e.showWithoutTime);
                            
                            return (
                              <>
                                {allDayEvents.length > 0 && (
                                  <div className="flex border-b border-slate-200/60 dark:border-slate-800/60 bg-white dark:bg-[#0d0e15] shrink-0 min-h-0">
                                    <div className="w-16 md:w-20 pt-2 shrink-0 border-r border-slate-200/60 dark:border-slate-800/60 text-[10px] md:text-xs text-center font-bold text-slate-400 uppercase">
                                      All day
                                    </div>
                                    <div className="flex-1 p-2 flex flex-col gap-1 overflow-y-auto max-h-[140px] custom-scrollbar">
                                      {allDayEvents.map((event, idx) => (
                                        <div 
                                          key={idx}
                                          onClick={() => setSelectedEvent(event)}
                                          className="p-2 bg-indigo-100 dark:bg-indigo-500/20 border-l-[4px] border-indigo-500 rounded-lg shadow-sm cursor-pointer hover:bg-indigo-200 dark:hover:bg-indigo-500/30 transition-all text-sm font-bold text-indigo-900 dark:text-indigo-100"
                                        >
                                          {event.title}
                                        </div>
                                      ))}
                                    </div>
                                  </div>
                                )}
                                
                                <div className="flex-1 overflow-y-auto custom-scrollbar relative pr-1 pb-16">
                                  <div className="flex relative" style={{ height: '1536px' }}>
                                    <div className="w-16 md:w-20 flex flex-col border-r border-slate-200/60 dark:border-slate-800/60 shrink-0 bg-white/50 dark:bg-black/50 z-10">
                                      {Array.from({ length: 24 }).map((_, i) => (
                                        <div key={i} className="h-16 flex items-start justify-end pr-2 md:pr-3 py-1.5">
                                          <span className="text-[10px] md:text-xs font-bold text-slate-400 uppercase tracking-wider">{calTimeFormat === '24-hour' ? `${i.toString().padStart(2, '0')}:00` : (i === 0 ? '12 AM' : i < 12 ? `${i} AM` : i === 12 ? '12 PM' : `${i - 12} PM`)}</span>
                                        </div>
                                      ))}
                                    </div>
                                    <div 
                                      className="flex-1 relative bg-slate-50/10 dark:bg-black/10 cursor-text"
                                      onDoubleClick={(e) => {
                                        const rect = e.currentTarget.getBoundingClientRect();
                                        const y = e.clientY - rect.top;
                                        const hour = Math.floor(y / 64);
                                        const clickDate = new Date(currentCalendarDate);
                                        clickDate.setHours(hour, 0, 0, 0);
                                        setNewEvent({ ...newEvent, startDate: format(clickDate, 'yyyy-MM-dd'), startTime: format(clickDate, 'HH:mm'), endDate: format(clickDate, 'yyyy-MM-dd'), endTime: format(new Date(clickDate.getTime() + 3600000), 'HH:mm') });
                                        setIsEventModalOpen(true);
                                      }}
                                    >
                                      {Array.from({ length: 24 }).map((_, h) => (
                                        <div key={h} className="absolute left-0 right-0 border-b border-slate-200/40 dark:border-slate-800/40 pointer-events-none" style={{ top: `${h * 64}px`, height: '64px' }}></div>
                                      ))}
                                      
                                      {(() => {
                                        const now = new Date();
                                        const isToday = currentCalendarDate.getDate() === now.getDate() && currentCalendarDate.getMonth() === now.getMonth() && currentCalendarDate.getFullYear() === now.getFullYear();
                                        
                                        if (!isToday) return null;
                                        const top = now.getHours() * 64 + (now.getMinutes() / 60) * 64;
                                        return (
                                          <div className="absolute left-0 right-0 border-b-[2.5px] border-red-500/90 z-20 pointer-events-none shadow-[0_1px_4px_rgba(239,68,68,0.2)]" style={{ top: `${top}px` }}>
                                            <div className="absolute left-0 -top-1.5 w-3 h-3 rounded-full bg-red-500/90 shadow-[0_0_8px_rgba(239,68,68,0.4)]"></div>
                                          </div>
                                        );
                                      })()}
        
                                      {(() => {
                                        const sortedTimedEvents = [...timedEvents].sort((a, b) => new Date(a.start || a.startDate).getTime() - new Date(b.start || b.startDate).getTime());
                                        const columns: any[][] = [];
                                        const layouts = sortedTimedEvents.map(event => {
                                          const start = new Date(event.start || event.startDate).getTime();
                                          const end = event.endDate ? new Date(event.endDate).getTime() : start + 60 * 60 * 1000;
                                          let colIdx = 0;
                                          for (let i = 0; i < columns.length; i++) {
                                            const lastEvent = columns[i][columns[i].length - 1];
                                            const lastEnd = lastEvent.endDate ? new Date(lastEvent.endDate).getTime() : new Date(lastEvent.start || lastEvent.startDate).getTime() + 60 * 60 * 1000;
                                            if (start >= lastEnd) {
                                              columns[i].push(event);
                                              colIdx = i;
                                              break;
                                            }
                                            if (i === columns.length - 1) {
                                              columns.push([event]);
                                              colIdx = columns.length - 1;
                                              break;
                                            }
                                          }
                                          if (columns.length === 0) {
                                            columns.push([event]);
                                          }
                                          return { event, colIdx };
                                        });

                                        return layouts.map(({ event, colIdx }, idx) => {
                                          const eventDate = new Date(event.start || event.startDate);
                                          const startTokens = event.startTime ? event.startTime.split(':') : [];
                                          const endTokens = event.endTime ? event.endTime.split(':') : [];
                                          
                                          const startHours = startTokens.length ? parseInt(startTokens[0]) : eventDate.getHours();
                                          const startMins = startTokens.length ? parseInt(startTokens[1]) : eventDate.getMinutes();
                                          const top = startHours * 64 + (startMins / 60) * 64;
                                          
                                          let height = 60; // Default approx 1 hour
                                          if (event.startDate && event.endDate && event.startTime && event.endTime && event.startDate === event.endDate) {
                                            const endHours = parseInt(endTokens[0] || '0');
                                            const endMins = parseInt(endTokens[1] || '0');
                                            const diffMins = (endHours * 60 + endMins) - (startHours * 60 + startMins);
                                            if (diffMins > 0) height = (diffMins / 60) * 64;
                                          }
                                          
                                          const widthPct = columns.length > 0 ? 100 / columns.length : 100;
                                          const leftPct = widthPct * colIdx;

                                          return (
                                            <div 
                                              key={idx}
                                              onClick={() => setSelectedEvent(event)}
                                              className="absolute p-2.5 bg-indigo-100 dark:bg-indigo-500/20 border-l-[4px] border-indigo-500 rounded-lg shadow-sm cursor-pointer hover:shadow-md transition-all z-10 hover:bg-indigo-200 dark:hover:bg-indigo-500/30"
                                              style={{ 
                                                top: `${top}px`, 
                                                height: `${height}px`,
                                                left: `calc(${leftPct}% + 8px)`,
                                                width: `calc(${widthPct}% - 16px)`
                                              }}
                                            >
                                              <div className="font-bold text-indigo-900 dark:text-indigo-100 leading-tight">{event.title}</div>
                                              <div className="text-[11px] font-medium text-indigo-700 dark:text-indigo-300 mt-1 flex items-center gap-1">
                                                <Clock className="w-3 h-3" />
                                                {format(eventDate, calTimeFormat === '24-hour' ? 'HH:mm' : 'h:mm a')}
                                              </div>
                                            </div>
                                          );
                                        });
                                      })()}
                                    </div>
                                  </div>
                                </div>
                              </>
                            );
                          })()}
                        </div>
                      </div>
                    )}

                    {calendarView === 'agenda' && (
                      <div className="flex-1 overflow-y-auto custom-scrollbar bg-white dark:bg-[#0d0e15] min-h-full rounded-b-3xl">
                        {(() => {
                          const startOfCurrent = new Date(currentCalendarDate.getFullYear(), currentCalendarDate.getMonth(), currentCalendarDate.getDate()).getTime();

                          const allUpcoming = [...filteredEvents].sort((a, b) => {
                            return new Date(a.start || a.startDate).getTime() - new Date(b.start || b.startDate).getTime();
                          }).filter(e => {
                            const eventDate = new Date(e.start || e.startDate);
                            const startOfEvent = new Date(eventDate.getFullYear(), eventDate.getMonth(), eventDate.getDate()).getTime();
                            return startOfEvent >= Math.min(startOfCurrent, new Date(new Date().getFullYear(), new Date().getMonth(), new Date().getDate()).getTime());
                          });

                          const groupedAll = allUpcoming.reduce((acc: any, event) => {
                            const date = new Date(event.start || event.startDate);
                            const localDate = new Date(date.getFullYear(), date.getMonth(), date.getDate());
                            const key = format(localDate, 'yyyy-MM-dd');
                            if (!acc[key]) acc[key] = [];
                            acc[key].push(event);
                            return acc;
                          }, {});

                          const todayKey = format(new Date(), 'yyyy-MM-dd');
                          if (!groupedAll[todayKey]) groupedAll[todayKey] = [];

                          const allDates = Object.keys(groupedAll).sort();

                          return (
                            <div className="flex flex-col flex-1 pb-16 min-h-full">
                              {allDates.map((dateStr) => {
                                const [year, month, day] = dateStr.split('-');
                                const date = new Date(parseInt(year), parseInt(month) - 1, parseInt(day));
                                const isCurrentlySelectedMonth = date.getMonth() === currentCalendarDate.getMonth() && date.getFullYear() === currentCalendarDate.getFullYear();
                                const isActuallyToday = dateStr === todayKey;
                                const isActuallyTomorrow = dateStr === format(new Date(new Date().getTime() + 86400000), 'yyyy-MM-dd');
                                const eventsForDay = groupedAll[dateStr];

                                let dateHeaderStr = format(date, 'EEEE, MMMM d');
                                if (isActuallyToday) dateHeaderStr = "Today";
                                else if (isActuallyTomorrow) dateHeaderStr = "Tomorrow";

                                // Scroll target ref could be added here if needed

                                return (
                                  <div key={dateStr} className="flex flex-col">
                                    <div className="sticky top-0 bg-white/90 dark:bg-[#0d0e15]/90 backdrop-blur-sm px-4 py-[10px] border-b border-slate-200 dark:border-slate-800/60 z-10 flex items-baseline gap-2">
                                      <span className={cn(
                                        "text-[14px] font-semibold",
                                        isActuallyToday ? "text-indigo-600 dark:text-indigo-400" : "text-slate-900 dark:text-white"
                                      )}>
                                        {dateHeaderStr}
                                      </span>
                                      <span className="text-[12px] text-slate-500 dark:text-slate-400">
                                        {format(date, 'MMM d, yyyy')}
                                      </span>
                                    </div>
                                    
                                    {eventsForDay.length === 0 ? (
                                      <div className="px-4 py-8 text-center text-[14px] text-slate-500">
                                        No events.
                                      </div>
                                    ) : (
                                      <div className="divide-y divide-slate-100 dark:divide-slate-800/60">
                                        {eventsForDay.map((event: any, eIdx: number) => {
                                          const eventDate = new Date(event.start || event.startDate);
                                          const cal = calendars.find((c: any) => c.id === (event.calendarId || (event.calendarIds && Object.keys(event.calendarIds)[0])) && c._accountId === event._accountId);
                                          
                                          let endStr = format(eventDate, calTimeFormat === '24-hour' ? 'HH:mm' : 'h:mm a');
                                          if (event.duration) {
                                            const matchHours = String(event.duration).match(/(\d+)H/);
                                            const matchMins = String(event.duration).match(/(\d+)M/);
                                            let ms = 0;
                                            if (matchHours) ms += parseInt(matchHours[1]) * 3600000;
                                            if (matchMins) ms += parseInt(matchMins[1]) * 60000;
                                            if (!matchHours && !matchMins) ms += 3600000;
                                            endStr = format(new Date(eventDate.getTime() + ms), calTimeFormat === '24-hour' ? 'HH:mm' : 'h:mm a');
                                          }
                                          
                                          const isPast = eventDate.getTime() < new Date().getTime() && !event.isAllDay && !event.showWithoutTime;

                                          return (
                                            <button 
                                              key={eIdx}
                                              onClick={() => setSelectedEvent(event)}
                                              className={cn(
                                                "w-full flex items-start px-4 py-[14px] sm:py-[18px] hover:bg-indigo-50/50 dark:hover:bg-indigo-500/10 transition-colors text-left border-l-[3px] border-transparent hover:border-indigo-500",
                                                isPast && "opacity-60"
                                              )}
                                              style={{ gap: '16px' }}
                                            >
                                              <div className="flex flex-col items-center pt-[3px] min-w-[64px] shrink-0">
                                                {event.showWithoutTime || event.isAllDay ? (
                                                  <span className="text-[12px] font-semibold text-indigo-500 dark:text-indigo-400">
                                                    All day
                                                  </span>
                                                ) : (
                                                  <>
                                                    <span className="text-[14px] font-semibold text-indigo-900 dark:text-indigo-200 leading-tight">
                                                      {format(eventDate, calTimeFormat === '24-hour' ? 'HH:mm' : 'h:mm a')}
                                                    </span>
                                                    <span className="text-[12px] text-indigo-500/70 dark:text-indigo-400/70 mt-[1px]">
                                                      {endStr}
                                                    </span>
                                                  </>
                                                )}
                                              </div>
                                              
                                              <div 
                                                className="w-[4px] self-stretch rounded-full shrink-0" 
                                                style={{ backgroundColor: cal?.color || '#4f46e5' }}
                                              ></div>
                                              
                                              <div className="flex-1 min-w-0 flex flex-col pt-[1px]">
                                                <div className="text-[14px] sm:text-[15px] font-semibold text-slate-900 dark:text-white truncate">
                                                  {event.title || "No title"}
                                                </div>
                                                {(event.locations ? Object.values(event.locations as any)[0] as any : null)?.name && (
                                                  <div className="flex items-center gap-1.5 text-[13px] text-slate-500 dark:text-slate-400 mt-[3px]">
                                                    <MapPin className="w-3.5 h-3.5 shrink-0" />
                                                    <span className="truncate">{(Object.values(event.locations as any)[0] as any).name}</span>
                                                  </div>
                                                )}
                                                {event.participants && Object.keys(event.participants).length > 0 && (
                                                  <div className="flex items-center gap-1.5 text-[13px] text-slate-500 dark:text-slate-400 mt-[3px]">
                                                    <Users className="w-3.5 h-3.5 shrink-0" />
                                                    <span>{Object.keys(event.participants).length}</span>
                                                  </div>
                                                )}
                                                {cal && (
                                                  <div className="flex items-center gap-1.5 text-[13px] text-slate-500 dark:text-slate-400 mt-[3px]">
                                                    <div className="w-2.5 h-2.5 rounded-full" style={{ backgroundColor: cal.color || '#4f46e5' }} />
                                                    <span className="truncate">{cal.name}</span>
                                                  </div>
                                                )}
                                              </div>
                                            </button>
                                          );
                                        })}
                                      </div>
                                    )}
                                  </div>
                                );
                              })}
                            </div>
                          );
                        })()}
                      </div>
                    )}

                    {calendarView === 'tasks' as any && (
                      <div className="flex-1 overflow-y-auto custom-scrollbar p-6 bg-slate-50/50 dark:bg-black/50">
                        <div className="max-w-3xl mx-auto">
                          <div className="flex items-center justify-between mb-8">
                            <div>
                              <h2 className="text-2xl font-bold tracking-tight text-slate-900 dark:text-white">My Tasks</h2>
                              <p className="text-slate-500 dark:text-slate-400 mt-1">Manage your upcoming to-dos.</p>
                            </div>
                            <button className="px-4 py-2 border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-800 text-slate-700 dark:text-slate-200 font-bold rounded-lg hover:bg-slate-50 dark:hover:bg-slate-700 transition flex items-center gap-2">
                              <Plus className="w-4 h-4" /> Add Task
                            </button>
                          </div>
                          
                          <div className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-2xl p-8 text-center text-slate-500 dark:text-slate-400 flex flex-col items-center">
                             <div className="w-16 h-16 bg-slate-100 dark:bg-slate-800 rounded-full flex items-center justify-center mb-4">
                               <Check className="w-8 h-8 text-slate-400" />
                             </div>
                             <p className="text-base font-semibold">You have no tasks.</p>
                             <p className="text-sm mt-1">Add tasks here to keep track of your work.</p>
                          </div>
                        </div>
                      </div>
                    )}
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
                    { id: 'account', icon: User },
                    { id: 'identities', icon: Mail },
                    { id: 'general', icon: Settings },
                    { id: 'compose', icon: Edit3 },
                    { id: 'read', icon: BookOpen },
                    { id: 'notifications', icon: Bell },
                    { id: 'vacation', icon: Reply },
                    { id: 'templates', icon: File },
                    { id: 'tags', icon: Tag },
                    { id: 'contacts', icon: Users },
                    { id: 'calendar', icon: Calendar },
                    { id: 'folders', icon: Folder },
                    { id: 'filters', icon: Filter },
                    { id: 'security', icon: Shield },
                    { id: 'advanced', icon: Key },
                  ].map((item) => (
                    <button 
                      key={item.id}
                      onClick={() => setIsSettingsSection(item.id as any)}
                      className={cn(
                        "flex items-center gap-3 px-4 py-2.5 rounded-xl text-sm font-medium transition-all",
                        isSettingsSection === item.id ? "bg-indigo-50 dark:bg-indigo-500/10 text-indigo-600 dark:text-indigo-400" : "text-slate-600 dark:text-slate-400 hover:bg-slate-50 dark:hover:bg-slate-900"
                      )}
                    >
                      <item.icon className="w-4 h-4" /> {t(language, item.id)}
                    </button>
                  ))}
                </nav>
                
                <div className="mt-auto pt-4 border-t border-slate-200 dark:border-slate-800">
                  <button 
                    onClick={onLogout}
                    className="w-full flex items-center gap-3 px-4 py-2.5 rounded-xl text-sm font-medium text-red-600 dark:text-red-400 hover:bg-red-50 dark:hover:bg-red-900/20 transition-all"
                  >
                    <LogOut className="w-4 h-4" /> {t(language, 'signOut')}
                  </button>
                </div>
              </div>

              {/* Settings Content Area */}
              <div className="flex-1 overflow-y-auto">
                {/* Mobile Settings Header */}
                <div className="sticky top-0 z-20 p-4 border-b border-slate-200 dark:border-slate-800 bg-white/80 dark:bg-black/80 backdrop-blur-md flex items-center justify-between md:p-6">
                  <h1 className="text-xl font-bold text-slate-900 dark:text-white md:text-2xl">
                    {isSettingsSection === 'account' ? t(language, 'accountInformation') : 
                     isSettingsSection === 'general' ? t(language, 'generalSettings') : 
                     isSettingsSection === 'compose' ? 'Compose' :
                     isSettingsSection === 'read' ? 'Read' :
                     isSettingsSection === 'identities' ? t(language, 'identities') :
                     isSettingsSection === 'security' ? t(language, 'security') : 
                     isSettingsSection === 'vacation' ? t(language, 'vacation') : 
                     isSettingsSection === 'notifications' ? t(language, 'notifications') : 
                     isSettingsSection === 'templates' ? t(language, 'templates') : 
                     isSettingsSection === 'tags' ? 'Tags' : 
                     isSettingsSection === 'contacts' ? t(language, 'contacts') : 
                     isSettingsSection === 'calendar' ? 'Calendar' :
                     isSettingsSection === 'folders' ? t(language, 'folders') : 
                     isSettingsSection === 'filters' ? t(language, 'filters') : t(language, 'advanced')}
                  </h1>
                  <button 
                    onClick={() => setIsSettingsMenuOpen(true)}
                    className="md:hidden flex items-center gap-2 bg-indigo-50 dark:bg-indigo-500/10 text-indigo-600 dark:text-indigo-400 px-4 py-2 rounded-full text-sm font-bold shadow-sm border border-indigo-100 dark:border-indigo-500/20"
                  >
                    {isSettingsSection === 'account' ? t(language, 'account') : 
                     isSettingsSection === 'general' ? t(language, 'general') : 
                     isSettingsSection === 'compose' ? 'Compose' :
                     isSettingsSection === 'read' ? 'Read' :
                     isSettingsSection === 'identities' ? t(language, 'identities') :
                     isSettingsSection === 'security' ? t(language, 'security') : 
                     isSettingsSection === 'vacation' ? t(language, 'vacation') : 
                     isSettingsSection === 'notifications' ? t(language, 'notifications') : 
                     isSettingsSection === 'templates' ? t(language, 'templates') : 
                     isSettingsSection === 'tags' ? 'Tags' : 
                     isSettingsSection === 'contacts' ? t(language, 'contacts') : 
                     isSettingsSection === 'calendar' ? 'Calendar' :
                     isSettingsSection === 'folders' ? t(language, 'folders') : 
                     isSettingsSection === 'filters' ? t(language, 'filters') : t(language, 'advanced')}
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
                          { id: 'account', icon: User },
                          { id: 'identities', icon: Mail },
                          { id: 'general', icon: Settings },
                          { id: 'compose', icon: Edit3 },
                          { id: 'read', icon: BookOpen },
                          { id: 'notifications', icon: Bell },
                          { id: 'vacation', icon: Reply },
                          { id: 'templates', icon: File },
                          { id: 'tags', icon: Tag },
                          { id: 'contacts', icon: Users },
                          { id: 'calendar', icon: Calendar },
                          { id: 'folders', icon: Folder },
                          { id: 'filters', icon: Filter },
                          { id: 'security', icon: Shield },
                          { id: 'advanced', icon: Key },
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
                                {t(language, item.id)}
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
                          <h2 className="text-xl font-bold text-slate-900 dark:text-white">{t(language, 'accountInformation')}</h2>
                        </div>
                        
                        <div className="divide-y divide-slate-200 dark:divide-slate-800">
                          <div className="py-4">
                            <div className="text-slate-500 dark:text-slate-400 text-xs font-bold uppercase tracking-wider mb-1">{t(language, 'username')}</div>
                            <div className="text-slate-900 dark:text-white font-bold text-lg">{credentials.username}</div>
                          </div>
                          <div className="py-4">
                            <div className="text-slate-500 dark:text-slate-400 text-[10px] font-black uppercase tracking-[0.2em] mb-1.5 opacity-60">{t(language, 'serverUrl')}</div>
                            <div className="text-slate-900 dark:text-white font-bold truncate leading-relaxed text-sm sm:text-base pr-4" title={credentials.serverUrl}>{credentials.serverUrl}</div>
                          </div>
                          <div className="py-4">
                            <div className="text-slate-500 dark:text-slate-400 text-[10px] font-black uppercase tracking-[0.2em] mb-1.5 opacity-60">API URL</div>
                            <div className="text-slate-900 dark:text-white font-bold truncate leading-relaxed text-sm sm:text-base pr-4" title={credentials.apiUrl || credentials.serverUrl}>{credentials.apiUrl || credentials.serverUrl}</div>
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

                  {isSettingsSection === 'identities' && (
                    <div className="grid gap-6">
                      <div className="bg-white dark:bg-slate-900 p-6 rounded-2xl border border-slate-200 dark:border-slate-800 shadow-sm">
                        <div className="flex items-center gap-3 mb-6">
                          <div className="p-2 bg-purple-100 dark:bg-purple-500/10 rounded-xl">
                            <Mail className="w-5 h-5 text-purple-600 dark:text-purple-400" />
                          </div>
                          <h2 className="text-xl font-bold text-slate-900 dark:text-white">{t(language, 'emailIdentities')}</h2>
                        </div>
                        <p className="text-sm text-slate-500 dark:text-slate-400 mb-6">
                          Manage your email identities. Note: You can also use plus addressing (e.g., yourname+tag@domain.com) directly when composing emails or sharing your address.
                        </p>

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
                                      {t(language, 'default')}
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
                    </div>
                  )}

                  {isSettingsSection === 'read' && (
                    <div className="grid gap-6">
                      <div className="bg-white dark:bg-slate-900 p-6 rounded-2xl border border-slate-200 dark:border-slate-800 shadow-sm">
                        <div className="flex items-center gap-3 mb-6">
                          <div className="p-2 bg-indigo-100 dark:bg-indigo-500/10 rounded-xl">
                            <BookOpen className="w-5 h-5 text-indigo-600 dark:text-indigo-400" />
                          </div>
                          <div>
                            <h2 className="text-lg font-bold text-slate-900 dark:text-white">Reading</h2>
                            <p className="text-sm font-medium text-slate-500">Configure how you read your messages</p>
                          </div>
                        </div>

                        <div className="space-y-6">
                          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b border-slate-100 dark:border-slate-800 pb-6">
                            <div className="flex-1 min-w-0 pr-4">
                              <div className="font-bold mb-1">Automatically mark as read</div>
                              <div className="text-slate-500 dark:text-slate-400 text-sm max-w-sm">When should messages be marked as read?</div>
                            </div>
                            <div className="flex bg-slate-100 dark:bg-slate-800 p-1 rounded-xl shrink-0">
                              <button
                                onClick={() => { setReadAutoMark('immediately'); localStorage.setItem('webmail_read_auto_mark', 'immediately'); }}
                                className={cn("px-4 py-2 rounded-lg text-sm font-bold transition-all", readAutoMark === 'immediately' ? "bg-white dark:bg-[#1a1b26] text-indigo-600 shadow-sm" : "text-slate-600 dark:text-slate-400 hover:text-slate-900 dark:hover:text-white")}
                              >
                                Immediately
                              </button>
                              <button
                                onClick={() => { setReadAutoMark('delayed'); localStorage.setItem('webmail_read_auto_mark', 'delayed'); }}
                                className={cn("px-4 py-2 rounded-lg text-sm font-bold transition-all", readAutoMark === 'delayed' ? "bg-white dark:bg-[#1a1b26] text-indigo-600 shadow-sm" : "text-slate-600 dark:text-slate-400 hover:text-slate-900 dark:hover:text-white")}
                              >
                                After 3s
                              </button>
                              <button
                                onClick={() => { setReadAutoMark('never'); localStorage.setItem('webmail_read_auto_mark', 'never'); }}
                                className={cn("px-4 py-2 rounded-lg text-sm font-bold transition-all", readAutoMark === 'never' ? "bg-white dark:bg-[#1a1b26] text-indigo-600 shadow-sm" : "text-slate-600 dark:text-slate-400 hover:text-slate-900 dark:hover:text-white")}
                              >
                                Never
                              </button>
                            </div>
                          </div>

                          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b border-slate-100 dark:border-slate-800 pb-6">
                            <div className="flex-1 min-w-0 pr-4">
                              <div className="font-bold mb-1">Show remote images</div>
                              <div className="text-slate-500 dark:text-slate-400 text-sm max-w-sm">Automatically display external images in emails</div>
                            </div>
                            <button
                              onClick={() => {
                                const newValue = !readShowImages;
                                setReadShowImages(newValue);
                                localStorage.setItem('webmail_read_show_images', newValue.toString());
                              }}
                              className={cn(
                                "relative inline-flex h-8 w-14 items-center rounded-full transition-all shrink-0",
                                readShowImages ? "bg-indigo-600" : "bg-slate-200 dark:bg-slate-700"
                              )}
                            >
                              <span className={cn("inline-block h-6 w-6 transform rounded-full bg-white shadow-md transition-transform duration-200", readShowImages ? "translate-x-7" : "translate-x-1")} />
                            </button>
                          </div>

                          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b border-slate-100 dark:border-slate-800 pb-6">
                            <div className="flex-1 min-w-0 pr-4">
                              <div className="font-bold mb-1">After deleting message</div>
                              <div className="text-slate-500 dark:text-slate-400 text-sm max-w-sm">When viewing an email and deleting it, show the next message</div>
                            </div>
                            <button
                              onClick={() => {
                                const newValue = !readNextOnDelete;
                                setReadNextOnDelete(newValue);
                                localStorage.setItem('webmail_read_next_on_delete', newValue.toString());
                              }}
                              className={cn(
                                "relative inline-flex h-8 w-14 items-center rounded-full transition-all shrink-0",
                                readNextOnDelete ? "bg-indigo-600" : "bg-slate-200 dark:bg-slate-700"
                              )}
                            >
                              <span className={cn("inline-block h-6 w-6 transform rounded-full bg-white shadow-md transition-transform duration-200", readNextOnDelete ? "translate-x-7" : "translate-x-1")} />
                            </button>
                          </div>

                          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b border-slate-100 dark:border-slate-800 pb-6">
                            <div className="flex-1 min-w-0 pr-4">
                              <div className="font-bold mb-1">Delete Action</div>
                              <div className="text-slate-500 dark:text-slate-400 text-sm max-w-sm">Move messages to trash or permanently delete them immediately</div>
                            </div>
                            <div className="flex flex-col gap-2 shrink-0 max-w-[200px] w-full items-end">
                              <select 
                                value={readDeleteAction}
                                onChange={(e) => {
                                  setReadDeleteAction(e.target.value);
                                  localStorage.setItem('webmail_read_delete_action', e.target.value);
                                }}
                                className="w-full px-4 py-2 bg-slate-100 dark:bg-slate-800 border-none rounded-lg text-sm font-bold text-slate-700 dark:text-slate-200 focus:ring-2 focus:ring-indigo-500 outline-none appearance-none cursor-pointer"
                              >
                                <option value="trash">Move to Trash</option>
                                <option value="permanent">Permanently Delete</option>
                              </select>
                              {readDeleteAction === 'permanent' && (
                                <div className="text-[11px] text-red-500 font-bold bg-red-50 dark:bg-red-500/10 px-2 py-1 rounded w-full text-center">
                                  Warning: Cannot be undone
                                </div>
                              )}
                            </div>
                          </div>

                          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b border-slate-100 dark:border-slate-800 pb-6">
                            <div className="flex-1 min-w-0 pr-4">
                              <div className="font-bold mb-1">Archive Mode</div>
                              <div className="text-slate-500 dark:text-slate-400 text-sm max-w-sm">How archived messages are organized</div>
                            </div>
                            <select 
                              value={readArchiveMode}
                              onChange={(e) => {
                                setReadArchiveMode(e.target.value);
                                localStorage.setItem('webmail_read_archive_mode', e.target.value);
                              }}
                              className="px-4 py-2 bg-slate-100 dark:bg-slate-800 border-none rounded-lg text-sm font-bold text-slate-700 dark:text-slate-200 focus:ring-2 focus:ring-indigo-500 outline-none appearance-none cursor-pointer shrink-0 min-w-[150px]"
                            >
                              <option value="single">Single Folder</option>
                              <option value="year">By Year</option>
                              <option value="month">By Month</option>
                            </select>
                          </div>
                          
                          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b border-slate-100 dark:border-slate-800 pb-6">
                            <div className="flex-1 min-w-0 pr-4">
                              <div className="font-bold mb-1">Attachment Click Action</div>
                              <div className="text-slate-500 dark:text-slate-400 text-sm max-w-sm">What happens when you click an attachment</div>
                            </div>
                            <select 
                              value={readAttachmentAction}
                              onChange={(e) => {
                                setReadAttachmentAction(e.target.value);
                                localStorage.setItem('webmail_read_attachment_action', e.target.value);
                              }}
                              className="px-4 py-2 bg-slate-100 dark:bg-slate-800 border-none rounded-lg text-sm font-bold text-slate-700 dark:text-slate-200 focus:ring-2 focus:ring-indigo-500 outline-none appearance-none cursor-pointer shrink-0 min-w-[150px]"
                            >
                              <option value="preview">Preview First</option>
                              <option value="download">Direct Download</option>
                            </select>
                          </div>

                          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b border-slate-100 dark:border-slate-800 pb-6">
                            <div className="flex-1 min-w-0 pr-4">
                              <div className="font-bold mb-1">Emails per page</div>
                              <div className="text-slate-500 dark:text-slate-400 text-sm max-w-sm">Number of emails to load per page</div>
                            </div>
                            <select 
                              value={readEmailsPerPage.toString()}
                              onChange={(e) => {
                                const val = parseInt(e.target.value, 10);
                                setReadEmailsPerPage(val);
                                localStorage.setItem('webmail_read_emails_per_page', val.toString());
                              }}
                              className="px-4 py-2 bg-slate-100 dark:bg-slate-800 border-none rounded-lg text-sm font-bold text-slate-700 dark:text-slate-200 focus:ring-2 focus:ring-indigo-500 outline-none appearance-none cursor-pointer shrink-0 min-w-[150px]"
                            >
                              <option value="10">10 Emails</option>
                              <option value="25">25 Emails</option>
                              <option value="50">50 Emails</option>
                              <option value="100">100 Emails</option>
                            </select>
                          </div>

                          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b border-slate-100 dark:border-slate-800 pb-6">
                            <div className="flex-1 min-w-0 pr-4">
                              <div className="font-bold mb-1">Permanently Delete Junk</div>
                              <div className="text-slate-500 dark:text-slate-400 text-sm max-w-sm">Permanently delete emails from the Junk/Spam folder instead of moving them to Trash</div>
                            </div>
                            <button
                              onClick={() => {
                                const newValue = !readPermanentDeleteJunk;
                                setReadPermanentDeleteJunk(newValue);
                                localStorage.setItem('webmail_read_permanent_delete_junk', newValue.toString());
                              }}
                              className={cn(
                                "relative inline-flex h-8 w-14 items-center rounded-full transition-all shrink-0",
                                readPermanentDeleteJunk ? "bg-indigo-600" : "bg-slate-200 dark:bg-slate-700"
                              )}
                            >
                              <span className={cn("inline-block h-6 w-6 transform rounded-full bg-white shadow-md transition-transform duration-200", readPermanentDeleteJunk ? "translate-x-7" : "translate-x-1")} />
                            </button>
                          </div>

                          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b border-slate-100 dark:border-slate-800 pb-6">
                            <div className="flex-1 min-w-0 pr-4">
                              <div className="font-bold mb-1">Show Preview Text</div>
                              <div className="text-slate-500 dark:text-slate-400 text-sm max-w-sm">Display inline preview text inside the focused one-line message list</div>
                            </div>
                            <button
                              onClick={() => {
                                const newValue = !readShowPreviewText;
                                setReadShowPreviewText(newValue);
                                localStorage.setItem('webmail_read_show_preview_text', newValue.toString());
                              }}
                              className={cn(
                                "relative inline-flex h-8 w-14 items-center rounded-full transition-all shrink-0",
                                readShowPreviewText ? "bg-indigo-600" : "bg-slate-200 dark:bg-slate-700"
                              )}
                            >
                              <span className={cn("inline-block h-6 w-6 transform rounded-full bg-white shadow-md transition-transform duration-200", readShowPreviewText ? "translate-x-7" : "translate-x-1")} />
                            </button>
                          </div>

                          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b border-slate-100 dark:border-slate-800 pb-6">
                            <div className="flex-1 min-w-0 pr-4">
                              <div className="font-bold mb-1">Disable Conversation Grouping</div>
                              <div className="text-slate-500 dark:text-slate-400 text-sm max-w-sm">Show emails as individual messages instead of grouped by conversation</div>
                            </div>
                            <button
                              onClick={() => {
                                const newValue = !readDisableConvGrouping;
                                setReadDisableConvGrouping(newValue);
                                localStorage.setItem('webmail_read_disable_conv_grouping', newValue.toString());
                              }}
                              className={cn(
                                "relative inline-flex h-8 w-14 items-center rounded-full transition-all shrink-0",
                                readDisableConvGrouping ? "bg-indigo-600" : "bg-slate-200 dark:bg-slate-700"
                              )}
                            >
                              <span className={cn("inline-block h-6 w-6 transform rounded-full bg-white shadow-md transition-transform duration-200", readDisableConvGrouping ? "translate-x-7" : "translate-x-1")} />
                            </button>
                          </div>
                          
                          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b border-slate-100 dark:border-slate-800 pb-6">
                            <div className="flex-1 min-w-0 pr-4">
                              <div className="font-bold mb-1">Plain Text Only</div>
                              <div className="text-slate-500 dark:text-slate-400 text-sm max-w-sm">Disable the rich text editor and send all emails as plain text only, including replies and forwards</div>
                            </div>
                            <button
                              onClick={() => {
                                const newValue = !readPlainTextOnly;
                                setReadPlainTextOnly(newValue);
                                localStorage.setItem('webmail_read_plain_text_only', newValue.toString());
                              }}
                              className={cn(
                                "relative inline-flex h-8 w-14 items-center rounded-full transition-all shrink-0",
                                readPlainTextOnly ? "bg-indigo-600" : "bg-slate-200 dark:bg-slate-700"
                              )}
                            >
                              <span className={cn("inline-block h-6 w-6 transform rounded-full bg-white shadow-md transition-transform duration-200", readPlainTextOnly ? "translate-x-7" : "translate-x-1")} />
                            </button>
                          </div>

                          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b border-slate-100 dark:border-slate-800 pb-6">
                            <div className="flex-1 min-w-0 pr-4">
                              <div className="font-bold mb-1">Attachment Position</div>
                              <div className="text-slate-500 dark:text-slate-400 text-sm max-w-sm">Where to display attachments in the email header</div>
                            </div>
                            <select 
                              value={readAttachmentPosition}
                              onChange={(e) => {
                                setReadAttachmentPosition(e.target.value);
                                localStorage.setItem('webmail_read_attachment_position', e.target.value);
                              }}
                              className="px-4 py-2 bg-slate-100 dark:bg-slate-800 border-none rounded-lg text-sm font-bold text-slate-700 dark:text-slate-200 focus:ring-2 focus:ring-indigo-500 outline-none appearance-none cursor-pointer shrink-0 min-w-[150px]"
                            >
                              <option value="below_header">Below header</option>
                              <option value="below_message">Below message</option>
                            </select>
                          </div>

                          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b border-slate-100 dark:border-slate-800 pb-6">
                            <div className="flex-1 min-w-0 pr-4">
                              <div className="font-bold mb-1">Hide inline images from attachments</div>
                              <div className="text-slate-500 dark:text-slate-400 text-sm max-w-sm">Images embedded in the message body are not listed as separate attachments</div>
                            </div>
                            <button
                              onClick={() => {
                                const newValue = !readHideInlineImages;
                                setReadHideInlineImages(newValue);
                                localStorage.setItem('webmail_read_hide_inline_images', newValue.toString());
                              }}
                              className={cn(
                                "relative inline-flex h-8 w-14 items-center rounded-full transition-all shrink-0",
                                readHideInlineImages ? "bg-indigo-600" : "bg-slate-200 dark:bg-slate-700"
                              )}
                            >
                              <span className={cn("inline-block h-6 w-6 transform rounded-full bg-white shadow-md transition-transform duration-200", readHideInlineImages ? "translate-x-7" : "translate-x-1")} />
                            </button>
                          </div>

                          <div className="flex flex-col gap-4 border-b border-slate-100 dark:border-slate-800 pb-6">
                            <div className="flex-1 min-w-0 pr-4">
                              <div className="font-bold mb-1">Quick Hover Actions</div>
                              <div className="text-slate-500 dark:text-slate-400 text-sm max-w-sm mb-4">Choose which quick actions appear when hovering over an email in the list</div>
                            </div>
                            <div className="flex flex-wrap gap-2">
                              {['Delete', 'Star / Unstar', 'Mark Read / Unread', 'Archive', 'Tag', 'Mark as Spam'].map((action) => {
                                const actionKey = action.toLowerCase().replace(/ \/ /g, '_').replace(/ /g, '_');
                                const isSelected = readQuickHoverActions.includes(actionKey);
                                return (
                                  <button
                                    key={actionKey}
                                    onClick={() => {
                                      const newSelection = isSelected 
                                        ? readQuickHoverActions.filter(a => a !== actionKey)
                                        : [...readQuickHoverActions, actionKey];
                                      setReadQuickHoverActions(newSelection);
                                      localStorage.setItem('webmail_read_quick_hover_actions', JSON.stringify(newSelection));
                                    }}
                                    className={cn("px-4 py-2 rounded-lg text-sm font-bold transition-all border", isSelected ? "bg-indigo-600 border-indigo-600 text-white" : "bg-white dark:bg-slate-800 border-slate-200 dark:border-slate-700 text-slate-700 dark:text-slate-300")}
                                  >
                                    {action}
                                  </button>
                                );
                              })}
                            </div>
                          </div>

                          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
                            <div className="flex-1 min-w-0 pr-4">
                              <div className="font-bold mb-1">Display Mode</div>
                              <div className="text-slate-500 dark:text-slate-400 text-sm max-w-sm">How to display the email viewer</div>
                            </div>
                            <div className="flex bg-slate-100 dark:bg-slate-800 p-1 rounded-xl shrink-0">
                              <button
                                onClick={() => { setReadDisplayMode('inline'); localStorage.setItem('webmail_read_display_mode', 'inline'); }}
                                className={cn("px-4 py-2 rounded-lg text-sm font-bold transition-all", readDisplayMode === 'inline' ? "bg-white dark:bg-[#1a1b26] text-indigo-600 shadow-sm" : "text-slate-600 dark:text-slate-400 hover:text-slate-900 dark:hover:text-white")}
                              >
                                Inline
                              </button>
                              <button
                                onClick={() => { setReadDisplayMode('floating'); localStorage.setItem('webmail_read_display_mode', 'floating'); }}
                                className={cn("px-4 py-2 rounded-lg text-sm font-bold transition-all", readDisplayMode === 'floating' ? "bg-white dark:bg-[#1a1b26] text-indigo-600 shadow-sm" : "text-slate-600 dark:text-slate-400 hover:text-slate-900 dark:hover:text-white")}
                              >
                                Floating
                              </button>
                            </div>
                          </div>
                        </div>
                      </div>
                    </div>
                  )}

                  {isSettingsSection === 'compose' && (
                    <div className="grid gap-6">
                      <div className="bg-white dark:bg-slate-900 p-6 rounded-2xl border border-slate-200 dark:border-slate-800 shadow-sm">
                        <div className="flex items-center gap-3 mb-6">
                          <div className="p-2 bg-indigo-100 dark:bg-indigo-500/10 rounded-xl">
                            <Edit3 className="w-5 h-5 text-indigo-600 dark:text-indigo-400" />
                          </div>
                          <div>
                            <h2 className="text-lg font-bold text-slate-900 dark:text-white">Compose</h2>
                            <p className="text-sm font-medium text-slate-500">Configure how you compose messages</p>
                          </div>
                        </div>

                        <div className="space-y-6">
                          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b border-slate-100 dark:border-slate-800 pb-6">
                            <div className="flex-1 min-w-0 pr-4">
                              <div className="font-bold mb-1">Compose Format</div>
                              <div className="text-slate-500 dark:text-slate-400 text-sm max-w-sm">Choose the default format for drafting new emails</div>
                            </div>
                            <select 
                              value={composeFormat}
                              onChange={(e) => {
                                setComposeFormat(e.target.value);
                                localStorage.setItem('webmail_compose_format', e.target.value);
                              }}
                              className="px-4 py-2 bg-slate-50 dark:bg-slate-800 border border-slate-200 dark:border-slate-700 rounded-xl text-slate-900 dark:text-white font-medium focus:ring-2 focus:ring-indigo-500 min-w-[120px]"
                            >
                              <option value="html">Rich Text</option>
                              <option value="markdown">Markdown</option>
                              <option value="plain">Plain Text</option>
                            </select>
                          </div>

                          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b border-slate-100 dark:border-slate-800 pb-6">
                            <div className="flex-1 min-w-0 pr-4">
                              <div className="font-bold mb-1">Undo Send Delay</div>
                              <div className="text-slate-500 dark:text-slate-400 text-sm max-w-sm">Time to wait before actually sending your message</div>
                            </div>
                            <select 
                              value={composeUndoSend.toString()}
                              onChange={(e) => {
                                const val = parseInt(e.target.value, 10);
                                setComposeUndoSend(val);
                                localStorage.setItem('webmail_compose_undo_send', val.toString());
                              }}
                              className="px-4 py-2 bg-slate-50 dark:bg-slate-800 border border-slate-200 dark:border-slate-700 rounded-xl text-slate-900 dark:text-white font-medium focus:ring-2 focus:ring-indigo-500 min-w-[120px]"
                            >
                              <option value="0">Disabled</option>
                              <option value="5">5 seconds</option>
                              <option value="10">10 seconds</option>
                              <option value="30">30 seconds</option>
                            </select>
                          </div>

                          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b border-slate-100 dark:border-slate-800 pb-6">
                            <div className="flex-1 min-w-0 pr-4">
                              <div className="font-bold mb-1">Auto-Save Drafts</div>
                              <div className="text-slate-500 dark:text-slate-400 text-sm max-w-sm">Interval to automatically save drafts as you type</div>
                            </div>
                            <select 
                              value={composeAutoSave.toString()}
                              onChange={(e) => {
                                const val = parseInt(e.target.value, 10);
                                setComposeAutoSave(val);
                                localStorage.setItem('webmail_compose_auto_save', val.toString());
                              }}
                              className="px-4 py-2 bg-slate-50 dark:bg-slate-800 border border-slate-200 dark:border-slate-700 rounded-xl text-slate-900 dark:text-white font-medium focus:ring-2 focus:ring-indigo-500 min-w-[120px]"
                            >
                              <option value="1">Every 1 minute</option>
                              <option value="3">Every 3 minutes</option>
                              <option value="5">Every 5 minutes</option>
                              <option value="10">Every 10 minutes</option>
                            </select>
                          </div>
                          
                          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b border-slate-100 dark:border-slate-800 pb-6">
                            <div className="flex-1 min-w-0 pr-4">
                              <div className="font-bold mb-1">Attachment Reminder</div>
                              <div className="text-slate-500 dark:text-slate-400 text-sm max-w-sm">Warn if message contains keywords like "attached" but has no attachments</div>
                            </div>
                            <button
                                onClick={() => {
                                  const newVal = composeAttachmentReminder === "true" ? "false" : "true";
                                  setComposeAttachmentReminder(newVal);
                                  localStorage.setItem('webmail_compose_attachment_reminder', newVal);
                                }}
                                className={cn(
                                  "relative inline-flex h-8 w-14 items-center rounded-full transition-all shrink-0",
                                  composeAttachmentReminder === "true" ? "bg-indigo-600" : "bg-slate-200 dark:bg-slate-700"
                                )}
                              >
                                <span className={cn("inline-block h-6 w-6 transform rounded-full bg-white shadow-md transition-transform duration-200", composeAttachmentReminder === "true" ? "translate-x-7" : "translate-x-1")} />
                            </button>
                          </div>
                          
                          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
                            <div className="flex-1 min-w-0 pr-4">
                              <div className="font-bold mb-1">Auto-select Reply Identity</div>
                              <div className="text-slate-500 dark:text-slate-400 text-sm max-w-sm">When replying, automatically select the identity that received the message</div>
                            </div>
                            <button
                                onClick={() => {
                                  const newVal = composeAutoSelectIdentity === "true" ? "false" : "true";
                                  setComposeAutoSelectIdentity(newVal);
                                  localStorage.setItem('webmail_compose_auto_select_identity', newVal);
                                }}
                                className={cn(
                                  "relative inline-flex h-8 w-14 items-center rounded-full transition-all shrink-0",
                                  composeAutoSelectIdentity === "true" ? "bg-indigo-600" : "bg-slate-200 dark:bg-slate-700"
                                )}
                              >
                                <span className={cn("inline-block h-6 w-6 transform rounded-full bg-white shadow-md transition-transform duration-200", composeAutoSelectIdentity === "true" ? "translate-x-7" : "translate-x-1")} />
                            </button>
                          </div>

                        </div>
                      </div>
                    </div>
                  )}

                  {isSettingsSection === 'general' && (
                    <div className="grid gap-6">
                      <div className="bg-white dark:bg-slate-900 p-6 rounded-2xl border border-slate-200 dark:border-slate-800 shadow-sm">
                        <div className="flex items-center gap-3 mb-6">
                          <div className="p-2 bg-blue-100 dark:bg-blue-500/10 rounded-xl">
                            <Settings className="w-5 h-5 text-blue-600 dark:text-blue-400" />
                          </div>
                          <h2 className="text-xl font-bold text-slate-900 dark:text-white">{t(language, 'appearance')}</h2>
                        </div>

                        <div className="flex flex-row items-center justify-between gap-4">
                          <div className="flex-1 min-w-0 pr-4">
                            <div className="font-bold text-slate-900 dark:text-white text-lg">{t(language, 'darkMode')}</div>
                            <div className="text-sm text-slate-500 dark:text-slate-400">{t(language, 'darkModeDesc')}</div>
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
                          <h2 className="text-xl font-bold text-slate-900 dark:text-white">{t(language, 'regional')}</h2>
                        </div>

                        <div className="space-y-6">
                          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
                            <span className="text-slate-600 dark:text-slate-400 font-medium tracking-wide">{t(language, 'language')}</span>
                            <div className="relative">
                              <select
                                value={language}
                                onChange={(e) => setLanguage(e.target.value)}
                                className="bg-slate-50 dark:bg-slate-800 border border-slate-200 dark:border-slate-700 rounded-xl px-4 py-2 text-sm font-bold dark:text-white outline-none hover:bg-slate-100 dark:hover:bg-slate-700/50 transition-colors focus:ring-2 focus:ring-indigo-500/20 appearance-none pr-10 w-full max-w-[200px]"
                              >
                                <option value="English (US)">English (US)</option>
                                <option value="English (UK)">English (UK)</option>
                                <option value="Spanish">Spanish</option>
                                <option value="French">French</option>
                                <option value="German">German</option>
                                <option value="Italian">Italian</option>
                                <option value="Chinese">Chinese</option>
                                <option value="Japanese">Japanese</option>
                              </select>
                              <ChevronDown className="absolute right-3 top-1/2 -translate-y-1/2 w-4 h-4 text-slate-400 pointer-events-none" />
                            </div>
                          </div>
                          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
                            <span className="text-slate-600 dark:text-slate-400 font-medium tracking-wide">{t(language, 'timezone')}</span>
                            <div className="relative">
                              <select
                                value={timezone}
                                onChange={(e) => setTimezone(e.target.value)}
                                className="bg-slate-50 dark:bg-slate-800 border border-slate-200 dark:border-slate-700 rounded-xl px-4 py-2 text-sm font-bold dark:text-white outline-none hover:bg-slate-100 dark:hover:bg-slate-700/50 transition-colors focus:ring-2 focus:ring-indigo-500/20 appearance-none pr-10 w-full max-w-[200px]"
                              >
                                {(['America/Los_Angeles', 'America/Denver', 'America/Chicago', 'America/New_York', 'America/Sao_Paulo', 'Europe/London', 'Europe/Paris', 'Europe/Berlin', 'Europe/Moscow', 'Africa/Cairo', 'Africa/Johannesburg', 'Asia/Dubai', 'Asia/Karachi', 'Asia/Kolkata', 'Asia/Bangkok', 'Asia/Singapore', 'Asia/Tokyo', 'Australia/Sydney', 'Pacific/Auckland', 'UTC'].includes(Intl.DateTimeFormat().resolvedOptions().timeZone) ? 
                                  ['America/Los_Angeles', 'America/Denver', 'America/Chicago', 'America/New_York', 'America/Sao_Paulo', 'Europe/London', 'Europe/Paris', 'Europe/Berlin', 'Europe/Moscow', 'Africa/Cairo', 'Africa/Johannesburg', 'Asia/Dubai', 'Asia/Karachi', 'Asia/Kolkata', 'Asia/Bangkok', 'Asia/Singapore', 'Asia/Tokyo', 'Australia/Sydney', 'Pacific/Auckland', 'UTC'] :
                                  Array.from(new Set([Intl.DateTimeFormat().resolvedOptions().timeZone, 'America/Los_Angeles', 'America/Denver', 'America/Chicago', 'America/New_York', 'America/Sao_Paulo', 'Europe/London', 'Europe/Paris', 'Europe/Berlin', 'Europe/Moscow', 'Africa/Cairo', 'Africa/Johannesburg', 'Asia/Dubai', 'Asia/Karachi', 'Asia/Kolkata', 'Asia/Bangkok', 'Asia/Singapore', 'Asia/Tokyo', 'Australia/Sydney', 'Pacific/Auckland', 'UTC']))
                                ).map(tz => (
                                  <option key={tz} value={tz}>
                                    {tz === 'UTC' ? 'UTC (Coordinated Universal Time)' : tz.replace(/_/g, ' ')}
                                  </option>
                                ))}
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
                      {/* Notification Sound */}
                      <div className="bg-white dark:bg-[#0b0c10] p-6 rounded-2xl border border-slate-200 dark:border-slate-800 shadow-sm">
                        <div className="flex flex-col gap-1 mb-6">
                          <h2 className="text-xl font-bold text-slate-900 dark:text-white">Notification Sound</h2>
                          <div className="text-sm text-slate-500 dark:text-slate-400">Choose which sound to play for notifications</div>
                        </div>

                        <div className="flex flex-row items-center justify-between gap-4">
                          <div className="font-medium text-slate-900 dark:text-white text-[15px]">Sound</div>
                          <div className="flex items-center gap-2">
                            <select 
                              value={notificationTone}
                              onChange={(e) => {
                                setNotificationTone(e.target.value);
                                localStorage.setItem('webmail_notification_tone', e.target.value);
                              }}
                              className="bg-slate-50 dark:bg-[#14151a] border border-slate-200 dark:border-slate-800 text-slate-900 dark:text-white text-sm rounded-xl focus:ring-indigo-500 focus:border-indigo-500 block p-2.5 outline-none font-medium"
                            >
                              <option value="relax">Relax</option>
                              <option value="chime">Chime</option>
                              <option value="ding">Ding</option>
                            </select>
                            <button 
                              onClick={() => {
                                const audio = getNotificationAudio();
                                audio.volume = 0.8;
                                audio.play().catch(e => console.log("Audio play blocked", e));
                              }}
                              className="p-2.5 rounded-xl hover:bg-slate-100 dark:hover:bg-slate-800 text-slate-600 dark:text-slate-400 hover:text-indigo-600 dark:hover:text-indigo-400 transition-colors border border-slate-200 dark:border-slate-800 bg-slate-50 dark:bg-[#14151a]"
                              title="Play sound"
                            >
                              <Bell className="w-4 h-4" />
                            </button>
                          </div>
                        </div>
                        <div className="text-xs text-slate-500 mt-2">Select a notification tone and click the speaker icon to preview it</div>
                      </div>

                      {/* Email Notifications */}
                      <div className="bg-white dark:bg-[#0b0c10] p-6 rounded-2xl border border-slate-200 dark:border-slate-800 shadow-sm">
                        <div className="flex flex-col gap-1 mb-6">
                          <h2 className="text-xl font-bold text-slate-900 dark:text-white">Email Notifications</h2>
                          <div className="text-sm text-slate-500 dark:text-slate-400">Configure notifications for incoming emails</div>
                        </div>

                        <div className="space-y-6">
                          <div className="flex flex-row items-center justify-between gap-4">
                            <div className="flex-1 min-w-0 pr-4">
                              <div className="font-medium text-slate-900 dark:text-white text-[15px]">Email notifications</div>
                              <div className="text-sm text-slate-500 dark:text-slate-400">Show notifications when new emails arrive</div>
                            </div>
                            <button 
                              onClick={async () => {
                                const newValue = !emailNotificationsEnabled;
                                if (newValue) {
                                  if (!("Notification" in window)) {
                                    toast.error("This browser does not support desktop notifications.");
                                    return;
                                  }
                                  
                                  try {
                                    const perm = await Notification.requestPermission();
                                    if (perm === 'granted') {
                                      setEmailNotificationsEnabled(true);
                                      localStorage.setItem('webmail_email_notifications', 'true');
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
                                  setEmailNotificationsEnabled(false);
                                  localStorage.setItem('webmail_email_notifications', 'false');
                                }
                              }}
                              className={cn(
                                "relative inline-flex h-8 w-14 items-center rounded-full transition-all shrink-0",
                                emailNotificationsEnabled ? "bg-indigo-600" : "bg-slate-200 dark:bg-slate-700"
                              )}
                            >
                              <span className={cn("inline-block h-6 w-6 transform rounded-full bg-white shadow-md transition-transform duration-200", emailNotificationsEnabled ? "translate-x-7" : "translate-x-1")} />
                            </button>
                          </div>

                          <div className="flex flex-row items-center justify-between gap-4">
                            <div className="flex-1 min-w-0 pr-4">
                              <div className="font-medium text-slate-900 dark:text-white text-[15px]">Notification sound</div>
                              <div className="text-sm text-slate-500 dark:text-slate-400">Play an audio alert when new emails arrive</div>
                            </div>
                            <button 
                              onClick={() => {
                                const newValue = !emailSoundEnabled;
                                setEmailSoundEnabled(newValue);
                                localStorage.setItem('webmail_email_sound', newValue.toString());
                              }}
                              className={cn(
                                "relative inline-flex h-8 w-14 items-center rounded-full transition-all shrink-0",
                                emailSoundEnabled ? "bg-indigo-600" : "bg-slate-200 dark:bg-slate-700"
                              )}
                            >
                              <span className={cn("inline-block h-6 w-6 transform rounded-full bg-white shadow-md transition-transform duration-200", emailSoundEnabled ? "translate-x-7" : "translate-x-1")} />
                            </button>
                          </div>
                        </div>
                      </div>

                      {/* Calendar Notifications */}
                      <div className="bg-white dark:bg-[#0b0c10] p-6 rounded-2xl border border-slate-200 dark:border-slate-800 shadow-sm">
                        <div className="flex flex-col gap-1 mb-6">
                          <h2 className="text-xl font-bold text-slate-900 dark:text-white">Calendar Notifications</h2>
                          <div className="text-sm text-slate-500 dark:text-slate-400">Configure notifications for calendar events</div>
                        </div>

                        <div className="space-y-6">
                          <div className="flex flex-row items-center justify-between gap-4">
                            <div className="flex-1 min-w-0 pr-4">
                              <div className="font-medium text-slate-900 dark:text-white text-[15px]">Event notifications</div>
                              <div className="text-sm text-slate-500 dark:text-slate-400">Show alerts for upcoming calendar events</div>
                            </div>
                            <button 
                              onClick={async () => {
                                const newValue = !calendarNotificationsEnabled;
                                if (newValue) {
                                  if (!("Notification" in window)) {
                                    toast.error("This browser does not support desktop notifications.");
                                    return;
                                  }
                                  
                                  try {
                                    const perm = await Notification.requestPermission();
                                    if (perm === 'granted') {
                                      setCalendarNotificationsEnabled(true);
                                      localStorage.setItem('webmail_calendar_notifications', 'true');
                                      toast.success("Calendar notifications enabled!");
                                    } else {
                                      toast.error("Notification permission denied.");
                                    }
                                  } catch (err) {
                                    toast.error("Could not request notification permission.");
                                  }
                                } else {
                                  setCalendarNotificationsEnabled(false);
                                  localStorage.setItem('webmail_calendar_notifications', 'false');
                                }
                              }}
                              className={cn(
                                "relative inline-flex h-8 w-14 items-center rounded-full transition-all shrink-0",
                                calendarNotificationsEnabled ? "bg-indigo-600" : "bg-slate-200 dark:bg-slate-700"
                              )}
                            >
                              <span className={cn("inline-block h-6 w-6 transform rounded-full bg-white shadow-md transition-transform duration-200", calendarNotificationsEnabled ? "translate-x-7" : "translate-x-1")} />
                            </button>
                          </div>

                          <div className="flex flex-row items-center justify-between gap-4">
                            <div className="flex-1 min-w-0 pr-4">
                              <div className="font-medium text-slate-900 dark:text-white text-[15px]">Notification sound</div>
                              <div className="text-sm text-slate-500 dark:text-slate-400">Play an audio alert for calendar reminders</div>
                            </div>
                            <button 
                              onClick={() => {
                                const newValue = !calendarSoundEnabled;
                                setCalendarSoundEnabled(newValue);
                                localStorage.setItem('webmail_calendar_sound', newValue.toString());
                              }}
                              className={cn(
                                "relative inline-flex h-8 w-14 items-center rounded-full transition-all shrink-0",
                                calendarSoundEnabled ? "bg-indigo-600" : "bg-slate-200 dark:bg-slate-700"
                              )}
                            >
                              <span className={cn("inline-block h-6 w-6 transform rounded-full bg-white shadow-md transition-transform duration-200", calendarSoundEnabled ? "translate-x-7" : "translate-x-1")} />
                            </button>
                          </div>

                          <div className="flex flex-row items-center justify-between gap-4">
                            <div className="flex-1 min-w-0 pr-4">
                              <div className="font-medium text-slate-900 dark:text-white text-[15px]">Parse email invitations</div>
                              <div className="text-sm text-slate-500 dark:text-slate-400">Detect calendar invitations in email attachments and show calendar actions</div>
                            </div>
                            <button 
                              onClick={() => {
                                const newValue = !parseEmailInvitations;
                                setParseEmailInvitations(newValue);
                                localStorage.setItem('webmail_parse_invitations', newValue.toString());
                              }}
                              className={cn(
                                "relative inline-flex h-8 w-14 items-center rounded-full transition-all shrink-0",
                                parseEmailInvitations ? "bg-indigo-600" : "bg-slate-200 dark:bg-slate-700"
                              )}
                            >
                              <span className={cn("inline-block h-6 w-6 transform rounded-full bg-white shadow-md transition-transform duration-200", parseEmailInvitations ? "translate-x-7" : "translate-x-1")} />
                            </button>
                          </div>
                        </div>

                      </div>
                    </div>
                  )}

                  {isSettingsSection === 'vacation' && (
                    <div className="bg-white dark:bg-slate-900 p-6 rounded-2xl border border-slate-200 dark:border-slate-800 shadow-sm relative overflow-hidden">
                      <div className="absolute top-0 right-0 w-32 h-32 bg-indigo-500/5 rounded-full -mr-16 -mt-16" />
                      
                      <div className="flex items-center gap-3 mb-6">
                        <div className="p-2 bg-indigo-100 dark:bg-indigo-500/10 rounded-xl">
                          <Reply className="w-5 h-5 text-indigo-600 dark:text-indigo-400" />
                        </div>
                        <h2 className="text-xl font-bold text-slate-900 dark:text-white">{t(language, 'autoResponder')}</h2>
                      </div>
                      
                      <div className="flex flex-row items-center justify-between mb-8 p-4 bg-slate-50 dark:bg-slate-800/50 rounded-2xl gap-4">
                        <div className="flex-1 min-w-0 pr-4">
                          <div className="font-bold text-slate-900 dark:text-white text-lg">{t(language, 'enableAutoReply')}</div>
                          <div className="text-sm text-slate-500 dark:text-slate-400">{t(language, 'automaticallyReply')}</div>
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
                          <label className="text-sm font-bold text-slate-700 dark:text-slate-300 ml-1">{t(language, 'subject')}</label>
                          <input 
                            type="text"
                            value={vacationSubject}
                            onChange={(e) => setVacationSubject(e.target.value)}
                            className="w-full bg-slate-50 dark:bg-slate-800 border border-slate-200 dark:border-slate-700 rounded-2xl px-5 py-4 text-sm font-medium outline-none focus:ring-2 focus:ring-indigo-500/20 focus:border-indigo-500 dark:text-white transition-all min-h-[50px] appearance-none"
                            placeholder={t(language, 'outOfOffice')}
                          />
                        </div>
                        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                          <div className="space-y-2">
                            <label className="text-sm font-bold text-slate-700 dark:text-slate-300 ml-1">{t(language, 'startDateOptional')}</label>
                            <input 
                              type="datetime-local"
                              value={vacationFromDate}
                              onChange={(e) => setVacationFromDate(e.target.value)}
                              className="w-full bg-slate-50 dark:bg-slate-800 border border-slate-200 dark:border-slate-700 rounded-2xl px-5 py-4 text-sm font-medium outline-none focus:ring-2 focus:ring-indigo-500/20 focus:border-indigo-500 dark:text-white transition-all min-h-[50px] appearance-none"
                            />
                          </div>
                          <div className="space-y-2">
                            <label className="text-sm font-bold text-slate-700 dark:text-slate-300 ml-1">{t(language, 'endDateOptional')}</label>
                            <input 
                              type="datetime-local"
                              value={vacationToDate}
                              onChange={(e) => setVacationToDate(e.target.value)}
                              className="w-full bg-slate-50 dark:bg-slate-800 border border-slate-200 dark:border-slate-700 rounded-2xl px-5 py-4 text-sm font-medium outline-none focus:ring-2 focus:ring-indigo-500/20 focus:border-indigo-500 dark:text-white transition-all min-h-[50px] appearance-none"
                            />
                          </div>
                        </div>
                        <div className="space-y-2">
                          <label className="text-sm font-bold text-slate-700 dark:text-slate-300 ml-1">{t(language, 'body')}</label>
                          <textarea 
                            value={vacationText}
                            onChange={(e) => setVacationText(e.target.value)}
                            className="w-full h-48 bg-slate-50 dark:bg-slate-800 border border-slate-200 dark:border-slate-700 rounded-2xl px-5 py-4 text-sm font-medium outline-none focus:ring-2 focus:ring-indigo-500/20 focus:border-indigo-500 dark:text-white transition-all resize-none"
                            placeholder={t(language, 'iAmCurrentlyAway')}
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
                                  ...(/<[a-z][\s\S]*>/i.test(vacationText) ? { htmlBody: vacationText } : { textBody: vacationText }),
                                  fromDate: vacationFromDate || null,
                                  toDate: vacationToDate || null
                                });
                                toast.success("Vacation responder updated!");
                              } catch (e) {
                                toast.error("Failed to save vacation responder.");
                              } finally {
                                setIsSavingVacation(false);
                              }
                            }}
                            disabled={isSavingVacation}
                            className={cn("w-full sm:w-auto px-8 py-4 disabled:opacity-50 text-white font-bold rounded-2xl shadow-lg flex items-center justify-center gap-2 transition-all active:scale-[0.98]",
                              vacationEnabled ? "bg-indigo-600 hover:bg-indigo-700 shadow-indigo-600/20" : "bg-slate-300 dark:bg-slate-700 text-slate-500 shadow-none hover:bg-slate-400 dark:hover:bg-slate-600"
                            )}
                          >
                            {isSavingVacation ? <Loader2 className="w-5 h-5 animate-spin" /> : <MailCheck className="w-5 h-5" />}
                            {t(language, 'updateResponder')}
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

                  {isSettingsSection === 'tags' && (
                    <div className="bg-white dark:bg-slate-900 p-6 rounded-xl border border-slate-200 dark:border-slate-800 shadow-sm max-w-2xl">
                      <h2 className="text-xl font-bold text-slate-900 dark:text-white mb-2">
                        Email Tags
                      </h2>
                      <p className="text-slate-500 dark:text-slate-400 mb-6 leading-relaxed">
                        Define tags to organize your emails with colors. These are stored as JMAP keywords on the server.
                      </p>
                      
                      <div className="space-y-3 mb-8">
                        {allTags.map((tag) => (
                          <div key={tag.keyword} className="flex items-center p-4 bg-slate-50 dark:bg-black/40 rounded-xl border border-slate-200 dark:border-slate-800/60">
                            <div className={`w-6 h-6 rounded-full flex items-center justify-center mr-4 shrink-0 ${tag.color} text-white font-bold text-[10px]`} style={{ backgroundColor: tag.color.startsWith('#') ? tag.color : undefined }}>
                              {tag.name}
                            </div>
                            <div className="font-mono text-sm text-slate-600 dark:text-slate-300">
                              {tag.keyword}
                            </div>
                          </div>
                        ))}
                      </div>

                      <div className="flex gap-4">
                        <button 
                          onClick={() => setIsAddTagModalOpen(true)}
                          className="px-5 py-2.5 bg-slate-100 dark:bg-slate-800/80 text-slate-700 dark:text-slate-300 font-bold rounded-xl hover:bg-slate-200 dark:hover:bg-slate-700 transition-all flex items-center gap-2 border border-slate-200 dark:border-slate-700"
                        >
                          <Plus className="w-4 h-4" /> Add Tag
                        </button>
                        <button 
                          onClick={() => {
                            if (window.confirm("Are you sure you want to remove all custom tags?")) {
                              setCustomTags([]);
                              localStorage.removeItem('webmail_custom_tags');
                            }
                          }}
                          className="px-5 py-2.5 bg-slate-100 dark:bg-slate-800/80 text-slate-700 dark:text-slate-300 font-bold rounded-xl hover:bg-slate-200 dark:hover:bg-slate-700 transition-all flex items-center gap-2 border border-slate-200 dark:border-slate-700"
                        >
                          <RefreshCw className="w-4 h-4" /> Clear Custom Tags
                        </button>
                      </div>

                      {isAddTagModalOpen && (
                        <div className="fixed inset-0 z-50 flex items-center justify-center">
                          <div className="fixed inset-0 bg-black/50 backdrop-blur-sm" onClick={() => setIsAddTagModalOpen(false)} />
                          <div className="relative bg-white dark:bg-slate-900 rounded-3xl p-6 shadow-2xl max-w-sm w-full mx-4 border border-slate-200 dark:border-slate-800">
                            <h3 className="text-xl font-bold text-slate-900 dark:text-white mb-4">Add Custom Tag</h3>
                            
                            <div className="space-y-4 mb-6">
                              <div>
                                <label className="text-sm font-bold text-slate-500 mb-1 block">Tag Name</label>
                                <input
                                  type="text"
                                  value={newTagName}
                                  onChange={(e) => setNewTagName(e.target.value)}
                                  className="w-full px-4 py-3 bg-slate-50 dark:bg-slate-800 border-none focus:ring-2 focus:ring-indigo-500/20 rounded-xl text-sm outline-none transition-all dark:text-white"
                                  placeholder="e.g. Work, Urgent"
                                />
                              </div>
                              <div>
                                <label className="text-sm font-bold text-slate-500 mb-1 block">Color</label>
                                <div className="flex gap-2 items-center">
                                  <input 
                                    type="color"
                                    value={newTagColor}
                                    onChange={(e) => setNewTagColor(e.target.value)}
                                    className="w-12 h-12 rounded-xl border-none cursor-pointer p-0 bg-transparent"
                                  />
                                  <span className="font-mono text-sm dark:text-white">{newTagColor}</span>
                                </div>
                              </div>
                            </div>
                            
                            <div className="flex gap-3">
                              <button
                                onClick={() => setIsAddTagModalOpen(false)}
                                className="flex-1 px-4 py-3 bg-slate-100 dark:bg-slate-800 text-slate-600 dark:text-slate-300 font-bold rounded-xl transition-colors hover:bg-slate-200 dark:hover:bg-slate-700"
                              >
                                Cancel
                              </button>
                              <button
                                onClick={() => {
                                  if (!newTagName.trim()) return;
                                  const keyword = `$label:${newTagName.trim().toLowerCase().replace(/\s+/g, '-')}`;
                                  
                                  const newTag = { keyword, name: newTagName.trim(), color: newTagColor };
                                  const updated = [...customTags, newTag];
                                  setCustomTags(updated);
                                  localStorage.setItem('webmail_custom_tags', JSON.stringify(updated));
                                  
                                  setNewTagName('');
                                  setIsAddTagModalOpen(false);
                                }}
                                disabled={!newTagName.trim()}
                                className="flex-1 px-4 py-3 bg-indigo-600 text-white font-bold rounded-xl transition-colors hover:bg-indigo-700 disabled:opacity-50 disabled:cursor-not-allowed"
                              >
                                Add Tag
                              </button>
                            </div>
                          </div>
                        </div>
                      )}
                    </div>
                  )}

                  {isSettingsSection === 'contacts' && (
                    <div className="grid gap-8">
                      <div className="bg-white dark:bg-slate-900 rounded-2xl border border-slate-200 dark:border-slate-800 shadow-sm overflow-hidden text-slate-900 dark:text-white pb-6">
                        <div className="p-6">
                          <h2 className="text-xl font-bold mb-4">Export Contacts</h2>
                          <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 border-b border-slate-200 dark:border-slate-800 pb-8">
                            <p className="text-slate-500 dark:text-slate-400 max-w-sm text-sm">
                              Export all contacts as a vCard (.vcf) file
                            </p>
                            <button 
                              onClick={handleExportContacts}
                              disabled={isLoading}
                              className="px-6 py-2 border border-slate-200 dark:border-slate-700 text-slate-700 dark:text-slate-200 font-bold rounded-lg hover:bg-slate-50 dark:hover:bg-slate-800 transition-all flex items-center shrink-0 justify-center gap-2 bg-transparent"
                            >
                              <Download className="w-5 h-5" /> Export Contacts
                            </button>
                          </div>
                          
                          <div className="pt-8 w-full border-b border-slate-200 dark:border-slate-800 pb-8">
                            <h2 className="text-xl font-bold mb-2">Address Books</h2>
                            <p className="text-slate-500 dark:text-slate-400 mb-6 text-sm">Rename your address books</p>
                            
                            <div className="border border-slate-200 dark:border-slate-700 rounded-xl p-4 flex items-center justify-between hover:bg-slate-50 dark:hover:bg-slate-800/50 cursor-pointer">
                              <div className="flex items-center gap-4">
                                <Folder className="w-5 h-5 text-slate-400" />
                                <span className="font-bold">Stalwart Ad... <span className="bg-slate-100 dark:bg-slate-800 text-slate-500 dark:text-slate-400 px-3 py-1 rounded-full text-xs font-semibold ml-2">Default</span></span>
                              </div>
                            </div>
                          </div>

                          <div className="pt-8">
                            <h2 className="text-xl font-bold mb-2">Categories</h2>
                            <p className="text-slate-500 dark:text-slate-400 mb-6 text-sm">Rename contact categories</p>
                            <p className="text-slate-600 dark:text-slate-400 text-sm">No categories found</p>
                          </div>
                        </div>
                      </div>
                    </div>
                  )}

                  {isSettingsSection === 'calendar' && (
                    <div className="grid gap-6">
                      <div className="bg-white dark:bg-slate-900 p-6 rounded-2xl border border-slate-200 dark:border-slate-800 shadow-sm">
                        <div className="flex items-center gap-3 mb-6">
                          <div className="p-2 bg-indigo-100 dark:bg-indigo-500/10 rounded-xl">
                            <Calendar className="w-5 h-5 text-indigo-600 dark:text-indigo-400" />
                          </div>
                          <h2 className="text-xl font-bold text-slate-900 dark:text-white">Calendar View</h2>
                        </div>
                        
                        <div className="space-y-6">
                          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 border-b border-slate-100 dark:border-slate-800 pb-6">
                            <span className="text-slate-600 dark:text-slate-400 font-medium tracking-wide">Default view</span>
                            <select 
                              value={calDefaultView}
                              onChange={(e) => {
                                setCalDefaultView(e.target.value);
                                localStorage.setItem('webmail_cal_default_view', e.target.value);
                              }}
                              className="bg-transparent border border-slate-200 dark:border-slate-700 rounded-lg px-4 py-2 font-medium text-slate-700 dark:text-white flex items-center focus:outline-none focus:ring-2 focus:ring-indigo-500 [&>option]:bg-white dark:[&>option]:bg-slate-900"
                            >
                              <option value="Day">Day</option>
                              <option value="Week">Week</option>
                              <option value="Month">Month</option>
                              <option value="Agenda">Agenda</option>
                            </select>
                          </div>

                          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 border-b border-slate-100 dark:border-slate-800 pb-6">
                            <span className="text-slate-600 dark:text-slate-400 font-medium tracking-wide">Time format</span>
                            <select 
                              value={calTimeFormat}
                              onChange={(e) => {
                                setCalTimeFormat(e.target.value);
                                localStorage.setItem('webmail_cal_time_format', e.target.value);
                              }}
                              className="bg-transparent border border-slate-200 dark:border-slate-700 rounded-lg px-4 py-2 font-medium text-slate-700 dark:text-white flex items-center focus:outline-none focus:ring-2 focus:ring-indigo-500 [&>option]:bg-white dark:[&>option]:bg-slate-900"
                            >
                              <option value="12-hour">12-hour (1:00 PM)</option>
                              <option value="24-hour">24-hour (13:00)</option>
                            </select>
                          </div>

                          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
                            <span className="text-slate-600 dark:text-slate-400 font-medium tracking-wide">Week starts on</span>
                            <select 
                              value={calWeekStartsOn}
                              onChange={(e) => {
                                setCalWeekStartsOn(e.target.value);
                                localStorage.setItem('webmail_cal_week_starts', e.target.value);
                              }}
                              className="bg-transparent border border-slate-200 dark:border-slate-700 rounded-lg px-4 py-2 font-medium text-slate-700 dark:text-white flex items-center focus:outline-none focus:ring-2 focus:ring-indigo-500 [&>option]:bg-white dark:[&>option]:bg-slate-900"
                            >
                              <option value="Monday">Monday</option>
                              <option value="Sunday">Sunday</option>
                            </select>
                          </div>
                        </div>
                      </div>

                      <div className="bg-white dark:bg-slate-900 p-6 rounded-2xl border border-slate-200 dark:border-slate-800 shadow-sm">
                        <div className="flex items-center gap-3 mb-6">
                          <div className="p-2 bg-purple-100 dark:bg-purple-500/10 rounded-xl">
                            <Settings className="w-5 h-5 text-purple-600 dark:text-purple-400" />
                          </div>
                          <h2 className="text-xl font-bold text-slate-900 dark:text-white">Events & Preferences</h2>
                        </div>
                        
                        <div className="space-y-6">
                          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b border-slate-100 dark:border-slate-800 pb-6">
                            <div className="flex-1 min-w-0 pr-4">
                              <div className="font-bold mb-1">Show time in month view</div>
                              <div className="text-slate-500 dark:text-slate-400 text-sm max-w-sm">Display event times in the month calendar view</div>
                            </div>
                            <button
                              onClick={() => {
                                const newValue = !calShowTimeInMonth;
                                setCalShowTimeInMonth(newValue);
                                localStorage.setItem('webmail_cal_show_time', newValue.toString());
                              }}
                              className={cn(
                                "relative inline-flex h-8 w-14 items-center rounded-full transition-all shrink-0",
                                calShowTimeInMonth ? "bg-indigo-600" : "bg-slate-200 dark:bg-slate-700"
                              )}
                            >
                              <span className={cn("inline-block h-6 w-6 transform rounded-full bg-white shadow-md transition-transform duration-200", calShowTimeInMonth ? "translate-x-7" : "translate-x-1")} />
                            </button>
                          </div>

                          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b border-slate-100 dark:border-slate-800 pb-6">
                            <div className="flex-1 min-w-0 pr-4">
                              <div className="font-bold mb-1">Show week numbers</div>
                              <div className="text-slate-500 dark:text-slate-400 text-sm max-w-sm">Display week numbers in the mini-calendar</div>
                            </div>
                            <button
                              onClick={() => {
                                const newValue = !calShowWeekNumbers;
                                setCalShowWeekNumbers(newValue);
                                localStorage.setItem('webmail_cal_week_numbers', newValue.toString());
                              }}
                              className={cn(
                                "relative inline-flex h-8 w-14 items-center rounded-full transition-all shrink-0",
                                calShowWeekNumbers ? "bg-indigo-600" : "bg-slate-200 dark:bg-slate-700"
                              )}
                            >
                              <span className={cn("inline-block h-6 w-6 transform rounded-full bg-white shadow-md transition-transform duration-200", calShowWeekNumbers ? "translate-x-7" : "translate-x-1")} />
                            </button>
                          </div>

                          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b border-slate-100 dark:border-slate-800 pb-6">
                            <div className="flex-1 min-w-0 pr-4">
                              <div className="font-bold mb-1">Compact Month View</div>
                              <div className="text-slate-500 dark:text-slate-400 text-sm max-w-sm">Show colored dots instead of full event banners in month view</div>
                            </div>
                            <button
                              onClick={() => {
                                const newValue = !calCompactMonthView;
                                setCalCompactMonthView(newValue);
                                localStorage.setItem('webmail_cal_month_compact', newValue.toString());
                              }}
                              className={cn(
                                "relative inline-flex h-8 w-14 items-center rounded-full transition-all shrink-0",
                                calCompactMonthView ? "bg-indigo-600" : "bg-slate-200 dark:bg-slate-700"
                              )}
                            >
                              <span className={cn("inline-block h-6 w-6 transform rounded-full bg-white shadow-md transition-transform duration-200", calCompactMonthView ? "translate-x-7" : "translate-x-1")} />
                            </button>
                          </div>
                          
                          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b border-slate-100 dark:border-slate-800 pb-6">
                            <div className="flex-1 min-w-0 pr-4">
                              <div className="font-bold mb-1">Event hover preview</div>
                              <div className="text-slate-500 dark:text-slate-400 text-sm">Show a detail popover when hovering over calendar events</div>
                            </div>
                            <select 
                              value={calEventHoverPreview}
                              onChange={(e) => {
                                setCalEventHoverPreview(e.target.value);
                                localStorage.setItem('webmail_cal_hover', e.target.value);
                              }}
                              className="bg-transparent border border-slate-200 dark:border-slate-700 rounded-lg px-4 py-2 font-medium text-slate-700 dark:text-white flex items-center focus:outline-none focus:ring-2 focus:ring-indigo-500 [&>option]:bg-white dark:[&>option]:bg-slate-900"
                            >
                              <option value="Always">No delay</option>
                              <option value="0.5s">0.5-second delay</option>
                              <option value="Disabled">Disabled</option>
                            </select>
                          </div>
                          
                          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
                            <div className="flex-1 min-w-0 pr-4">
                              <div className="font-bold mb-1">Contact birthday calendar</div>
                              <div className="text-slate-500 dark:text-slate-400 text-sm max-w-sm">Show a virtual calendar with birthdays from your contacts</div>
                            </div>
                            <button
                              onClick={() => {
                                const newValue = !calContactBirthday;
                                setCalContactBirthday(newValue);
                                localStorage.setItem('webmail_cal_birthday', newValue.toString());
                              }}
                              className={cn(
                                "relative inline-flex h-8 w-14 items-center rounded-full transition-all shrink-0",
                                calContactBirthday ? "bg-indigo-600" : "bg-slate-200 dark:bg-slate-700"
                              )}
                            >
                              <span className={cn("inline-block h-6 w-6 transform rounded-full bg-white shadow-md transition-transform duration-200", calContactBirthday ? "translate-x-7" : "translate-x-1")} />
                            </button>
                          </div>
                        </div>
                      </div>

                      <div className="bg-white dark:bg-slate-900 p-6 rounded-2xl border border-slate-200 dark:border-slate-800 shadow-sm">
                        <div className="flex items-center gap-3 mb-6">
                          <div className="p-2 bg-pink-100 dark:bg-pink-500/10 rounded-xl">
                            <Calendar className="w-5 h-5 text-pink-600 dark:text-pink-400" />
                          </div>
                          <h2 className="text-xl font-bold text-slate-900 dark:text-white">Calendars</h2>
                        </div>
                        <p className="text-slate-500 dark:text-slate-400 text-[13px] md:text-sm font-medium mb-6">Create, rename, and customize your calendars. Right-click a calendar in the sidebar to quickly change its color.</p>
                        
                        <div className="space-y-3 mb-6">
                          {calendars && calendars.filter((c: any) => !icalSubscriptions.some(sub => sub.calendarId === c.id)).map((cal, idx) => (
                            <div key={idx} className="flex flex-col sm:flex-row sm:items-center justify-between p-4 bg-slate-50 dark:bg-[#111111] rounded-xl border border-slate-100 dark:border-[#222222]">
                              <div className="flex items-center gap-3 mb-3 sm:mb-0">
                                <div className="w-5 h-5 rounded-full flex items-center justify-center shrink-0" style={{ backgroundColor: cal.color || '#4f46e5' }}></div>
                                <Calendar className="w-5 h-5 text-slate-400" />
                                <span className="font-bold text-slate-700 dark:text-slate-200">{cal.name}</span>
                                {idx === 0 && <span className="ml-2 px-2 py-0.5 bg-slate-200 dark:bg-slate-800 text-slate-600 dark:text-slate-400 text-[10px] font-bold rounded-full uppercase tracking-wider">Default</span>}
                              </div>
                              <div className="flex items-center gap-1 sm:gap-2">
                                <button
                                  className="p-2 text-slate-400 hover:text-slate-600 dark:hover:text-slate-300 rounded-lg transition-colors"
                                  title="Share link"
                                >
                                  <Link className="w-4 h-4" />
                                </button>
                                <button
                                  className="p-2 text-slate-400 hover:text-slate-600 dark:hover:text-slate-300 rounded-lg transition-colors"
                                  title="Copy link"
                                >
                                  <Copy className="w-4 h-4" />
                                </button>
                                <button
                                  onClick={async () => {
                                    if(confirm('Are you sure you want to delete this calendar?')) {
                                      try {
                                        const client = new JmapClient(credentials);
                                        await client.deleteCalendar(cal.id);
                                        toast.success("Calendar deleted");
                                        setCalendars(await client.getCalendars());
                                      } catch (err: any) {
                                        toast.error(err.message || 'Failed to delete calendar');
                                      }
                                    }
                                  }}
                                  className="p-2 text-slate-400 hover:text-red-500 rounded-lg transition-colors"
                                  title="Delete calendar"
                                >
                                  <Trash2 className="w-4 h-4" />
                                </button>
                              </div>
                            </div>
                          ))}
                          {!calendars?.filter((c: any) => !icalSubscriptions.some(sub => sub.calendarId === c.id)).length && <div className="text-sm text-slate-500 py-2">No calendars found.</div>}
                        </div>
                        
                        <div className="flex flex-wrap items-center gap-3">
                          <button 
                            onClick={() => setIsAddCalendarOpen(true)}
                            className="px-5 py-2.5 bg-indigo-600 hover:bg-indigo-700 text-white font-bold rounded-full shadow-sm transition-transform active:scale-95 flex items-center gap-2 text-sm"
                          >
                            <Plus className="w-4 h-4" /> Add calendar
                          </button>
                          <button 
                            onClick={() => {
                              const input = document.createElement('input');
                              input.type = 'file';
                              input.accept = '.ics';
                              input.onchange = async (e: any) => {
                                if (e.target.files && e.target.files.length > 0) {
                                  try {
                                    if (!credentials) return;
                                    const file = e.target.files[0];
                                    const text = await file.text();
                                    const jcalData = ICAL.parse(text);
                                    const comp = new ICAL.Component(jcalData);
                                    const vevents = comp.getAllSubcomponents("vevent");
                                    const client = new JmapClient(credentials);
                                    
                                    // Make sure we have a calendar to import to
                                    let calendarId = calendars[0]?.id;
                                    if (!calendarId) {
                                      const newCal = await client.createCalendar("Imported Calendar", "#4f46e5");
                                      calendarId = newCal.id;
                                    }
                                    
                                    let count = 0;
                                    for (const vevent of vevents) {
                                      try {
                                        const event = new ICAL.Event(vevent);
                                        await client.createEvent({
                                          title: event.summary,
                                          description: event.description || "",
                                          location: event.location || "",
                                          virtualLocation: "",
                                          startDate: format(event.startDate.toJSDate(), 'yyyy-MM-dd'),
                                          startTime: format(event.startDate.toJSDate(), 'HH:mm'),
                                          endDate: event.endDate ? format(event.endDate.toJSDate(), 'yyyy-MM-dd') : format(event.startDate.toJSDate(), 'yyyy-MM-dd'),
                                          endTime: event.endDate ? format(event.endDate.toJSDate(), 'HH:mm') : format(event.startDate.toJSDate(), 'HH:mm'),
                                          isAllDay: event.startDate.isDate,
                                          timeZone: timezone,
                                          recurrence: 'none',
                                          calendarId: calendarId,
                                          invitees: '',
                                          reminder: 'none'
                                        });
                                        count++;
                                      } catch (evErr) {}
                                    }
                                    toast.success(`Successfully imported ${count} events from ${file.name}`);
                                    fetchCalendarsAndEvents();
                                  } catch (error: any) {
                                    toast.error(error.message || "Failed to parse ICS file");
                                  }
                                }
                              };
                              input.click();
                            }}
                            className="px-5 py-2.5 bg-slate-100 dark:bg-slate-800 hover:bg-slate-200 dark:hover:bg-slate-700 text-slate-700 dark:text-slate-200 font-bold rounded-full transition-transform active:scale-95 flex items-center gap-2 text-sm"
                          >
                            <Upload className="w-4 h-4" /> Import calendar
                          </button>
                        </div>
                      </div>

                      <div className="bg-white dark:bg-slate-900 p-6 rounded-2xl border border-slate-200 dark:border-slate-800 shadow-sm">
                        <div className="flex items-center gap-3 mb-6">
                          <div className="p-2 bg-emerald-100 dark:bg-emerald-500/10 rounded-xl">
                            <Globe className="w-5 h-5 text-emerald-600 dark:text-emerald-400" />
                          </div>
                          <h2 className="text-xl font-bold text-slate-900 dark:text-white">iCal Subscriptions</h2>
                        </div>
                        
                        <div className="space-y-4 mb-6">
                          {icalSubscriptions.map((sub, idx) => (
                            <div key={sub.id || idx} className="flex flex-col sm:flex-row sm:items-start justify-between p-4 bg-slate-50 dark:bg-[#111111] rounded-xl border border-slate-100 dark:border-[#222222]">
                              <div className="flex items-start gap-3">
                                <div className="w-5 h-5 rounded-full flex items-center justify-center shrink-0 mt-1" style={{ backgroundColor: sub.color || '#22c55e' }}></div>
                                <Globe className="w-5 h-5 text-slate-400 shrink-0 mt-1" />
                                <div className="flex flex-col gap-1 min-w-0">
                                  <span className="font-bold text-slate-700 dark:text-slate-200">{sub.name}</span>
                                  <span className="text-xs text-indigo-500 dark:text-indigo-400 truncate max-w-[200px] sm:max-w-md">{sub.url}</span>
                                  <span className="text-xs text-slate-500 dark:text-slate-400 font-medium tracking-wide">Last updated: {format(new Date(sub.lastUpdated || Date.now()), "MMM d, yyyy, HH:mm")}</span>
                                </div>
                              </div>
                              <div className="flex items-center gap-1 sm:gap-2 mt-4 sm:mt-0">
                                <button
                                  onClick={async () => {
                                    if(confirm('Are you sure you want to unsubscribe from this calendar?')) {
                                      try {
                                        if (!sub.isVirtual && credentials) {
                                          try {
                                            const client = new JmapClient(credentials);
                                            await client.deleteCalendar(sub.calendarId);
                                          } catch (e) {
                                            console.warn("Could not delete from JMAP, ignoring...", e);
                                          }
                                        }
                                        const updated = icalSubscriptions.filter(s => s.id !== sub.id);
                                        setICalSubscriptions(updated);
                                        localStorage.setItem('webmail_ical_subscriptions', JSON.stringify(updated));
                                        toast.success("Unsubscribed successfully");
                                        fetchCalendarsAndEvents();
                                      } catch (err: any) {
                                        toast.error(err.message || 'Failed to unsubscribe');
                                      }
                                    }
                                  }}
                                  className="p-2 text-slate-400 hover:text-red-500 rounded-lg transition-colors"
                                  title="Unsubscribe"
                                >
                                  <Trash2 className="w-4 h-4" />
                                </button>
                              </div>
                            </div>
                          ))}
                          {!icalSubscriptions.length && <div className="text-sm text-slate-500 p-2">No active subscriptions.</div>}
                        </div>

                        <button 
                          onClick={() => {
                            setIsAddSubscriptionOpen(true);
                            setNewSubscriptionUrl("");
                            setNewSubscriptionName("");
                            setNewSubscriptionColor("#22c55e");
                          }}
                          className="px-5 py-2.5 bg-slate-100 dark:bg-slate-800 hover:bg-slate-200 dark:hover:bg-slate-700 text-slate-700 dark:text-slate-200 font-bold rounded-full transition-transform active:scale-95 flex items-center gap-2 text-sm"
                        >
                          <Globe className="w-4 h-4" /> Add subscription
                        </button>
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
                            { id: 'reports', label: 'Reports', description: 'Domain reports, DMARC, and Postmaster reports', active: filterReports },
                          ].map((cat) => (
                            <div key={cat.id} className="flex flex-row items-center justify-between p-4 rounded-2xl bg-slate-50 dark:bg-slate-800/50 border border-slate-100 dark:border-slate-800 transition-colors gap-4">
                              <div className="flex-1 min-w-0 pr-4">
                                <div className="font-bold text-slate-900 dark:text-white text-lg">{cat.label}</div>
                                <div className="text-sm text-slate-500 dark:text-slate-400">{cat.description}</div>
                              </div>
                              <button 
                                onClick={() => {
                                  const newState = !cat.active;
                                  if (cat.id === 'promotions') { setFilterPromotions(newState); localStorage.setItem('webmail_filter_promo', newState.toString()); compileAndPushSieve(newState, filterSocial, filterUpdates, filterReports, filterOnlyContacts); }
                                  if (cat.id === 'social') { setFilterSocial(newState); localStorage.setItem('webmail_filter_social', newState.toString()); compileAndPushSieve(filterPromotions, newState, filterUpdates, filterReports, filterOnlyContacts); }
                                  if (cat.id === 'updates') { setFilterUpdates(newState); localStorage.setItem('webmail_filter_updates', newState.toString()); compileAndPushSieve(filterPromotions, filterSocial, newState, filterReports, filterOnlyContacts); }
                                  if (cat.id === 'reports') { setFilterReports(newState); localStorage.setItem('webmail_filter_reports', newState.toString()); compileAndPushSieve(filterPromotions, filterSocial, filterUpdates, newState, filterOnlyContacts); }
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
                          
                          <div className="flex flex-row items-center justify-between p-4 rounded-2xl bg-slate-50 dark:bg-slate-800/50 border border-slate-100 dark:border-slate-800 transition-colors gap-4">
                            <div className="flex-1 min-w-0 pr-4">
                              <h3 className="text-lg font-bold text-slate-900 dark:text-white">Strict Contacts Mode</h3>
                              <p className="text-sm text-slate-500 dark:text-slate-400">Move emails from unknown senders (not in your Contacts) directly to Junk.</p>
                            </div>
                            <button 
                              onClick={async () => {
                                const newState = !filterOnlyContacts;
                                setFilterOnlyContacts(newState);
                                localStorage.setItem('webmail_filter_only_contacts', newState.toString());
                                compileAndPushSieve(filterPromotions, filterSocial, filterUpdates, filterReports, newState);
                              }}
                              className={cn(
                                "relative inline-flex h-8 w-14 items-center rounded-full transition-all focus:outline-none focus:ring-2 focus:ring-indigo-500 focus:ring-offset-2 dark:focus:ring-offset-slate-900 shrink-0",
                                filterOnlyContacts ? "bg-indigo-600" : "bg-slate-200 dark:bg-slate-800"
                              )}>
                              <span className={cn("inline-block h-6 w-6 transform rounded-full bg-white shadow-md transition-transform duration-200", filterOnlyContacts ? "translate-x-7" : "translate-x-1")} />
                            </button>
                          </div>
                        </div>
                      </div>

                      <div className="bg-white dark:bg-[#050505] p-6 rounded-2xl border border-slate-200 dark:border-slate-800 shadow-sm overflow-hidden relative">
                        <div className="flex items-center gap-3 mb-6">
                          <div className="p-2 bg-indigo-100 dark:bg-indigo-500/10 rounded-xl">
                            <Filter className="w-5 h-5 text-indigo-600 dark:text-indigo-400" />
                          </div>
                          <div className="flex-1">
                            <h2 className="text-xl font-bold text-slate-900 dark:text-white">Custom Rules</h2>
                            <p className="text-xs text-slate-500 dark:text-slate-400">Create specific Sieve rules to route, flag, or delete incoming messages.</p>
                          </div>
                          <button 
                            onClick={() => {
                              setEditingRule({ id: '', name: '', active: true, condition: { type: 'subject', matcher: 'contains', value: '' }, action: { type: 'move', value: 'Trash' } });
                              setIsRuleModalOpen(true);
                            }}
                            className="bg-indigo-600 hover:bg-indigo-700 text-white p-2 rounded-xl"
                          >
                            <Plus className="w-5 h-5" />
                          </button>
                        </div>

                        {customRules.length === 0 ? (
                          <div className="py-12 flex flex-col items-center justify-center text-center border-2 border-dashed border-slate-100 dark:border-slate-800 rounded-3xl bg-slate-50/50 dark:bg-black">
                            <div className="w-16 h-16 bg-slate-100 dark:bg-[#11131f] rounded-2xl flex items-center justify-center mb-4 text-slate-400">
                              <Filter className="w-8 h-8" />
                            </div>
                            <h3 className="text-lg font-bold text-slate-900 dark:text-white mb-2">No custom rules active</h3>
                            <p className="text-sm text-slate-500 dark:text-slate-400 mb-8 max-w-xs">
                              Organize your inbox by setting up automated rules for your incoming messages.
                            </p>
                            <button 
                              onClick={() => {
                                setEditingRule({ id: '', name: '', active: true, condition: { type: 'subject', matcher: 'contains', value: '' }, action: { type: 'move', value: 'Trash' } });
                                setIsRuleModalOpen(true);
                              }}
                              className="px-8 py-4 bg-indigo-600 hover:bg-indigo-700 text-white font-bold rounded-2xl shadow-lg shadow-indigo-600/20 transition-all active:scale-[0.98]">
                              Create New Rule
                            </button>
                          </div>
                        ) : (
                          <div className="space-y-4">
                            {customRules.map(rule => (
                              <div key={rule.id} className="flex flex-col sm:flex-row sm:items-center justify-between p-4 rounded-2xl bg-white dark:bg-slate-800 border border-slate-200 dark:border-slate-700 gap-4 shadow-sm">
                                <div className="flex-1 min-w-0 pr-4">
                                  <div className="flex items-center gap-2">
                                    <div className="font-bold text-slate-900 dark:text-white text-lg truncate">{rule.name}</div>
                                    <span className="text-[10px] font-bold uppercase tracking-wider bg-slate-100 dark:bg-slate-700 text-slate-600 dark:text-slate-300 px-2 py-0.5 rounded-full whitespace-nowrap shrink-0 overflow-hidden text-ellipsis max-w-[150px]">
                                      {rule.action?.type?.replace('_', ' ')} {rule.action?.value && <span className="opacity-70">{rule.action.value}</span>}
                                    </span>
                                  </div>
                                  <div className="text-sm text-slate-500 dark:text-slate-400 mt-1 truncate">
                                    If <span className="font-semibold text-slate-700 dark:text-slate-300">{rule.condition?.type}</span> {rule.condition?.matcher?.replace('_', ' ')} "{rule.condition?.value}"
                                  </div>
                                </div>
                                <div className="flex items-center gap-2 self-end sm:self-auto shrink-0 mt-2 sm:mt-0">
                                  <button 
                                    onClick={() => {
                                      setEditingRule(rule);
                                      setIsRuleModalOpen(true);
                                    }}
                                    className="p-2 text-slate-400 hover:bg-slate-100 dark:hover:bg-slate-700 rounded-lg transition-colors"
                                  >
                                    <Edit2 className="w-4 h-4" />
                                  </button>
                                  <button 
                                    onClick={() => {
                                      const updated = customRules.map(r => r.id === rule.id ? { ...r, active: !r.active } : r);
                                      setCustomRules(updated);
                                      localStorage.setItem('webmail_custom_rules', JSON.stringify(updated));
                                      compileAndPushSieve(filterPromotions, filterSocial, filterUpdates, filterReports, filterOnlyContacts, updated);
                                    }}
                                    className={cn(
                                      "relative inline-flex h-8 w-14 items-center rounded-full transition-all focus:outline-none shrink-0",
                                      rule.active ? "bg-indigo-600" : "bg-slate-200 dark:bg-slate-700"
                                    )}
                                  >
                                    <span className={cn("inline-block h-6 w-6 transform rounded-full bg-white shadow-md transition-transform duration-200", rule.active ? "translate-x-7" : "translate-x-1")} />
                                  </button>
                                  <button 
                                    onClick={() => {
                                      const updated = customRules.filter(r => r.id !== rule.id);
                                      setCustomRules(updated);
                                      localStorage.setItem('webmail_custom_rules', JSON.stringify(updated));
                                      compileAndPushSieve(filterPromotions, filterSocial, filterUpdates, filterReports, filterOnlyContacts, updated);
                                    }}
                                    className="p-2 text-red-500 hover:bg-red-50 dark:hover:bg-red-500/10 rounded-lg transition-colors"
                                  >
                                    <Trash2 className="w-4 h-4" />
                                  </button>
                                </div>
                              </div>
                            ))}
                          </div>
                        )}
                      </div>
                    </div>
                  )}

                  {isSettingsSection === 'folders' && (
                    <div className="grid gap-6">
                      <div className="bg-white dark:bg-[#050505] p-6 rounded-2xl border border-slate-200 dark:border-slate-800 shadow-sm">
                        <div className="flex items-center gap-3 mb-6">
                          <div className="p-2 bg-indigo-100 dark:bg-indigo-500/10 rounded-xl">
                            <Folder className="w-5 h-5 text-indigo-600 dark:text-indigo-400" />
                          </div>
                          <h2 className="text-xl font-bold text-slate-900 dark:text-white">{getTranslation(language, "folders")}</h2>
                        </div>
                        
                        <div className="space-y-3">
                          {mailboxes.map((mb) => {
                            const isNative = mb.role || ['inbox', 'drafts', 'sent', 'trash', 'junk', 'archive', 'outbox'].includes(mb.name.toLowerCase());
                            let Icon = iconMap[mb.icon] || Folder;
                            
                            // Re-apply same sidebar display overrides if needed (e.g. for muted, important, snoozed custom folders that might not be in iconMap logic in getMailboxes)
                            if (mb.role === 'junk') Icon = ShieldAlert;
                            else if (mb.role === 'trash') Icon = Trash2;
                            else if (mb.role === 'drafts') Icon = FileEdit;
                            else if (mb.role === 'inbox') Icon = Inbox;
                            else if (mb.role === 'archive' || mb.name.toLowerCase() === 'archive') Icon = Archive;
                            else if (mb.role === 'sent' || mb.role === 'outbox' || mb.name.toLowerCase() === 'outbox') Icon = Send;
                            else if (mb.name.toLowerCase().includes('report')) Icon = BarChart3;
                            else if (mb.name.toLowerCase() === 'muted') Icon = BellOff;
                            else if (mb.name.toLowerCase() === 'important') Icon = Star;
                            else if (mb.name.toLowerCase() === 'snoozed') Icon = Clock;
                            
                            return (
                              <div key={mb.id} className="flex items-center justify-between p-4 bg-slate-50 dark:bg-slate-800/50 rounded-2xl">
                                <div className="flex items-center gap-3">
                                  <div className="p-2 bg-white dark:bg-slate-800 rounded-xl shadow-sm border border-slate-200 dark:border-slate-700">
                                    <Icon className={cn("w-4 h-4", isNative ? "text-slate-400" : "text-indigo-500")} />
                                  </div>
                                  <div>
                                    <h3 className="text-sm font-semibold text-slate-900 dark:text-white">{getMailboxDisplayName(mb, language)}</h3>
                                    <p className="text-xs text-slate-500 dark:text-slate-400">
                                      {isNative ? 'System folder' : 'Custom folder'} • {mb.totalEmails || 0} messages
                                    </p>
                                  </div>
                                </div>
                                {!isNative && (
                                  <button
                                    onClick={() => handleDeleteMailbox(mb.id, mb.name)}
                                    className="p-2 text-red-600 dark:text-red-400 hover:bg-red-50 dark:hover:bg-red-500/10 rounded-lg transition-colors"
                                    title="Delete custom folder"
                                  >
                                    <Trash2 className="w-5 h-5" />
                                  </button>
                                )}
                              </div>
                            );
                          })}
                          
                          {mailboxes.length === 0 && (
                            <p className="text-sm text-slate-500 dark:text-slate-400 p-4 text-center">No folders found.</p>
                          )}
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
                            <button 
                              onClick={() => {
                                const newMode = !isDeveloperMode;
                                setIsDeveloperMode(newMode);
                                localStorage.setItem("webmail_developer_mode", String(newMode));
                              }}
                              className={cn("relative inline-flex h-8 w-14 items-center rounded-full transition-colors shrink-0 outline-none", isDeveloperMode ? 'bg-indigo-600' : 'bg-slate-200 dark:bg-slate-700')}
                            >
                              <span className={cn("inline-block h-6 w-6 transform rounded-full bg-white transition-transform shadow-md", isDeveloperMode ? 'translate-x-7' : 'translate-x-1')} />
                            </button>
                          </div>
                          <div className="flex items-center justify-between gap-4">
                            <div className="flex-1 min-w-0">
                              <div className="font-bold text-slate-900 dark:text-white">Beta Features</div>
                              <div className="text-xs text-slate-500 dark:text-slate-400">Try out experimental UI improvements</div>
                            </div>
                            <button 
                              onClick={() => {
                                const newMode = !isBetaFeaturesEnabled;
                                setIsBetaFeaturesEnabled(newMode);
                                localStorage.setItem("webmail_beta_features", String(newMode));
                              }}
                              className={cn("relative inline-flex h-8 w-14 items-center rounded-full transition-colors shrink-0 outline-none", isBetaFeaturesEnabled ? 'bg-indigo-600' : 'bg-slate-200 dark:bg-slate-700')}
                            >
                              <span className={cn("inline-block h-6 w-6 transform rounded-full bg-white transition-transform shadow-md", isBetaFeaturesEnabled ? 'translate-x-7' : 'translate-x-1')} />
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
          {((activeApp === 'mail' && !isSidebarOpen && !selectedEmail)) && (
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
                    return editingTemplateId ? t(language, 'editTemplate') : t(language, 'newTemplate');
                  }
                  return t(language, 'compose');
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
                          <span className="text-[11px] font-semibold tracking-widest text-slate-500 uppercase w-12">{getTranslation(language, "from")}</span>
                          <div className="flex-1 relative min-w-0">
                            <div 
                              onClick={() => setIsIdentityDropdownOpen(!isIdentityDropdownOpen)}
                              className="flex justify-between items-center cursor-pointer min-w-0 gap-2"
                            >
                              <div className="flex items-center gap-3 min-w-0 flex-1">
                                <div className={cn(
                                  "w-6 h-6 rounded-full flex items-center justify-center text-[10px] text-white font-bold shrink-0",
                                  getAccountColor(identities.find(i => i.id === selectedIdentityId)?.email || "")
                                )}>
                                  {(identities.find(i => i.id === selectedIdentityId)?.name || "?").charAt(0).toUpperCase()}
                                </div>
                                <span className="text-[15px] font-medium text-slate-800 dark:text-slate-200 truncate">
                                  {(() => {
                                    const baseEmail = identities.find(i => i.id === selectedIdentityId)?.email || "";
                                    if (!baseEmail) return "";
                                    const parts = baseEmail.split('@');
                                    return `${parts[0]}${composeSubAddress ? `+${composeSubAddress}` : ''}@${parts[1]}`;
                                  })()}
                                </span>
                              </div>
                              <div className="flex items-center gap-1 shrink-0">
                                <button
                                  onClick={(e) => {
                                    e.stopPropagation();
                                    setIsSubAddressModalOpen(true);
                                  }}
                                  className="p-1.5 rounded-md hover:bg-slate-100 dark:hover:bg-slate-800 transition-colors flex items-center gap-1 text-slate-500 hover:text-slate-700 dark:hover:text-slate-300"
                                >
                                  <Plus className="w-4 h-4" />
                                  <Tag className="w-4 h-4" />
                                </button>
                                <ChevronDown className={cn("w-4 h-4 text-slate-400 transition-transform", isIdentityDropdownOpen && "rotate-180")} />
                              </div>
                            </div>

                            {isSubAddressModalOpen && (
                              <div 
                                className="fixed inset-0 z-[60] flex items-center justify-center p-4 bg-black/50 overflow-y-auto"
                                onClick={(e) => { e.stopPropagation(); setIsSubAddressModalOpen(false); }}
                              >
                                <div 
                                  className="w-full max-w-sm bg-[#1a1a1a] dark:bg-[#11131f] rounded-2xl shadow-2xl flex flex-col p-5 border border-white/10"
                                  onClick={(e) => e.stopPropagation()}
                                >
                                  <div className="flex justify-between items-center mb-6">
                                    <h3 className="text-white font-medium text-lg">Add Sub-Address Tag</h3>
                                    <button 
                                      onClick={() => setIsSubAddressModalOpen(false)}
                                      className="text-slate-400 hover:text-white"
                                    >
                                      <X className="w-5 h-5" />
                                    </button>
                                  </div>
                                  
                                  <div className="mb-4">
                                    <input
                                      type="text"
                                      autoFocus
                                      placeholder="Enter tag (e.g., shopping)"
                                      value={composeSubAddress}
                                      onChange={(e) => {
                                        setComposeSubAddress(e.target.value.replace(/[^a-zA-Z0-9-]/g, '').toLowerCase());
                                      }}
                                      className="w-full px-4 py-3 bg-[#0a0a0a] border border-[#2e2e2e] focus:border-[#4b4b4b] rounded-xl text-[16px] outline-none transition-all text-white placeholder-slate-500"
                                    />
                                  </div>

                                  <div className="bg-[#2e2e2e]/50 p-4 rounded-xl mb-4">
                                    <div className="text-slate-400 text-xs mb-1">Preview:</div>
                                    <div className="text-white font-mono text-sm break-all">
                                      {(() => {
                                        const baseEmail = identities.find(i => i.id === selectedIdentityId)?.email || "user@domain.com";
                                        const parts = baseEmail.split('@');
                                        return `${parts[0]}${composeSubAddress ? `+${composeSubAddress}` : ''}@${parts[1]}`;
                                      })()}
                                    </div>
                                  </div>

                                  <p className="text-slate-400 text-sm mb-6 leading-relaxed">
                                    Emails sent to this address will arrive in your inbox
                                  </p>

                                  <button
                                    onClick={() => setIsSubAddressModalOpen(false)}
                                    className="w-full py-3.5 bg-white text-black font-semibold rounded-xl hover:bg-slate-200 transition-colors"
                                  >
                                    Use This Address
                                  </button>
                                </div>
                              </div>
                            )}

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
                          <span className="text-[11px] font-semibold tracking-widest text-slate-500 uppercase w-12">{getTranslation(language, "to")}</span>
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
                              placeholder={toAddresses.length === 0 ? getTranslation(language, "addRecipients") : ""}
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
                      placeholder={isTemplateFolder ? getTranslation(language, "templateSubject") : getTranslation(language, "subject")} 
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
                          placeholder={isTemplateFolder ? getTranslation(language, "typeTemplateBody") : getTranslation(language, "startWriting")} 
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
                           {isSending ? <Loader2 className="w-4 h-4 animate-spin" /> : <>{getTranslation(language, "send").toUpperCase()} <Send className="w-3.5 h-3.5 ml-1" /></>}
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
                   <p className="text-sm font-medium text-slate-500">{t(language, 'loading')}</p>
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
                   <span className="text-sm font-medium">{t(language, 'loading')}</span>
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

      {/* Custom Rule Modal */}
      {isRuleModalOpen && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/60 backdrop-blur-sm overflow-y-auto pt-20 pb-20">
          <div className="bg-white dark:bg-slate-900 w-full max-w-lg rounded-3xl shadow-2xl border border-slate-200 dark:border-slate-800 overflow-hidden animate-in fade-in zoom-in duration-200 my-auto">
            <div className="p-6 border-b border-slate-100 dark:border-slate-800 flex justify-between items-center bg-slate-50/50 dark:bg-slate-800/50">
              <h3 className="text-xl font-bold text-slate-900 dark:text-white flex items-center gap-2">
                <Filter className="w-5 h-5 text-indigo-500" />
                {editingRule.id ? 'Edit Custom Rule' : 'Create Custom Rule'}
              </h3>
              <button 
                onClick={() => setIsRuleModalOpen(false)}
                className="p-2 bg-slate-100 hover:bg-slate-200 dark:bg-slate-800 dark:hover:bg-slate-700 rounded-full transition-colors"
                title="Close Modal"
              >
                <X className="w-5 h-5 text-slate-500 dark:text-slate-400" />
              </button>
            </div>
            
            <div className="p-6 space-y-6">
              <div>
                <label className="block text-sm font-bold text-slate-700 dark:text-slate-300 mb-2">Rule Name</label>
                <input
                  autoFocus
                  type="text"
                  placeholder="e.g. Move receipts to tax folder"
                  className="w-full px-4 py-3 bg-slate-50 dark:bg-slate-800/50 border border-slate-200 dark:border-slate-700 rounded-xl focus:ring-2 focus:ring-indigo-500 outline-none text-slate-900 dark:text-white transition-all shadow-sm"
                  value={editingRule.name || ''}
                  onChange={e => setEditingRule({...editingRule, name: e.target.value})}
                />
              </div>

              <div className="p-5 bg-slate-50 dark:bg-slate-800/30 rounded-2xl border border-slate-200 dark:border-slate-700 space-y-4">
                <h4 className="font-bold text-slate-800 dark:text-slate-200 uppercase tracking-widest text-[11px] mb-2 text-indigo-600 dark:text-indigo-400">If</h4>
                <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                  <div className="space-y-1.5">
                    <label className="block text-xs font-semibold text-slate-600 dark:text-slate-400">Condition</label>
                    <div className="relative">
                      <select 
                        className="w-full pl-3 pr-8 py-2.5 bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-700 rounded-xl focus:ring-2 focus:ring-indigo-500 outline-none text-slate-900 dark:text-white shadow-sm appearance-none"
                        value={editingRule.condition?.type}
                        onChange={e => {
                          const newType = e.target.value as RuleConditionType;
                          setEditingRule({
                            ...editingRule, 
                            condition: { 
                              ...editingRule.condition!, 
                              type: newType, 
                              matcher: newType === 'size' ? 'gt' : 'contains' 
                            }
                          });
                        }}
                      >
                        <option value="subject">Subject</option>
                        <option value="from">Sender</option>
                        <option value="to">Recipient</option>
                        <option value="body">Body (Text)</option>
                        <option value="header">Custom Header</option>
                        <option value="spam_score">Spam Score</option>
                        <option value="size">Message Size</option>
                      </select>
                      <ChevronDown className="absolute right-3 top-1/2 -translate-y-1/2 w-4 h-4 text-slate-400 pointer-events-none" />
                    </div>
                  </div>
                  <div className="space-y-1.5">
                    <label className="block text-xs font-semibold text-slate-600 dark:text-slate-400">Matches</label>
                    <div className="relative">
                      <select 
                        className="w-full pl-3 pr-8 py-2.5 bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-700 rounded-xl focus:ring-2 focus:ring-indigo-500 outline-none text-slate-900 dark:text-white shadow-sm appearance-none"
                        value={editingRule.condition?.matcher}
                        onChange={e => setEditingRule({
                          ...editingRule, 
                          condition: { ...editingRule.condition!, matcher: e.target.value as RuleMatcher }
                        })}
                      >
                        {editingRule.condition?.type === 'size' ? (
                          <>
                            <option value="gt">Is greater than</option>
                            <option value="lt">Is less than</option>
                          </>
                        ) : editingRule.condition?.type === 'spam_score' ? (
                          <option value="gt">Is greater than or eq</option>
                        ) : (
                          <>
                            <option value="contains">Contains</option>
                            <option value="is">Is exactly</option>
                            <option value="starts_with">Starts with</option>
                            <option value="ends_with">Ends with</option>
                            <option value="regex">Matches Regex</option>
                          </>
                        )}
                      </select>
                      <ChevronDown className="absolute right-3 top-1/2 -translate-y-1/2 w-4 h-4 text-slate-400 pointer-events-none" />
                    </div>
                  </div>
                </div>

                {editingRule.condition?.type === 'header' && (
                  <div className="space-y-1.5">
                    <label className="block text-xs font-semibold text-slate-600 dark:text-slate-400">Header Name</label>
                    <input
                      type="text"
                      placeholder="e.g. List-Id"
                      className="w-full px-4 py-2.5 bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-700 rounded-xl focus:ring-2 focus:ring-indigo-500 outline-none text-slate-900 dark:text-white shadow-sm"
                      value={editingRule.condition.headerName || ''}
                      onChange={e => setEditingRule({
                        ...editingRule, 
                        condition: { ...editingRule.condition!, headerName: e.target.value }
                      })}
                    />
                  </div>
                )}

                <div className="space-y-1.5">
                  <label className="block text-xs font-semibold text-slate-600 dark:text-slate-400">
                    {editingRule.condition?.type === 'size' ? 'Size (Bytes)' : 'Value'}
                  </label>
                  <input
                    type="text"
                    placeholder={
                      editingRule.condition?.type === 'size' ? "1024000 (for 1MB)" :
                      editingRule.condition?.type === 'spam_score' ? "5.0" :
                      editingRule.condition?.type === 'from' ? "mark@example.com" : "invoice"
                    }
                    className="w-full px-4 py-2.5 bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-700 rounded-xl focus:ring-2 focus:ring-indigo-500 outline-none text-slate-900 dark:text-white shadow-sm"
                    value={editingRule.condition?.value || ''}
                    onChange={e => setEditingRule({
                      ...editingRule, 
                      condition: { ...editingRule.condition!, value: e.target.value }
                    })}
                  />
                  {editingRule.condition?.type === 'regex' && (
                    <p className="text-xs text-slate-500 mt-2 font-mono bg-white dark:bg-slate-900 p-2 rounded-lg border border-slate-100 dark:border-slate-800">
                      Sieve Regex: use regular expressions like <span className="text-indigo-500">.*@spam\.com</span>
                    </p>
                  )}
                </div>
              </div>

              <div className="p-5 bg-slate-50 dark:bg-slate-800/30 rounded-2xl border border-slate-200 dark:border-slate-700 space-y-4">
                <h4 className="font-bold text-slate-800 dark:text-slate-200 uppercase tracking-widest text-[11px] mb-2 text-emerald-600 dark:text-emerald-400">Then</h4>
                
                <div className="space-y-1.5">
                  <label className="block text-xs font-semibold text-slate-600 dark:text-slate-400">Action</label>
                  <div className="relative">
                    <select 
                      className="w-full pl-3 pr-8 py-2.5 bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-700 rounded-xl focus:ring-2 focus:ring-emerald-500 outline-none text-slate-900 dark:text-white shadow-sm appearance-none"
                      value={editingRule.action?.type}
                      onChange={e => setEditingRule({
                        ...editingRule, 
                        action: { ...editingRule.action!, type: e.target.value as RuleActionType }
                      })}
                    >
                      <option value="move">Move to Folder</option>
                      <option value="forward">Forward To</option>
                      <option value="reject">Reject with Message</option>
                      <option value="mark_read">Mark as Read</option>
                      <option value="mark_spam">Move to Spam</option>
                      <option value="add_flag">Add Flag</option>
                    </select>
                    <ChevronDown className="absolute right-3 top-1/2 -translate-y-1/2 w-4 h-4 text-slate-400 pointer-events-none" />
                  </div>
                </div>

                {(editingRule.action?.type === 'move' || editingRule.action?.type === 'forward' || editingRule.action?.type === 'reject' || editingRule.action?.type === 'add_flag') && (
                  <div className="space-y-1.5 mt-4">
                    <label className="block text-xs font-semibold text-slate-600 dark:text-slate-400">
                      {editingRule.action?.type === 'move' ? 'Destination Folder' :
                       editingRule.action?.type === 'forward' ? 'Forwarding Email' :
                       editingRule.action?.type === 'add_flag' ? 'Flag Value' : 'Rejection Message'}
                    </label>
                    {editingRule.action?.type === 'move' ? (
                      <div className="relative">
                        <select 
                          className="w-full pl-3 pr-8 py-2.5 bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-700 rounded-xl focus:ring-2 focus:ring-emerald-500 outline-none text-slate-900 dark:text-white shadow-sm appearance-none"
                          value={editingRule.action?.value}
                          onChange={e => setEditingRule({
                            ...editingRule, 
                            action: { ...editingRule.action!, value: e.target.value }
                          })}
                        >
                          <option value="Trash">Trash</option>
                          <option value="Spam">Spam</option>
                          <option value="Archive">Archive</option>
                          <option value="Inbox">Inbox</option>
                          <option disabled>──────</option>
                          {Array.from(new Set(mailboxes.map(m => m.name).filter(n => !['Trash', 'Spam', 'Junk Mail', 'Archive', 'Inbox'].includes(n)))).map(m => (
                            <option key={m} value={m}>{m}</option>
                          ))}
                          <option value="__custom__">+ Or type a custom folder name</option>
                        </select>
                        <ChevronDown className="absolute right-3 top-1/2 -translate-y-1/2 w-4 h-4 text-slate-400 pointer-events-none" />
                      </div>
                    ) : (
                      <input
                        type="text"
                        placeholder={
                          editingRule.action?.type === 'forward' ? "assistant@domain.com" :
                          editingRule.action?.type === 'add_flag' ? "\\\\Flagged or MyCustomTag" :
                          "Your message was rejected."
                        }
                        className="w-full px-4 py-2.5 bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-700 rounded-xl focus:ring-2 focus:ring-emerald-500 outline-none text-slate-900 dark:text-white shadow-sm"
                        value={editingRule.action?.value || ''}
                        onChange={e => setEditingRule({
                          ...editingRule, 
                          action: { ...editingRule.action!, value: e.target.value }
                        })}
                      />
                    )}

                    {editingRule.action?.value === '__custom__' && editingRule.action.type === 'move' && (
                      <input
                        type="text"
                        autoFocus
                        placeholder="Type new folder name..."
                        className="w-full px-4 py-2.5 mt-3 bg-white dark:bg-slate-900 border-2 border-emerald-500 rounded-xl focus:ring-2 focus:ring-emerald-500/50 outline-none text-slate-900 dark:text-white shadow-sm"
                        onChange={e => setEditingRule({
                          ...editingRule, 
                          action: { ...editingRule.action!, value: e.target.value }
                        })}
                      />
                    )}
                  </div>
                )}
              </div>

              <div className="pt-2">
                <button 
                  onClick={() => {
                    if (!editingRule.name || (!editingRule.condition?.value && editingRule.condition?.type !== 'size') || !editingRule.action?.value) {
                       toast.error("Please fill all required fields");
                       return;
                    }
                    if (editingRule.action.value === '__custom__') {
                       toast.error("Please specify a directory name");
                       return;
                    }
                    const newRule: CustomRule = {
                       id: editingRule.id || Math.random().toString(36).substring(7),
                       name: editingRule.name,
                       active: editingRule.active ?? true,
                       condition: editingRule.condition as CustomRuleCondition,
                       action: editingRule.action as CustomRuleAction,
                    };
                    
                    let updatedRules: CustomRule[];
                    if (editingRule.id) {
                       updatedRules = customRules.map(r => r.id === newRule.id ? newRule : r);
                    } else {
                       updatedRules = [...customRules, newRule];
                    }
                    
                    setCustomRules(updatedRules);
                    localStorage.setItem('webmail_custom_rules', JSON.stringify(updatedRules));
                    compileAndPushSieve(filterPromotions, filterSocial, filterUpdates, filterReports, filterOnlyContacts, updatedRules);
                    setIsRuleModalOpen(false);
                  }}
                  className="w-full py-4 bg-indigo-600 hover:bg-indigo-700 text-white font-bold rounded-xl shadow-lg shadow-indigo-600/20 transition-all active:scale-[0.98] flex items-center justify-center gap-2"
                >
                  <Save className="w-5 h-5" />
                  Save Sieve Rule
                </button>
              </div>
            </div>
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
        <div className="fixed inset-0 z-50 flex items-end sm:items-center justify-center sm:p-4 bg-black/60 backdrop-blur-sm">
          <div className="bg-white dark:bg-slate-900 w-full max-w-md sm:rounded-3xl rounded-t-3xl shadow-2xl border border-slate-200 dark:border-slate-800 flex flex-col h-[90vh] sm:h-auto sm:max-h-[90vh] overflow-hidden animate-in sm:fade-in sm:zoom-in slide-in-from-bottom-full sm:slide-in-from-bottom-0 duration-200">
            <div className="p-6 border-b border-slate-100 dark:border-slate-800 flex items-center justify-between bg-slate-50/50 dark:bg-slate-900/50 shrink-0">
              <h2 className="text-xl font-bold text-slate-900 dark:text-white">Create Contact</h2>
              <button onClick={() => setIsContactModalOpen(false)} className="p-2 hover:bg-slate-200 dark:hover:bg-slate-800 rounded-full transition-colors">
                <X className="w-5 h-5 text-slate-500" />
              </button>
            </div>
            <form onSubmit={handleCreateContact} className="flex flex-col flex-1 min-h-0">
              <div className="flex-1 min-h-0 p-6 space-y-4 overflow-y-auto custom-scrollbar">
                <div className="flex items-center justify-center mb-6">
                <div className="relative group cursor-pointer">
                  {newContact.photoUrl ? (
                    <img src={newContact.photoUrl} alt="Contact" className="w-24 h-24 rounded-full object-cover border-4 border-white dark:border-slate-800 shadow-lg" />
                  ) : (
                    <div className="w-24 h-24 rounded-full bg-slate-100 dark:bg-slate-800 border-4 border-white dark:border-slate-800 shadow-lg flex items-center justify-center text-slate-400 group-hover:bg-slate-200 dark:group-hover:bg-slate-700 transition-colors">
                      <Users className="w-8 h-8" />
                    </div>
                  )}
                  <div className="absolute inset-0 bg-black/40 rounded-full opacity-0 group-hover:opacity-100 transition-opacity flex items-center justify-center" onClick={() => {
                    const url = prompt("Enter photo URL:", newContact.photoUrl || "");
                    if (url !== null) setNewContact({ ...newContact, photoUrl: url });
                  }}>
                    <Camera className="w-6 h-6 text-white" />
                  </div>
                </div>
              </div>
              <div className="grid grid-cols-2 gap-4">
                <div className="space-y-1">
                  <label className="text-xs font-bold text-slate-400 uppercase tracking-wider">{getTranslation(language, "firstName")} *</label>
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
                  <label className="text-xs font-bold text-slate-400 uppercase tracking-wider">{getTranslation(language, "lastName")}</label>
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
                <label className="text-xs font-bold text-slate-400 uppercase tracking-wider">{getTranslation(language, "emailAddress")} *</label>
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
                  <label className="text-xs font-bold text-slate-400 uppercase tracking-wider">{getTranslation(language, "phone")}</label>
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
                  <label className="text-xs font-bold text-slate-400 uppercase tracking-wider">{getTranslation(language, "organization")}</label>
                  <input 
                    type="text" 
                    value={newContact.organization}
                    onChange={e => setNewContact({...newContact, organization: e.target.value})}
                    placeholder="Company Inc."
                    className="w-full px-4 py-3 bg-slate-50 dark:bg-slate-800 border-transparent focus:bg-white dark:focus:bg-slate-700 focus:ring-2 focus:ring-indigo-500/20 rounded-xl text-sm outline-none transition-all dark:text-white"
                  />
                </div>
                <div className="space-y-1">
                  <label className="text-xs font-bold text-slate-400 uppercase tracking-wider">Birthday</label>
                  <input 
                    type="date" 
                    value={newContact.birthday}
                    onChange={e => setNewContact({...newContact, birthday: e.target.value})}
                    className="w-full px-4 py-3 bg-slate-50 dark:bg-slate-800 border-transparent focus:bg-white dark:focus:bg-slate-700 focus:ring-2 focus:ring-indigo-500/20 rounded-xl text-sm outline-none transition-all dark:text-white [&::-webkit-calendar-picker-indicator]:dark:invert"
                  />
                </div>
              </div>
              
              <div className="space-y-1">
                <label className="text-xs font-bold text-slate-400 uppercase tracking-wider">{getTranslation(language, "notes")}</label>
                <textarea 
                  value={newContact.notes}
                  onChange={e => setNewContact({...newContact, notes: e.target.value})}
                  placeholder="Add any additional notes here..."
                  className="w-full px-4 py-3 bg-slate-50 dark:bg-slate-800 border-transparent focus:bg-white dark:focus:bg-slate-700 focus:ring-2 focus:ring-indigo-500/20 rounded-xl text-sm outline-none transition-all dark:text-white resize-none min-h-[80px]"
                />
              </div>
              </div>

              <div className="p-6 border-t border-slate-100 dark:border-slate-800 shrink-0 flex gap-3 bg-white dark:bg-slate-900">
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
                  {t(language, 'save')}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {isAddCalendarOpen && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/60 backdrop-blur-sm">
          <div className="bg-white dark:bg-[#1C1C1C] w-full max-w-sm rounded-[24px] shadow-2xl border border-slate-200 dark:border-[#333333] overflow-hidden animate-in fade-in zoom-in duration-200">
            <div className="px-6 pt-6 pb-4">
              <h2 className="text-xl font-bold text-slate-900 dark:text-white">Add calendar</h2>
            </div>
            <form onSubmit={async (e) => {
              e.preventDefault();
              if (!newCalendarName.trim()) return;
              try {
                const client = new JmapClient(credentials);
                await client.createCalendar(newCalendarName.trim(), newCalendarColor);
                toast.success("Calendar created");
                const list = await client.getCalendars();
                setCalendars(list);
                setIsAddCalendarOpen(false);
                setNewCalendarName("");
                setNewCalendarColor("#4f46e5");
              } catch (err: any) {
                toast.error(err.message || "Failed to create calendar");
              }
            }} className="px-6 pb-6 space-y-6">
              <div className="space-y-2">
                <label className="text-xs font-bold text-slate-500 dark:text-[#888888] uppercase tracking-wider block">Name</label>
                <input 
                  required
                  type="text" 
                  value={newCalendarName}
                  onChange={e => setNewCalendarName(e.target.value)}
                  placeholder="Calendar name"
                  className="w-full px-4 py-3 bg-slate-50 dark:bg-[#111111] border border-slate-200 dark:border-[#333333] focus:border-indigo-500 focus:ring-1 focus:ring-indigo-500 rounded-xl text-sm outline-none transition-all dark:text-white"
                />
              </div>
              <div className="space-y-3">
                <label className="text-xs font-bold text-slate-500 dark:text-[#888888] uppercase tracking-wider block">Color</label>
                <div className="grid grid-cols-7 gap-3">
                  {[
                    "#ef4444", "#f97316", "#f59e0b", "#84cc16", "#22c55e", "#10b981", "#14b8a6",
                    "#06b6d4", "#0ea5e9", "#3b82f6", "#4f46e5", "#8b5cf6", "#a855f7", "#d946ef",
                    "#ec4899", "#f43f5e", "#b91c1c", "#c2410c", "#4d7c0f", "#0f766e"
                  ].map((hex, idx) => (
                    <button
                      key={hex}
                      type="button"
                      onClick={() => setNewCalendarColor(hex)}
                      className="w-7 h-7 rounded-full flex items-center justify-center relative cursor-pointer group transition-transform active:scale-90"
                      style={{ backgroundColor: hex }}
                    >
                      {newCalendarColor === hex && (
                        <div className="w-1.5 h-1.5 bg-white rounded-full mx-auto" />
                      )}
                    </button>
                  ))}
                  <button type="button" className="w-7 h-7 rounded-full flex items-center justify-center bg-slate-100 mt-0 hover:bg-slate-200 dark:bg-[#222222] dark:hover:bg-[#333333] transition-colors">
                    <Plus className="w-4 h-4 text-slate-500 dark:text-slate-400" />
                  </button>
                </div>
              </div>
              <div className="pt-2 flex justify-end gap-3">
                <button type="button" onClick={() => { setIsAddCalendarOpen(false); setNewCalendarName(""); }} className="px-5 py-2.5 font-bold rounded-lg text-slate-600 dark:text-slate-300 hover:bg-slate-100 dark:hover:bg-slate-800 transition-colors text-sm">Cancel</button>
                <button type="submit" disabled={!newCalendarName.trim()} className="px-5 py-2.5 bg-purple-600 hover:bg-purple-700 disabled:opacity-50 text-white font-bold rounded-lg transition-all shadow-sm flex items-center justify-center text-sm">
                  Create
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {isAddSubscriptionOpen && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/60 backdrop-blur-sm">
          <div className="bg-white dark:bg-[#1C1C1C] w-full max-w-sm rounded-[24px] shadow-2xl border border-slate-200 dark:border-[#333333] overflow-hidden animate-in fade-in zoom-in duration-200">
            <div className="px-6 pt-6 pb-4">
              <h2 className="text-xl font-bold text-slate-900 dark:text-white">Add iCal Subscription</h2>
            </div>
            <form className="px-6 pb-6 space-y-5" onSubmit={async (e) => {
              e.preventDefault();
              if (!newSubscriptionUrl.trim() || !newSubscriptionName.trim()) return;

              try {
                const subId = Math.random().toString(36).substr(2);
                const newSub = {
                  id: subId,
                  url: newSubscriptionUrl.trim().replace(/^webcal:\/\//i, 'https://'),
                  name: newSubscriptionName.trim(),
                  color: newSubscriptionColor,
                  calendarId: `extcal-${subId}`,
                  lastUpdated: Date.now(),
                  isVirtual: true
                };
                
                const updated = [...icalSubscriptions, newSub];
                setICalSubscriptions(updated);
                localStorage.setItem('webmail_ical_subscriptions', JSON.stringify(updated));
                
                toast.success(`Subscribed to ${newSub.name} successfully! Calendar is syncing.`);
                
                setIsAddSubscriptionOpen(false);
                setNewSubscriptionUrl("");
                setNewSubscriptionName("");
                setNewSubscriptionColor("#22c55e");
                
                fetchCalendarsAndEvents();
              } catch (err: any) {
                toast.error(err.message || 'Failed to subscribe');
              }
            }}>
              <div className="space-y-4">
                <div>
                  <label className="text-xs font-bold text-slate-500 dark:text-[#888888] uppercase tracking-wider mb-2 block">Subscription URL</label>
                  <input
                    type="text"
                    required
                    value={newSubscriptionUrl}
                    onChange={(e) => setNewSubscriptionUrl(e.target.value)}
                    placeholder="https://.../*.ics"
                    className="w-full px-4 py-2.5 bg-slate-50 dark:bg-[#111111] border border-slate-200 dark:border-[#333333] rounded-lg focus:outline-none focus:ring-2 focus:ring-green-500 dark:text-white transition-all text-sm font-medium"
                    autoFocus
                  />
                </div>
                <div>
                  <label className="text-xs font-bold text-slate-500 dark:text-[#888888] uppercase tracking-wider mb-2 block">Name</label>
                  <input
                    type="text"
                    required
                    value={newSubscriptionName}
                    onChange={(e) => setNewSubscriptionName(e.target.value)}
                    placeholder="e.g. Holidays, Work"
                    className="w-full px-4 py-2.5 bg-slate-50 dark:bg-[#111111] border border-slate-200 dark:border-[#333333] rounded-lg focus:outline-none focus:ring-2 focus:ring-green-500 dark:text-white transition-all text-sm font-medium"
                  />
                </div>
                <div>
                  <label className="text-xs font-bold text-slate-500 dark:text-[#888888] uppercase tracking-wider mb-2 block">Color</label>
                  <div className="grid grid-cols-7 gap-3">
                    {[
                      "#ef4444", "#f97316", "#f59e0b", "#84cc16", "#22c55e", "#10b981", "#14b8a6",
                      "#06b6d4", "#0ea5e9", "#3b82f6", "#4f46e5", "#8b5cf6", "#a855f7", "#d946ef",
                      "#ec4899", "#f43f5e", "#b91c1c", "#c2410c", "#4d7c0f", "#0f766e"
                    ].map((hex) => (
                      <button
                        key={hex}
                        type="button"
                        onClick={() => setNewSubscriptionColor(hex)}
                        className="w-7 h-7 rounded-full flex items-center justify-center relative cursor-pointer group transition-transform active:scale-90"
                        style={{ backgroundColor: hex }}
                      >
                        {newSubscriptionColor === hex && (
                          <div className="w-1.5 h-1.5 bg-white rounded-full mx-auto" />
                        )}
                      </button>
                    ))}
                    <button type="button" className="w-7 h-7 rounded-full flex items-center justify-center bg-slate-100 mt-0 hover:bg-slate-200 dark:bg-[#222222] dark:hover:bg-[#333333] transition-colors">
                      <Plus className="w-4 h-4 text-slate-500 dark:text-slate-400" />
                    </button>
                  </div>
                </div>
              </div>
              <div className="pt-2 flex justify-end gap-3">
                <button type="button" onClick={() => { setIsAddSubscriptionOpen(false); setNewSubscriptionUrl(""); setNewSubscriptionName(""); setNewSubscriptionColor("#22c55e"); }} className="px-5 py-2.5 font-bold rounded-lg text-slate-600 dark:text-slate-300 hover:bg-slate-100 dark:hover:bg-slate-800 transition-colors text-sm">Cancel</button>
                <button type="submit" disabled={!newSubscriptionUrl.trim() || !newSubscriptionName.trim()} className="px-5 py-2.5 bg-green-600 hover:bg-green-700 disabled:opacity-50 text-white font-bold rounded-lg transition-all shadow-sm flex items-center justify-center text-sm">
                  Subscribe
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {isEventModalOpen && (
        <div className="fixed inset-0 z-[90] flex flex-col bg-[#050505] animate-in slide-in-from-bottom-2 duration-200">
          <div className="flex items-center justify-between p-4 bg-[#050505] z-10 sticky top-0">
            <h2 className="text-[22px] font-bold text-white tracking-tight">{editingEventId ? 'Edit event' : 'Create event'}</h2>
            <button onClick={() => { setIsEventModalOpen(false); setEditingEventId(null); }} className="p-2 hover:bg-[#1e1e1e] rounded-full transition-colors shrink-0 text-slate-300">
              <X className="w-5 h-5 text-current" />
            </button>
          </div>
          
          <div className="flex-1 overflow-y-auto w-full">
            <form onSubmit={handleCreateEvent} className="p-4 space-y-6 pb-24 max-w-2xl mx-auto w-full text-slate-200">
              
              <div className="space-y-2">
                <label className="text-[15px] font-medium block">Title</label>
                <div className="relative">
                  <input 
                    required
                    type="text" 
                    value={newEvent.title}
                    onChange={e => setNewEvent({...newEvent, title: e.target.value})}
                    placeholder="Title"
                    className="w-full px-4 py-3.5 bg-[#0a0a0a] border border-[#2e2e2e] focus:border-[#4b4b4b] rounded-xl text-[16px] outline-none transition-all text-white placeholder-slate-500"
                  />
                </div>
              </div>

              <div className="space-y-2">
                <label className="text-[15px] font-medium block">Description</label>
                <textarea 
                  value={newEvent.description}
                  onChange={e => setNewEvent({...newEvent, description: e.target.value})}
                  placeholder="Description"
                  rows={4}
                  className="w-full px-4 py-3.5 bg-[#0a0a0a] border border-[#2e2e2e] focus:border-[#4b4b4b] rounded-xl text-[16px] outline-none transition-all text-white placeholder-slate-500 resize-none"
                />
              </div>

              <div className="space-y-2">
                <label className="text-[15px] font-medium block">Location</label>
                <input 
                  type="text" 
                  value={newEvent.location}
                  onChange={e => setNewEvent({...newEvent, location: e.target.value})}
                  placeholder="Location"
                  className="w-full px-4 py-3.5 bg-[#0a0a0a] border border-[#2e2e2e] focus:border-[#4b4b4b] rounded-xl text-[16px] outline-none transition-all text-white placeholder-slate-500"
                />
              </div>

              <div className="space-y-2">
                <div className="flex items-center gap-2 mb-2">
                  <Video className="w-4 h-4 text-slate-300" />
                  <label className="text-[15px] font-medium block">Meeting link</label>
                </div>
                <input 
                  type="text" 
                  value={newEvent.virtualLocation}
                  onChange={e => setNewEvent({...newEvent, virtualLocation: e.target.value})}
                  placeholder="https://meet.example.com/..."
                  className="w-full px-4 py-3.5 bg-[#0a0a0a] border border-[#2e2e2e] focus:border-[#4b4b4b] rounded-xl text-[16px] outline-none transition-all text-white placeholder-slate-500"
                />
              </div>

              <div className="space-y-2">
                <div className="flex items-center gap-2 mb-2">
                  <Users className="w-4 h-4 text-slate-300" />
                  <label className="text-[15px] font-medium block">Participants</label>
                </div>
                <input 
                  type="text" 
                  value={newEvent.invitees}
                  onChange={e => setNewEvent({...newEvent, invitees: e.target.value})}
                  placeholder="Add email address or search contacts"
                  className="w-full px-4 py-3.5 bg-[#0a0a0a] border border-[#2e2e2e] focus:border-[#4b4b4b] rounded-xl text-[16px] outline-none transition-all text-white placeholder-slate-500"
                />
              </div>

              <div className="h-px bg-[#2e2e2e] w-full my-6"></div>

              <div className="flex items-center gap-3">
                <button
                  type="button"
                  onClick={() => setNewEvent({ ...newEvent, isAllDay: !newEvent.isAllDay })}
                  className={cn(
                    "w-6 h-6 rounded flex items-center justify-center border transition-colors shrink-0",
                    newEvent.isAllDay ? "bg-indigo-500 border-indigo-500" : "bg-[#0a0a0a] border-[#5a5a5a]"
                  )}
                >
                  {newEvent.isAllDay && <Check className="w-4 h-4 text-white" />}
                </button>
                <span className="text-[16px] font-medium text-white">All-day event</span>
              </div>

              <div className="space-y-2">
                <label className="text-[15px] font-medium block">Start date</label>
                <div className="relative">
                  <input 
                    required
                    type="date" 
                    value={newEvent.startDate}
                    onChange={e => setNewEvent({...newEvent, startDate: e.target.value})}
                    className="w-full px-4 py-3.5 bg-[#0a0a0a] border border-[#2e2e2e] focus:border-[#4b4b4b] rounded-xl text-[16px] outline-none transition-all text-white [color-scheme:dark] appearance-none"
                  />
                  <ChevronDown className="absolute right-4 top-1/2 -translate-y-1/2 w-5 h-5 text-slate-500 pointer-events-none" />
                </div>
              </div>

              {!newEvent.isAllDay && (
                <div className="space-y-2">
                  <label className="text-[15px] font-medium block">Start time</label>
                  <div className="relative">
                    <input 
                      required
                      type="time" 
                      value={newEvent.startTime}
                      onChange={e => setNewEvent({...newEvent, startTime: e.target.value})}
                      className="w-full px-4 py-3.5 bg-[#0a0a0a] border border-[#2e2e2e] focus:border-[#4b4b4b] rounded-xl text-[16px] outline-none transition-all text-white [color-scheme:dark] appearance-none"
                    />
                    <ChevronDown className="absolute right-4 top-1/2 -translate-y-1/2 w-5 h-5 text-slate-500 pointer-events-none" />
                  </div>
                </div>
              )}

              <div className="space-y-2">
                <label className="text-[15px] font-medium block">End date</label>
                <div className="relative">
                  <input 
                    required
                    type="date" 
                    value={newEvent.endDate}
                    onChange={e => setNewEvent({...newEvent, endDate: e.target.value})}
                    className="w-full px-4 py-3.5 bg-[#0a0a0a] border border-[#2e2e2e] focus:border-[#4b4b4b] rounded-xl text-[16px] outline-none transition-all text-white [color-scheme:dark] appearance-none"
                  />
                  <ChevronDown className="absolute right-4 top-1/2 -translate-y-1/2 w-5 h-5 text-slate-500 pointer-events-none" />
                </div>
              </div>

              {!newEvent.isAllDay && (
                <div className="space-y-2">
                  <label className="text-[15px] font-medium block">End time</label>
                  <div className="relative">
                    <input 
                      required
                      type="time" 
                      value={newEvent.endTime}
                      onChange={e => setNewEvent({...newEvent, endTime: e.target.value})}
                      className="w-full px-4 py-3.5 bg-[#0a0a0a] border border-[#2e2e2e] focus:border-[#4b4b4b] rounded-xl text-[16px] outline-none transition-all text-white [color-scheme:dark] appearance-none"
                    />
                    <ChevronDown className="absolute right-4 top-1/2 -translate-y-1/2 w-5 h-5 text-slate-500 pointer-events-none" />
                  </div>
                </div>
              )}

              <div className="space-y-2">
                <label className="text-[15px] font-medium block">Calendar</label>
                <div className="relative">
                  <select 
                    value={newEvent.calendarId}
                    onChange={e => setNewEvent({...newEvent, calendarId: e.target.value})}
                    className="w-full px-4 py-3.5 bg-[#0a0a0a] border border-[#2e2e2e] focus:border-[#4b4b4b] rounded-xl text-[16px] outline-none transition-all text-white appearance-none"
                  >
                    <option value="">Default Calendar</option>
                    {calendars.filter((c: any) => !icalSubscriptions.some(sub => sub.calendarId === c.id)).map(cal => (
                      <option key={cal.id} value={cal.id}>{cal.name}</option>
                    ))}
                  </select>
                  <ChevronDown className="absolute right-4 top-1/2 -translate-y-1/2 w-5 h-5 text-slate-500 pointer-events-none" />
                </div>
              </div>

              <div className="space-y-2">
                <label className="text-[15px] font-medium block">Recurrence</label>
                <div className="relative">
                  <select 
                    value={newEvent.recurrence}
                    onChange={e => setNewEvent({...newEvent, recurrence: e.target.value})}
                    className="w-full px-4 py-3.5 bg-[#0a0a0a] border border-[#2e2e2e] focus:border-[#4b4b4b] rounded-xl text-[16px] outline-none transition-all text-white appearance-none"
                  >
                    <option value="none">Does not repeat</option>
                    <option value="daily">Daily</option>
                    <option value="weekly">Weekly on {format(new Date(newEvent.startDate), 'EEEE')}</option>
                    <option value="monthly">Monthly on day {format(new Date(newEvent.startDate), 'd')}</option>
                    <option value="yearly">Annually on {format(new Date(newEvent.startDate), 'MMM d')}</option>
                    <option value="custom">Custom...</option>
                  </select>
                  <ChevronDown className="absolute right-4 top-1/2 -translate-y-1/2 w-5 h-5 text-slate-500 pointer-events-none" />
                </div>
              </div>

              <div className="space-y-2">
                <label className="text-[15px] font-medium block">Reminder</label>
                <div className="relative">
                  <select 
                    value={newEvent.reminder}
                    onChange={e => setNewEvent({...newEvent, reminder: e.target.value})}
                    className="w-full px-4 py-3.5 bg-[#0a0a0a] border border-[#2e2e2e] focus:border-[#4b4b4b] rounded-xl text-[16px] outline-none transition-all text-white appearance-none"
                  >
                    <option value="none">No reminder</option>
                    <option value="15">15 minutes before</option>
                    <option value="30">30 minutes before</option>
                    <option value="60">1 hour before</option>
                  </select>
                  <ChevronDown className="absolute right-4 top-1/2 -translate-y-1/2 w-5 h-5 text-slate-500 pointer-events-none" />
                </div>
              </div>

              {/* Spacer so content is above bottom floating bar */}
              <div className="pt-8"></div>
              
            </form>
          </div>

          <div className="fixed bottom-0 left-0 right-0 p-4 bg-[#050505] flex justify-end gap-3 z-20 max-w-2xl mx-auto border-t border-[#1a1a1a]">
            <button 
              type="button"
              onClick={() => { setIsEventModalOpen(false); setEditingEventId(null); }}
              className="px-6 py-2.5 border border-[#2e2e2e] text-white font-medium rounded-xl hover:bg-[#1a1a1a] transition-all"
            >
              Cancel
            </button>
            <button 
              type="button"
              onClick={(e) => {
                e.preventDefault();
                handleCreateEvent(e as any);
              }}
              disabled={isLoading}
              className="px-6 py-2.5 bg-slate-200 hover:bg-white text-[#050505] font-semibold rounded-xl shadow-lg transition-all active:scale-95 disabled:opacity-50 flex items-center justify-center gap-2"
            >
              {isLoading ? <Loader2 className="w-4 h-4 animate-spin" /> : null}
              Save
            </button>
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
                        {format(new Date(event.start), calTimeFormat === '24-hour' ? 'HH:mm' : 'h:mm a')}
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
          <div className="bg-white dark:bg-slate-900 w-full max-w-md rounded-3xl shadow-2xl border border-slate-200 dark:border-slate-800 overflow-hidden animate-in fade-in zoom-in duration-200 flex flex-col max-h-[90vh]">
            <div className="p-6 border-b border-slate-100 dark:border-slate-800 flex items-center justify-between shrink-0">
              <h2 className="text-xl font-bold text-slate-900 dark:text-white italic">Event Details</h2>
              <button onClick={() => setSelectedEvent(null)} className="p-2 hover:bg-slate-100 dark:hover:bg-slate-800 rounded-full transition-colors">
                <X className="w-5 h-5 text-slate-500" />
              </button>
            </div>
            <div className="p-8 space-y-8 overflow-y-auto no-scrollbar">
              <div>
                <h1 className="text-3xl font-black text-slate-900 dark:text-white tracking-tight leading-tight">{selectedEvent.title}</h1>
                <div className="flex items-center gap-3 mt-4 text-indigo-600 dark:text-indigo-400 font-bold">
                  <Calendar className="w-5 h-5" />
                  {format(new Date(selectedEvent.start || selectedEvent.startDate), 'MMMM do, yyyy')}
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
                      {selectedEvent.showWithoutTime || selectedEvent.isAllDay ? "All day" : format(new Date(selectedEvent.start), calTimeFormat === '24-hour' ? 'HH:mm' : 'h:mm a')}
                    </div>
                  </div>
                </div>

                <div className="flex gap-4">
                  <div className="w-12 h-12 bg-slate-100 dark:bg-slate-800 rounded-2xl flex items-center justify-center shrink-0">
                    <Calendar className="w-6 h-6 text-slate-400" />
                  </div>
                  <div>
                    <div className="text-xs font-black uppercase text-slate-400 tracking-widest mb-1">Calendar</div>
                    <div className="text-slate-900 dark:text-white font-bold text-lg">
                      {calendars.find((c: any) => c.id === (selectedEvent.calendarId || (selectedEvent.calendarIds && Object.keys(selectedEvent.calendarIds)[0])) && c._accountId === selectedEvent._accountId)?.name || "Unknown Calendar"}
                    </div>
                  </div>
                </div>

                {(selectedEvent.locations ? Object.values(selectedEvent.locations as any)[0] as any : null)?.name && (
                  <div className="flex gap-4">
                    <div className="w-12 h-12 bg-slate-100 dark:bg-slate-800 rounded-2xl flex items-center justify-center shrink-0">
                      <MapPin className="w-6 h-6 text-slate-400" />
                    </div>
                    <div>
                      <div className="text-xs font-black uppercase text-slate-400 tracking-widest mb-1">Location</div>
                      <div className="text-slate-900 dark:text-white font-bold text-lg">{(Object.values(selectedEvent.locations as any)[0] as any).name}</div>
                    </div>
                  </div>
                )}

                {selectedEvent.virtualLocations && Object.values(selectedEvent.virtualLocations).length > 0 && (
                  <div className="flex gap-4">
                    <div className="w-12 h-12 bg-slate-100 dark:bg-slate-800 rounded-2xl flex items-center justify-center shrink-0">
                      <Video className="w-6 h-6 text-slate-400" />
                    </div>
                    <div className="truncate min-w-0 pr-4">
                      <div className="text-xs font-black uppercase text-slate-400 tracking-widest mb-1">Meeting Link</div>
                      <a href={(Object.values(selectedEvent.virtualLocations)[0] as any).uri} target="_blank" rel="noreferrer" className="text-indigo-600 dark:text-indigo-400 font-bold text-lg hover:underline truncate block">
                        {(Object.values(selectedEvent.virtualLocations)[0] as any).uri}
                      </a>
                    </div>
                  </div>
                )}

                {selectedEvent.participants && Object.values(selectedEvent.participants).length > 0 && (
                  <div className="flex gap-4">
                    <div className="w-12 h-12 bg-slate-100 dark:bg-slate-800 rounded-2xl flex items-center justify-center shrink-0">
                      <Users className="w-6 h-6 text-slate-400" />
                    </div>
                    <div className="truncate min-w-0 pr-4">
                      <div className="text-xs font-black uppercase text-slate-400 tracking-widest mb-1">Participants</div>
                      <div className="text-slate-900 dark:text-white font-bold text-lg truncate block">
                        {Object.values(selectedEvent.participants).map((p: any) => p.email || p.name).join(', ')}
                      </div>
                    </div>
                  </div>
                )}

                {selectedEvent.alerts && Object.values(selectedEvent.alerts).length > 0 && (
                  <div className="flex gap-4">
                    <div className="w-12 h-12 bg-slate-100 dark:bg-slate-800 rounded-2xl flex items-center justify-center shrink-0">
                      <Bell className="w-6 h-6 text-slate-400" />
                    </div>
                    <div>
                      <div className="text-xs font-black uppercase text-slate-400 tracking-widest mb-1">Reminder</div>
                      <div className="text-slate-900 dark:text-white font-bold text-lg">
                        {(Object.values(selectedEvent.alerts)[0] as any).trigger?.offset ? 
                          `${(Object.values(selectedEvent.alerts)[0] as any).trigger.offset.replace('-PT', '').replace('M', '')} minutes before` 
                          : "Custom"}
                      </div>
                    </div>
                  </div>
                )}

                {selectedEvent.recurrenceRules && selectedEvent.recurrenceRules.length > 0 && (
                  <div className="flex gap-4">
                    <div className="w-12 h-12 bg-slate-100 dark:bg-slate-800 rounded-2xl flex items-center justify-center shrink-0">
                      <RefreshCw className="w-6 h-6 text-slate-400" />
                    </div>
                    <div>
                      <div className="text-xs font-black uppercase text-slate-400 tracking-widest mb-1">Repeat</div>
                      <div className="text-slate-900 dark:text-white font-bold text-lg capitalize">{selectedEvent.recurrenceRules[0].frequency}</div>
                    </div>
                  </div>
                )}

                {selectedEvent.description && (
                  <div className="bg-slate-50 dark:bg-slate-800/50 p-6 rounded-3xl border border-slate-100 dark:border-slate-700">
                    <div className="text-xs font-black uppercase text-slate-400 tracking-widest mb-3">Notes</div>
                    <div className="text-slate-700 dark:text-slate-300 whitespace-pre-wrap leading-relaxed break-words max-h-[300px] overflow-y-auto custom-scrollbar">{selectedEvent.description}</div>
                  </div>
                )}
              </div>

              <div className="flex gap-4 pt-4">
                <button 
                  onClick={() => {
                    setEditingEventId(selectedEvent.id);
                    // extract details
                    // get duration and compute end date/time if not present?
                    let startObj = new Date(selectedEvent.start);
                    let endObj = new Date(selectedEvent.start);
                    if (selectedEvent.duration) {
                      // rough parse of duration... P...D or PT...H...M
                      const pMatch = selectedEvent.duration.match(/P(\d+)D/);
                      if (pMatch) {
                        endObj.setDate(startObj.getDate() + parseInt(pMatch[1]));
                      } else {
                        const hMatch = selectedEvent.duration.match(/(\d+)H/);
                        const mMatch = selectedEvent.duration.match(/(\d+)M/);
                        if (hMatch) endObj.setHours(startObj.getHours() + parseInt(hMatch[1]));
                        if (mMatch) endObj.setMinutes(startObj.getMinutes() + parseInt(mMatch[1]));
                      }
                    } else {
                      endObj.setHours(startObj.getHours() + 1);
                    }
                    setNewEvent({
                      title: selectedEvent.title || '',
                      description: selectedEvent.description || '',
                      location: (selectedEvent.locations ? Object.values(selectedEvent.locations as any)[0] as any : null)?.name || '',
                      virtualLocation: '',
                      isAllDay: selectedEvent.showWithoutTime || false,
                      startDate: format(startObj, 'yyyy-MM-dd'),
                      startTime: format(startObj, 'HH:mm'),
                      endDate: format(endObj, 'yyyy-MM-dd'),
                      endTime: format(endObj, 'HH:mm'),
                      timeZone: selectedEvent.timeZone || timezone,
                      recurrence: selectedEvent.recurrenceRules?.[0]?.frequency || 'none',
                      invitees: '',
                      calendarId: selectedEvent.calendarId || calendars[0]?.id || ''
                    });
                    setSelectedEvent(null);
                    setIsEventModalOpen(true);
                  }}
                  className="flex-1 px-4 py-4 bg-indigo-50 dark:bg-indigo-500/10 text-indigo-600 dark:text-indigo-400 font-bold rounded-2xl border border-indigo-100 dark:border-indigo-900/30 hover:bg-indigo-100 transition-all flex items-center justify-center gap-2"
                >
                  <Edit2 className="w-5 h-5" /> Edit
                </button>
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
                  placeholder={t(language, 'searchInContacts')}
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
        <div className="fixed inset-0 z-[110] flex items-end sm:items-center justify-center sm:p-4 bg-black/60 backdrop-blur-sm">
          <div className="bg-white dark:bg-slate-900 w-full max-w-md sm:rounded-3xl rounded-t-3xl shadow-2xl border border-slate-200 dark:border-slate-800 flex flex-col h-[90vh] sm:h-auto sm:max-h-[90vh] overflow-hidden animate-in sm:fade-in sm:zoom-in slide-in-from-bottom-full sm:slide-in-from-bottom-0 duration-200">
            <div className="p-6 border-b border-slate-100 dark:border-slate-800 flex items-center justify-between shrink-0">
              <h2 className="text-xl font-bold text-slate-900 dark:text-white">
                {isEditingContact ? "Edit Contact" : "Contact Details"}
              </h2>
              <button onClick={() => setSelectedContact(null)} className="p-2 hover:bg-slate-100 dark:hover:bg-slate-800 rounded-full">
                <X className="w-5 h-5 text-slate-500" />
              </button>
            </div>

            <div className="flex-1 min-h-0 p-6 sm:p-8 space-y-6 overflow-y-auto custom-scrollbar">
              <div className="flex flex-col items-center gap-4 text-center">
                <div className="relative group cursor-pointer" onClick={() => {
                  if (isEditingContact) {
                    const url = prompt("Enter photo URL:", getContactPhoto(selectedContact));
                    if (url !== null) setEditingContactData({ ...editingContactData, photoUrl: url });
                  }
                }}>
                  {getContactPhoto(selectedContact) || editingContactData?.photoUrl ? (
                    <img src={editingContactData?.photoUrl || getContactPhoto(selectedContact)} alt="Contact" className="w-24 h-24 rounded-3xl object-cover shadow-xl shadow-indigo-500/20" />
                  ) : (
                    <div className="w-24 h-24 rounded-3xl bg-gradient-to-br from-indigo-500 to-purple-600 text-white flex items-center justify-center font-black text-4xl shadow-xl shadow-indigo-500/20">
                      {getContactName(selectedContact).charAt(0).toUpperCase()}
                    </div>
                  )}
                  {isEditingContact && (
                    <div className="absolute inset-0 bg-black/40 rounded-3xl opacity-0 group-hover:opacity-100 transition-opacity flex items-center justify-center">
                      <Camera className="w-6 h-6 text-white" />
                    </div>
                  )}
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
                    <div>
                      <label className="text-[10px] font-black uppercase text-slate-400 tracking-widest ml-1 mb-1 block">Organization</label>
                      <input 
                        type="text"
                        value={editingContactData?.organization || ""}
                        onChange={(e) => setEditingContactData({...editingContactData, organization: e.target.value})}
                        className="w-full bg-slate-50 dark:bg-slate-800 border-none rounded-2xl px-4 py-3 text-sm focus:ring-2 focus:ring-indigo-500/20 outline-none"
                      />
                    </div>
                    <div>
                      <label className="text-[10px] font-black uppercase text-slate-400 tracking-widest ml-1 mb-1 block">Birthday</label>
                      <input 
                        type="date"
                        value={editingContactData?.birthday || ""}
                        onChange={(e) => setEditingContactData({...editingContactData, birthday: e.target.value})}
                        className="w-full bg-slate-50 dark:bg-slate-800 border-none rounded-2xl px-4 py-3 text-sm focus:ring-2 focus:ring-indigo-500/20 outline-none [&::-webkit-calendar-picker-indicator]:dark:invert"
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

                    {editingContactData?.birthday && (
                      <div className="flex gap-4">
                        <div className="w-12 h-12 bg-slate-100 dark:bg-slate-800 rounded-2xl flex items-center justify-center shrink-0">
                          <span className="text-xl">🎂</span>
                        </div>
                        <div className="min-w-0">
                          <div className="text-[10px] font-black uppercase text-slate-400 tracking-widest mb-1">Birthday</div>
                          <div className="text-slate-900 dark:text-white font-bold text-lg truncate">
                            {editingContactData.birthday}
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

            <div className="flex flex-col sm:flex-row gap-3 p-6 border-t border-slate-100 dark:border-slate-800 shrink-0 bg-white dark:bg-slate-900">
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
                      {t(language, 'save')}
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
