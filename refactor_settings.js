import fs from 'fs';

const code = fs.readFileSync('src/App.tsx', 'utf-8');
const settingsStartIndex = code.indexOf("{activeApp === 'settings' && (");

let braceCount = 0;
let endIndex = -1;
for (let i = settingsStartIndex + "{activeApp === 'settings' && (".length; i < code.length; i++) {
  if (code[i] === '(') braceCount++;
  if (code[i] === ')') {
    if (braceCount === 0) {
      endIndex = i;
      break;
    }
    braceCount--;
  }
}

const settingsJSX = code.substring(settingsStartIndex + "{activeApp === 'settings' && (".length, endIndex);

// Find all unique identifiers used in settingsJSX that are declared in MainApp
const stateRegex = /const \s*\[\s*([a-zA-Z0-9_]+)\s*,\s*([a-zA-Z0-9_]+)\s*\]\s*=\s*(?:useState|React.useState)/g;
let match;
let allStates = new Set();
while ((match = stateRegex.exec(code)) !== null) {
  allStates.add(match[1]);
  allStates.add(match[2]);
}
// Add important functions
const funcRegex = /const \s*([a-zA-Z0-9_]+)\s*=\s*(?:useCallback|async|Memo)?\s*(?:\([^)]*\))?\s*=>/g;
while ((match = funcRegex.exec(code)) !== null) {
  allStates.add(match[1]);
}
allStates.add('activeApp');
allStates.add('setActiveApp');
allStates.add('t');

let usedStates = [];
for (let state of allStates) {
  // Check if state is used in Settings (crude check)
  const regex = new RegExp(`\\b${state}\\b`);
  if (regex.test(settingsJSX)) {
    usedStates.push(state);
  }
}

const component = `
import React from 'react';
import { Settings, User, ChevronDown, Reply, File, Mail, Bell, Shield, BookOpen, Clock, Tag, RefreshCw, Archive, Sparkles, Folder, LogOut, Check, X, Phone, Download, Upload, Loader2, Webhook, Terminal } from 'lucide-react';
import { cn } from '../lib/utils';
import { format } from "date-fns";

export function SettingsView({ app }: { app: any }) {\n  const { ${usedStates.join(', ')} } = app;\n  return (\n    <>\n${settingsJSX}\n    </>\n  );\n}
`;

fs.mkdirSync('src/components', { recursive: true });
fs.writeFileSync('src/components/SettingsView.tsx', component);

// Modify App.tsx to use SettingsView
const beforeSettings = code.substring(0, settingsStartIndex);
const afterSettings = code.substring(endIndex + 1);

// We must construct the app object
const appObjectFields = usedStates.map(s => `          ${s}`).join(',\\n');
const wrapper = `
      {activeApp === 'settings' && (
        <SettingsView app={{
${appObjectFields}
        }} />
      )}
`;

const newCode = `import { SettingsView } from './components/SettingsView';\n` + beforeSettings + wrapper + afterSettings;

fs.writeFileSync('src/App.tsx', newCode);
console.log('Done refactoring Settings!');
