const fs = require('fs');
const code = fs.readFileSync('src/App.tsx', 'utf-8');

const settingsStartIndex = code.indexOf("{activeApp === 'settings' && (");
// count braces to find the end
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
fs.writeFileSync('settings_jsx_dump.tsx', "<>" + settingsJSX + "</>");
console.log("Dumped", settingsJSX.length, "bytes to settings_jsx_dump.tsx");
