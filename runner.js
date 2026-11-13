import { spawn } from 'child_process';
import path from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

let restartCount = 0;
let lastRestartTime = Date.now();
let activeChild = null;

function startServer() {
  const now = Date.now();
  if (now - lastRestartTime < 10000) {
    restartCount++;
  } else {
    restartCount = 0;
  }
  lastRestartTime = now;

  if (restartCount > 5) {
    console.error('[Runner] Server crashed repeatedly (>5 times in 10s). Stopping runner to prevent crash loop.');
    process.exit(1);
  }

  console.log('[Runner] Starting server...');
  activeChild = spawn('node', [path.join(__dirname, 'dist/server.cjs')], {
    stdio: 'inherit'
  });

  activeChild.on('close', (code) => {
    activeChild = null;
    if (code === 0) {
      console.log('[Runner] Server exited cleanly.');
      return;
    }
    const delay = Math.min(1000 * Math.pow(2, restartCount), 15000);
    console.log(`[Runner] Server exited with code ${code}. Restarting in ${delay / 1000}s...`);
    setTimeout(startServer, delay);
  });
}

function handleSignal(signal) {
  console.log(`[Runner] Received ${signal}. Shutting down...`);
  if (activeChild) {
    activeChild.kill(signal);
  }
  process.exit(0);
}

process.on('SIGINT', () => handleSignal('SIGINT'));
process.on('SIGTERM', () => handleSignal('SIGTERM'));

startServer();
