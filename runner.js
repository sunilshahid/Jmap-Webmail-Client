import { spawn } from 'child_process';
import path from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

function startServer() {
  console.log('[Runner] Starting server...');
  const child = spawn('node', [path.join(__dirname, 'dist/server.cjs')], {
    stdio: 'inherit'
  });

  child.on('close', (code) => {
    console.log(`[Runner] Server exited with code ${code}. Restarting in 1s...`);
    setTimeout(startServer, 1000);
  });
}

startServer();
