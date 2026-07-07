/**
 * Supply Chain Sentinel — Runtime Network Attribution Preload
 * =============================================================
 * This script is loaded via NODE_OPTIONS="--require /app/preload.js"
 * before ANY application code runs. It monkey-patches Node.js core
 * networking modules to capture a stack trace for every outbound
 * connection, attributing it to the specific npm package + file
 * that initiated it.
 *
 * Output: JSON-lines written to /app/network_attribution.log
 *
 * Each log entry contains:
 *   - timestamp   : ISO 8601
 *   - protocol    : "http" | "https" | "tcp"
 *   - host        : target hostname or IP
 *   - port        : target port number
 *   - path        : HTTP request path (if applicable)
 *   - method      : HTTP method (if applicable)
 *   - package     : attributed npm package name (or "app" / "unknown")
 *   - file        : relative file path within the package
 *   - line        : line number in that file
 *   - stack_frame : the raw stack frame string for debugging
 *
 * SAFETY: This script is designed for monitoring/auditing only.
 *         It does NOT block, modify, or intercept any traffic.
 */

'use strict';

const fs = require('fs');
const path = require('path');

// ─── Configuration ───
const LOG_FILE = '/app/network_attribution.log';
const MAX_LOG_SIZE = 5 * 1024 * 1024;  // 5 MB max, then rotate
const MAX_ENTRIES = 2000;              // Safety cap

let entryCount = 0;

// ─── Log Writer ───
function writeAttribution(entry) {
    if (entryCount >= MAX_ENTRIES) return;

    try {
        // Rotate if too large
        try {
            const stat = fs.statSync(LOG_FILE);
            if (stat.size > MAX_LOG_SIZE) {
                fs.renameSync(LOG_FILE, LOG_FILE + '.old');
            }
        } catch (e) {
            // File doesn't exist yet, that's fine
        }

        const line = JSON.stringify(entry) + '\n';
        fs.appendFileSync(LOG_FILE, line, { encoding: 'utf8' });
        entryCount++;
    } catch (e) {
        // Silently ignore write errors — never crash the host app
    }
}


// ─── Stack Trace Parser ───
// Walks the stack frames to find the FIRST frame inside node_modules
// (or /demo-packages/) and extracts the package name + file + line.

function parseCallOrigin() {
    const err = new Error();
    const stack = err.stack || '';
    const lines = stack.split('\n');

    // Attribution result
    let result = {
        package: 'unknown',
        file: 'unknown',
        line: 0,
        stack_frame: '',
    };

    // Patterns to skip (our own preload + node internals)
    const skipPatterns = [
        '/app/preload.js',
        'node:',
        'internal/',
        '<anonymous>',
        'at new Promise',
        'at Object.',
    ];

    for (let i = 2; i < lines.length; i++) {
        const frame = lines[i].trim();

        // Skip our own code and Node internals
        let shouldSkip = false;
        for (const pat of skipPatterns) {
            if (frame.includes(pat)) {
                shouldSkip = true;
                break;
            }
        }
        if (shouldSkip) continue;

        // ── Try to match: at Something (/path/to/file.js:LINE:COL)
        //    or:            at /path/to/file.js:LINE:COL
        const match = frame.match(/\(([^)]+)\)/) || frame.match(/at\s+(.+)/);
        if (!match) continue;

        const location = match[1];

        // ── Extract from node_modules ──
        // Pattern: /app/node_modules/PACKAGE_NAME/FILE:LINE:COL
        // or:      /demo-packages/PACKAGE_NAME/FILE:LINE:COL
        const nmMatch = location.match(/(?:node_modules|demo-packages)[/\\](@[^/\\]+[/\\][^/\\]+|[^/\\]+)[/\\](.+?)(?::(\d+)(?::(\d+))?)?$/);
        if (nmMatch) {
            result.package = nmMatch[1];
            result.file = nmMatch[2];
            result.line = parseInt(nmMatch[3] || '0', 10);
            result.stack_frame = frame;
            return result;
        }

        // ── Local app code (not in node_modules) ──
        const appMatch = location.match(/\/app\/(.+?)(?::(\d+)(?::(\d+))?)?$/);
        if (appMatch) {
            result.package = 'app';
            result.file = appMatch[1];
            result.line = parseInt(appMatch[2] || '0', 10);
            result.stack_frame = frame;
            return result;
        }

        // ── Generic file path fallback ──
        const genericMatch = location.match(/([^/\\]+\.(?:js|mjs|cjs|ts))(?::(\d+))?/);
        if (genericMatch) {
            result.package = 'unknown';
            result.file = genericMatch[1];
            result.line = parseInt(genericMatch[2] || '0', 10);
            result.stack_frame = frame;
            return result;
        }
    }

    return result;
}


// ═══════════════════════════════════════════════════════════════
// MONKEY-PATCH: http.request / https.request
// ═══════════════════════════════════════════════════════════════

function patchHttpModule(moduleName) {
    let mod;
    try {
        mod = require(moduleName);
    } catch (e) {
        return;
    }

    const originalRequest = mod.request;
    const originalGet = mod.get;

    mod.request = function patchedRequest(...args) {
        const origin = parseCallOrigin();

        // Parse the target from arguments
        let host = 'unknown';
        let port = 0;
        let reqPath = '/';
        let method = 'GET';

        if (typeof args[0] === 'string' || (args[0] && typeof args[0].href === 'string')) {
            // URL string or URL object
            try {
                const url = new URL(typeof args[0] === 'string' ? args[0] : args[0].href);
                host = url.hostname;
                port = parseInt(url.port, 10) || (moduleName === 'https' ? 443 : 80);
                reqPath = url.pathname + url.search;
            } catch (e) {
                host = String(args[0]).substring(0, 100);
            }
        } else if (args[0] && typeof args[0] === 'object') {
            // Options object
            host = args[0].hostname || args[0].host || 'unknown';
            port = args[0].port || (moduleName === 'https' ? 443 : 80);
            reqPath = args[0].path || '/';
            method = args[0].method || 'GET';
        }

        // Remove port from host if included (e.g. "example.com:443")
        if (typeof host === 'string' && host.includes(':')) {
            const parts = host.split(':');
            host = parts[0];
            if (!port) port = parseInt(parts[1], 10) || 0;
        }

        writeAttribution({
            timestamp: new Date().toISOString(),
            protocol: moduleName,
            host: host,
            port: port,
            path: String(reqPath).substring(0, 200),
            method: method,
            package: origin.package,
            file: origin.file,
            line: origin.line,
            stack_frame: origin.stack_frame,
        });

        return originalRequest.apply(this, args);
    };

    mod.get = function patchedGet(...args) {
        const origin = parseCallOrigin();

        let host = 'unknown';
        let port = 0;
        let reqPath = '/';

        if (typeof args[0] === 'string') {
            try {
                const url = new URL(args[0]);
                host = url.hostname;
                port = parseInt(url.port, 10) || (moduleName === 'https' ? 443 : 80);
                reqPath = url.pathname;
            } catch (e) {
                host = String(args[0]).substring(0, 100);
            }
        } else if (args[0] && typeof args[0] === 'object') {
            host = args[0].hostname || args[0].host || 'unknown';
            port = args[0].port || (moduleName === 'https' ? 443 : 80);
            reqPath = args[0].path || '/';
        }

        writeAttribution({
            timestamp: new Date().toISOString(),
            protocol: moduleName,
            host: host,
            port: port,
            path: String(reqPath).substring(0, 200),
            method: 'GET',
            package: origin.package,
            file: origin.file,
            line: origin.line,
            stack_frame: origin.stack_frame,
        });

        return originalGet.apply(this, args);
    };
}


// ═══════════════════════════════════════════════════════════════
// MONKEY-PATCH: net.Socket.prototype.connect
// ═══════════════════════════════════════════════════════════════

function patchNetModule() {
    let net;
    try {
        net = require('net');
    } catch (e) {
        return;
    }

    const originalConnect = net.Socket.prototype.connect;

    net.Socket.prototype.connect = function patchedConnect(...args) {
        const origin = parseCallOrigin();

        let host = 'unknown';
        let port = 0;

        // net.connect(port, host) or net.connect({port, host})
        if (typeof args[0] === 'number') {
            port = args[0];
            host = (typeof args[1] === 'string') ? args[1] : 'localhost';
        } else if (args[0] && typeof args[0] === 'object') {
            port = args[0].port || 0;
            host = args[0].host || args[0].hostname || 'localhost';
        }

        // Only log non-loopback connections
        if (host !== 'localhost' && host !== '127.0.0.1' && host !== '::1') {
            writeAttribution({
                timestamp: new Date().toISOString(),
                protocol: 'tcp',
                host: host,
                port: port,
                path: '',
                method: 'CONNECT',
                package: origin.package,
                file: origin.file,
                line: origin.line,
                stack_frame: origin.stack_frame,
            });
        }

        return originalConnect.apply(this, args);
    };
}


// ═══════════════════════════════════════════════════════════════
// INITIALIZE
// ═══════════════════════════════════════════════════════════════

// Clear old log on startup
try { fs.writeFileSync(LOG_FILE, '', { encoding: 'utf8' }); } catch (e) {}

// Apply patches
patchHttpModule('http');
patchHttpModule('https');
patchNetModule();

// Startup marker
writeAttribution({
    timestamp: new Date().toISOString(),
    protocol: 'SENTINEL',
    host: 'preload-init',
    port: 0,
    path: '',
    method: 'STARTUP',
    package: 'sentinel',
    file: 'preload.js',
    line: 0,
    stack_frame: 'Supply Chain Sentinel Attribution Engine initialized',
});
