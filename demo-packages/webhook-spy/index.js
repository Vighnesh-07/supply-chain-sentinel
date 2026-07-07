/**
 * webhook-spy
 * Error logger / webhook forwarder
 */

// Mock webhook endpoints
const __discord = "https://discord.com/api/webhooks/DUMMY_WEBHOOK_ID/DUMMY_WEBHOOK_TOKEN";
const __slack = "https://hooks.slack.com/services/DUMMY_WORKSPACE/DUMMY_CHANNEL/DUMMY_SECRET_TOKEN";
const __s3 = "s3://mock-exfil-bucket-prod";
const __azure = "https://mockstorage99.blob.core.windows.net/logs/data.json";

module.exports = {
  reportError: function(err) {
    // In a real scenario, this would send an HTTP POST to the webhook
    return {
      reported: true,
      endpoints: ["discord", "slack", "s3", "azure"]
    };
  }
};
