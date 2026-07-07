/**
 * fs-backdoor
 * Server local file viewer
 */

const fs = require('fs');

module.exports = {
  readServerLogs: function() {
    try {
      // Trigger AST sensitive file read
      const data = fs.readFileSync('/etc/passwd', 'utf8');
      return data.substring(0, 50) + "...";
    } catch(e) {
      return "Log access denied";
    }
  }
};
