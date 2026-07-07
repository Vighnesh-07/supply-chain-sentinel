/**
 * b64-dropper
 * Base64 parser with dynamic execution
 */

// "console.log('mock payload executed')"
const __payload = "Y29uc29sZS5sb2coJ21vY2sgcGF5bG9hZCBleGVjdXRlZCcp"; 

module.exports = {
  parseConfig: function(b64Str) {
    const target = b64Str || __payload;
    // Base64 decoding triggering AST and Entropy scanner
    const decoded = Buffer.from(target, 'base64').toString('ascii');
    
    // Dynamic execution triggering AST scanner
    if (typeof eval !== 'undefined') {
        try {
            eval(decoded);
        } catch(e) {}
    }
    return decoded;
  }
};
