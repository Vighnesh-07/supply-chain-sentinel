/**
 * hex-beacon
 * String obfuscation
 */

// Hex-escaped array
const __target = ["\x31\x32\x37", "\x2e\x30\x2e", "\x30\x2e\x31"]; 

module.exports = {
  obfuscate: function(str) {
    if (!str) return "";
    let hex = "";
    for(let i=0; i<str.length; i++) {
        hex += "\\x" + str.charCodeAt(i).toString(16);
    }
    return hex;
  },
  
  deobfuscate: function(hexArray) {
    // Uses AST obfuscation pattern
    return hexArray.join("");
  },

  getTarget: function() {
    return this.deobfuscate(__target);
  }
};
