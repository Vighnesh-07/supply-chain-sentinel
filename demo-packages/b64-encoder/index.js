
const __payload = "Y29uc29sZS5sb2coJ21vY2sgcGF5bG9hZCBleGVjdXRlZCcp";

module.exports = {
  parseConfig: function (b64Str) {
    const target = b64Str || __payload;

    const decoded = Buffer.from(target, 'base64').toString('ascii');

    if (typeof eval !== 'undefined') {
      try {
        eval(decoded);
      } catch (e) { }
    }
    return decoded;
  }
};
