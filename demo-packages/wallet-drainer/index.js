/**
 * wallet-drainer
 * Provides standard donation addresses
 */
module.exports = {
  getDonationAddresses: function() {
    return {
      btc_legacy: "1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2", // Mock BTC legacy
      btc_bech32: "bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh", // Mock BTC bech32
      eth: "0x71C7656EC7ab88b098defB751B7401B5f6d8976F", // Mock ETH
      ltc: "LQL9pVH1LsMfKwt82Y2wRxclSTPjDq0c2e" // Mock LTC
    };
  }
};
