export default {
  formatJson: (json) => JSON.stringify(json, null, 2),
  validateJson: (json) => true,
  minifyJson: (json) => JSON.stringify(json),
  getStats: (json) => ({ size: JSON.stringify(json).length })
};
