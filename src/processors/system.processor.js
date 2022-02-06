
const si = require('systeminformation');

const getSystemInfo = () => si.cpu();

module.exports = {
  getSystemInfo,
};
