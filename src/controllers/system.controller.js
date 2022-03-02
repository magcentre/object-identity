const { sendResult, sendError } = require('@magcentre/response-helper');
const processor = require('../processors/system.processor');

const getHealthCheck = (req, res) => {
  processor.getSystemInfo()
    .then((e) => sendResult(e, 200, res, req))
    .catch((e) => sendError(e, res, 500, req));
};

module.exports = {
  getHealthCheck,
};
