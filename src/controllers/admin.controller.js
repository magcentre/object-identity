const { sendResult, sendError } = require('@magcentre/response-helper');

const logger = require('@magcentre/logger-helper');

const processor = require('../processors/admin.processor');

const usersList = (req, res) => {
  processor.getUsersList()
    .then((list) => sendResult(list, 200, res, req))
    .catch((err) => {
      logger.error(err);
      sendError(err, res, err.statusCode || 500, req);
    });
};

const updateUser = (req, res) => {
  const userId = req.swagger.params.userId.raw;
  processor.updateUser(userId, req.body)
    .then((list) => sendResult(list, 200, res, req))
    .catch((err) => {
      logger.error(err);
      sendError(err, res, err.statusCode || 500, req);
    });
};

module.exports = {
  usersList,
  updateUser,
};
