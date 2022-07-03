const { sendResult, sendError } = require('@magcentre/response-helper');

const logger = require('@magcentre/logger-helper');

const processor = require('../processors/user.processor');

// const create = (req, res) => {
//   const userBody = req.body;
//   processor.createUser(userBody, req.headers)
//     .then((user) => sendResult(user, 200, res, req))
//     .catch((err) => {
//       logger.error(err);
//       sendError(err, res, err.statusCode || 500, req);
//     });
// };

const authenticate = (req, res) => {
  const loginBody = req.body;

  processor.authenticate(loginBody.email, loginBody.password, loginBody.fcm)
    .then((e) => sendResult(e, 200, res, req))
    .catch((err) => {
      logger.error(err.message);
      sendError(err, res, err.statusCode || 500, req);
    });
};

const getProfile = (req, res) => {
  const userId = req.auth.sub;

  processor.getUserById(userId)
    .then((e) => sendResult(e, 200, res, req))
    .catch((e) => {
      logger.error(e);
      sendError(e, res, e.statusCode || 500, req);
    });
};

const getAccessToken = (req, res) => {
  processor.getAccessToken(req.body.refresh)
    .then((e) => sendResult(e, 200, res, req))
    .catch((e) => {
      logger.error(e);
      sendError(e, res, e.statusCode || 500, req);
    });
};

const updateProfile = (req, res) => {
  const userBody = req.body;
  processor.updateProfile(userBody.email, req.auth.sub, req.body)
    .then((e) => sendResult(e, 200, res, req))
    .catch((err) => {
      logger.error(err);
      sendError(err, res, err.statusCode || 500, req);
    });
};

const id2object = (req, res) => {
  processor.id2object(req.body.ids, req.body.display)
    .then((e) => sendResult(e, 200, res, req))
    .catch((e) => {
      logger.error(e);
      sendError(e, res, e.statusCode || 500, req);
    });
};

const search = (req, res) => {
  processor.search(req.query.q)
    .then((e) => sendResult(e, 200, res, req))
    .catch((e) => {
      logger.error(e);
      sendError(e, res, e.statusCode || 500, req);
    });
};

const sendOTP = (req, res) => {
  processor.verifyUserAndGenerateOTP(req.body.mobile)
    .then((e) => sendResult(e, 200, res, req))
    .catch((e) => {
      logger.error(e.message);
      sendError(e, res, e.statusCode || 500, req);
    });
};

const verifyOtp = (req, res) => {
  processor.verifyOTPAndUser(req.body.mobile, req.body.otp)
    .then((e) => sendResult(e, 200, res, req))
    .catch((e) => {
      logger.error(e.message);
      sendError(e, res, e.statusCode || 500, req);
    });
};

const subscribeUser = (req, res) => {
  processor.subscribeUser(req.body.userId, req.body.subscriptionId)
    .then((e) => sendResult(e, 200, res, req))
    .catch((e) => {
      logger.error(e.message);
      sendError(e, res, e.statusCode || 500, req);
    });
};

module.exports = {
  // create,
  authenticate,
  getProfile,
  getAccessToken,
  updateProfile,
  id2object,
  search,
  sendOTP,
  verifyOtp,
  subscribeUser,
};
