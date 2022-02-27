const { sendResult, sendError } = require('@magcentre/response-helper');

const logger = require('@magcentre/logger-helper');

const processor = require('../processors/user.processor');

const create = (req, res) => {
  const userBody = req.body;
  processor
    .isEmailTaken(userBody.email)
    .then((e) => {
      if (e) throw new Error({ statusCode: 400, message: 'Email already exists' });
      return processor.createUser(userBody, req.headers);
    })
    .then((e) => sendResult(e, 200, res, req))
    .catch((e) => {
      logger.error(e);
      sendError(e, res, e.statusCode || 500, req);
    });
};

const authenticate = (req, res) => {
  const loginBody = req.body;

  processor.getUserByEmail(loginBody.email)
    .then((user) => {
      if (user) return user.isPasswordMatch(loginBody.password);
      sendError('Unregisted email address', res, 400, req);
    })
    .then((user) => {
      if (user.match) return processor.generateAndSaveAuthToken(user);
      sendError('Invalid email and password', res, 400, req);
    })
    .then((e) => sendResult(e, 200, res, req))
    .catch((e) => {
      logger.error(e);
      sendError(e.message, res, e.statusCode || 500, req);
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
  processor.verifyToken(req.body.refresh)
    .then((token) => {
      if (!token) throw new Error({ statusCode: 401, message: 'Not a valid refresh token' });
      return token.remove();
    })
    .then((token) => {
      const { user } = token;
      return processor.generateAndSaveAuthToken({
        _id: user,
      });
    })
    .then((e) => sendResult(e, 200, res, req))
    .catch((e) => {
      logger.error(e);
      sendError(e, res, e.statusCode || 500, req);
    });
};

const updateProfile = (req, res) => {
  const userBody = req.body;

  processor.isEmailTaken(userBody.email, req.auth.sub)
    .then(() => processor.updateProfile(req.auth.sub, req.body))
    .then(() => processor.getUserById(req.auth.sub))
    .then((e) => sendResult(e, 200, res, req))
    .catch((e) => {
      logger.error(e);
      sendError(e.message, res, e.statusCode || 500, req);
    });
};

const id2object = (req, res) => {
  processor.id2object(req.body.ids, req.body.display)
    .then((e) => sendResult(e, 200, res, req))
    .catch((e) => {
      logger.error(e);
      sendError(e.message, res, e.statusCode || 500, req);
    });
};

const search = (req, res) => {
  processor.search(req.query.q)
    .then((e) => sendResult(e, 200, res, req))
    .catch((e) => {
      logger.error(e);
      sendError(e.message, res, e.statusCode || 500, req);
    });
};

const sendOTP = (req, res) => {
  processor.verifyUserAndGenerateOTP(req.body.mobile)
    .then((e) => sendResult(e, 200, res, req))
    .catch((e) => {
      logger.error(e.message);
      sendError(e.message, res, e.statusCode || 500, req);
    });
};

const verifyOtp = (req, res) => {
  processor.verifyOtp(req.body.mobile, req.body.otp)
    .then((user) => processor.isNewRegistration(user))
    .then((user) => processor.generateAndSaveAuthToken(user.toObject()))
    .then((e) => sendResult(e, 200, res, req))
    .catch((e) => {
      logger.error(e.message);
      sendError(e.message, res, e.statusCode || 500, req);
    });
};

module.exports = {
  create,
  authenticate,
  getProfile,
  getAccessToken,
  updateProfile,
  id2object,
  search,
  sendOTP,
  verifyOtp,
};
