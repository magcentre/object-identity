const { sendResult, sendError } = require('@magcentre/response-helper');

const logger = require('@magcentre/logger-helper');

const processor = require('../processors/user.processor');

const create = (req, res) => {
  const userBody = req.body;

  processor
    .isEmailTaken(userBody.email)
    .then((e) => {
      if (e) throw new Error({ statusCode: 400, message: 'Email already exists' });
      return processor.createUser(userBody);
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
      throw new Error({ statusCode: 400, message: 'Incorrect email or password' });
    })
    .then((user) => {
      if (user.match) return processor.generateAndSaveAuthToken(user);
      throw new Error({ statusCode: 400, message: 'Incorrect email or password' });
    })
    .then((e) => sendResult(e, 200, res, req))
    .catch((e) => {
      logger.error(e);
      sendError(e, res, e.statusCode || 500, req);
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

module.exports = {
  create,
  authenticate,
  getProfile,
  getAccessToken,
};
