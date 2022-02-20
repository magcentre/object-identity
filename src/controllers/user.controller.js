const { sendResult, sendError } = require('@magcentre/response-helper');

const logger = require('@magcentre/logger-helper');

const processor = require('../processors/user.processor');

const create = (req, res) => {
  const userBody = req.body;
  processor
    .verifyEmail(userBody.email)
    .then(() => processor.createUser(userBody, req.headers))
    .then((user) => sendResult(user, 200, res, req))
    .catch((err) => {
      logger.error(err.message);
      sendError(err, res, err.statusCode || 500, req);
    });
};

const authenticate = (req, res) => {
  const loginBody = req.body;

  processor.verifyEmailAndPassword(loginBody.email, loginBody.password)
    .then((user) => processor.generateAndSaveAuthToken(user))
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

module.exports = {
  create,
  authenticate,
  getProfile,
  getAccessToken,
  updateProfile,
  id2object,
  search,
};
