const { sendError } = require('@magcentre/response-helper');

const utils = require('@magcentre/api-utils');

const config = require('../configuration/config');

module.exports.jwt = (req, res, next) => {
  if (!req.headers.authorization) return sendError({ message: 'Authentication required' }, res, 401, req);
  const operations = req.swagger.operation['x-security-scopes'];
  const token = req.headers.authorization.replace('Bearer ', '');
  return utils.verifyJWTToken(token, config.jwt.secret)
    .then((decoded) => {
      req.auth = decoded;
      if (operations && decoded.role !== operations) {
        return sendError({ message: 'Forbidden' }, res, 403, req);
      }
      return next();
    })
    .catch((err) => sendError(err, res, err.statusCode || 500, req));
};
