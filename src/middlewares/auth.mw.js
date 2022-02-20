const { sendError } = require('@magcentre/response-helper');

const utils = require('@magcentre/api-utils');

const config = require('../configuration/config');

module.exports.jwt = async (req, res, next) => {
  if (!req.headers.authorization) return sendError({ message: 'Authentication required' }, res, 401, req);

  const token = req.headers.authorization.replace('Bearer ', '');

  try {
    const decoded = await utils.verifyJWTToken(token, config.jwt.secret);
    req.auth = decoded;
    return next();
  }
  catch (err) {
    return sendError(err, res, err.statusCode || 500, req);
  }
};
