const jwt = require('jsonwebtoken');

const config = require('../configuration/config');

const { sendError } = require('@magcentre/response-helper');

module.exports.jwt = function (req, res, next) {

    if (!req.headers.authorization) return sendError('Authentication required', res, 401, req);

    jwt.verify(req.headers.authorization.replace('Bearer ',''), config.jwt.secret, function (error, decoded, info) {

        if (error) return sendError('Error in JWT authentication process', res, 500, req);

        if (!decoded) return sendError('Authentication failed,: ' + info, res, 401, req);

        req.auth = decoded;

        return next();
    });
};