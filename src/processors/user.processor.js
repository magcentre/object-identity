const moment = require('moment');
const jwt = require('jsonwebtoken');
const { model } = require('../models/user.model');
const token = require('../models/token.model');
const config = require('../configuration/config');

/**
 * Generate token
 * @param {string} email
 * @returns {Promise<User>}
 */
const isEmailTaken = (email) => model.isEmailTaken(email);

/** row { statusCode: 400, message: "Incorr
 * Generate token
 * @param {ObjectId} userId
 * @param {Moment} expires
 * @param {string} type
 * @param {string} [secret]
 * @returns {string}
 */
const generateToken = (userId, expires, type, secret = config.jwt.secret) => {
  // payload to generate jwt token
  const payload = {
    sub: userId,
    iat: moment().unix(),
    exp: expires.unix(),
    type,
  };

  return jwt.sign(payload, secret);
};

/**
 * Create a user
 * @param {Object} userBody
 * @returns {Promise<User>}
 */
const createUser = (body) => model.create(body);

/**
 * Get user by id
 * @param {ObjectId} id
 * @returns {Promise<User>}
 */
const getUserById = (id) => model.findById(id, { password: 0 });

/**
 * Get user by email
 * @param {string} email
 * @returns {Promise<User>}
 */
const getUserByEmail = (email) => model.findOne({ email });

/**
 * Verify token and return token doc (or throw an error if it is not valid)
 * @param {string} token
 * @param {string} type
 * @returns {Promise<Token>}
 */
const verifyToken = (refreshToken) => {
  const payload = jwt.verify(refreshToken, config.jwt.secret);
  return token.model.findOne({
    token: refreshToken, type: token.types.REFRESH, user: payload.sub, blacklisted: false,
  });
};

/**
 * Generate auth tokens
 * @param {User} user
 * @returns {Promise<Object>}
 */
const generateAndSaveAuthToken = (user) => {
  // delete password match from user object
  delete user.match;

  // delete password from user object
  delete user.password;

  // generate access token expiry
  const accessTokenExpires = moment().add(config.jwt.accessExpirationMinutes, 'minutes');

  // generate access token
  const accessToken = generateToken(user._id, accessTokenExpires, token.types.ACCESS);

  // generate refresh token expiry
  const refreshTokenExpires = moment().add(config.jwt.refreshExpirationDays, 'days');

  // generate refresh token
  const refreshToken = generateToken(user._id, refreshTokenExpires, token.types.REFRESH);

  // return promise and store token in database
  return new Promise((resolve, reject) => {
    token.model.createToken({
      token: refreshToken,
      user: user._id,
      expires: refreshTokenExpires.toDate(),
      type: token.types.REFRESH,
      blacklisted: false,
    }, (err, newToken) => {
      if (err) return reject(err);
      return resolve({
        ...user,
        access: {
          token: accessToken,
          expires: accessTokenExpires.toDate(),
        },
        refresh: {
          token: newToken.token,
          expires: refreshTokenExpires.toDate(),
        },
      });
    });
  });
};

module.exports = {
  isEmailTaken,
  createUser,
  getUserById,
  getUserByEmail,
  generateAndSaveAuthToken,
  verifyToken,
};
