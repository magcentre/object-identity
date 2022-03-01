const moment = require('moment');
const jwt = require('jsonwebtoken');
const utils = require('@magcentre/api-utils');
const { getRichError } = require('@magcentre/response-helper');
const logger = require('@magcentre/logger-helper');
const { model } = require('../models/user.model');
const token = require('../models/token.model');
const config = require('../configuration/config');
const { createBucket } = require('../constants');

/**
 * Check if account exists or not with provided email address
 * @param {string} email
 * @returns {Promise<User>}
 */
const verifyEmail = (email, excludeUserId) => model.isEmailTaken(email, excludeUserId)
  .then((user) => {
    if (user) throw getRichError('Parameter', 'Email already exists', { user }, null, 'error', null);
    return user;
  });

/**
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

const createUserBucket = (bucketName) => utils.connect(createBucket, 'POST', { bucketName });

/**
 * Create a user
 * Verify email address before creating the account
 * Once the email is verified, the new account entry will be created
 * Account creation is completed followed by the bucket creation for newly created account
 * @param {Object} userBody
 * @returns {Promise<User>}
 */
const createUser = (body) => {
  let user = {};
  return verifyEmail(body.email)
    .then(() => model.createUserAccount(body))
    .then((newUser) => {
      user = newUser.toObject();
      return utils.connect(createBucket, 'POST', { bucketName: newUser._id.toHexString() });
    })
    .then(() => {
      logger.info('User account created', {
        user,
      });
      return user;
    });
};

/**
 * Get user by id
 * @param {ObjectId} id
 * @returns {Promise<User>}
 */
const getUserById = (id) => model.getUserById(id);

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
  return token.model.createToken({
    token: refreshToken,
    user: user._id,
    expires: refreshTokenExpires.toDate(),
    type: token.types.REFRESH,
    blacklisted: false,
  })
    .then((newToken) => ({
      ...user,
      access: {
        token: accessToken,
        expires: accessTokenExpires.toDate(),
      },
      refresh: {
        token: newToken.token,
        expires: refreshTokenExpires.toDate(),
      },
    }));
};

const authenticate = (email, password) => model.getUserByEmail(email)
  .then((user) => {
    if (!user) throw getRichError('ParameterError', 'Invalid email', { email }, null, 'error', null);
    return user;
  })
  .then((user) => user.isPasswordMatch(password))
  .then((userWithPassword) => {
    if (!userWithPassword.match) throw getRichError('ParameterError', 'Invalid password', { match: userWithPassword.match }, null, 'error', null);
    return userWithPassword;
  })
  .then((user) => generateAndSaveAuthToken(user));

/**
 * Verify token and return token doc (or throw an error if it is not valid)
 * @param {string} token
 * @param {string} type
 * @returns {Promise<Token>}
 */
const verifyToken = (refreshToken) => utils.verifyJWTToken(refreshToken, config.jwt.secret)
  .catch((err) => {
    throw getRichError('UnAuthorized', 'Failed to verify refresh token', { err }, null, 'error', null);
  })
  .then((decoded) => token.model.findToken({
    token: refreshToken, type: token.types.REFRESH, user: decoded.sub, blacklisted: false,
  }))
  .then((oldToken) => {
    if (!oldToken) throw getRichError('UnAuthorized', 'Not a valid refresh token', { oldToken }, null, 'error', null);
    return oldToken.remove();
  });

/**
 * Update the user profile
 * @param {string} id user id
 * @param {string} param json object of field and values to be updated
 * @returns {Promise<Token>}
 */
const updateProfile = (id, param) => model.update({ _id: id }, { $set: param });

/**
 * Convert list of userIds into objects
 * @param {List<String>} ids user id
 * * @param {List<String>} display display parameters
 * @returns {Promise<List<User>>}
 */
const id2object = (ids, display) => model.find({ _id: { $in: ids } }, display);

/**
 * Convert list of userIds into objects
 * @param {List<String>} ids user id
 * * @param {List<String>} display display parameters
 * @returns {Promise<List<User>>}
 */
const search = (q) => model.find({ $or: [{ firstName: { $regex: q } }, { lastName: { $regex: q } }] }, { firstName: 1, lastName: 1, email: 1 });

module.exports = {
  authenticate,
  verifyEmail,
  createUser,
  getUserById,
  generateAndSaveAuthToken,
  verifyToken,
  updateProfile,
  id2object,
  search,
  createUserBucket,
};
