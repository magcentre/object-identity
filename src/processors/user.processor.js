const moment = require('moment');
const jwt = require('jsonwebtoken');
const utils = require('@magcentre/api-utils');
const { model } = require('../models/user.model');
const token = require('../models/token.model');
const config = require('../configuration/config');
const { createBucket } = require('../constants');

/**
 * Generate token
 * @param {string} email
 * @returns {Promise<User>}
 */
const isEmailTaken = (email, excludeUserId) => new Promise((resolve, reject) => {
  model.isEmailTaken(email, excludeUserId)
    .then((e) => {
      if (e) reject(new Error('Email already exists'));
      resolve(true);
    })
    .catch((err) => reject(err));
});

/**
 * Check if account exists or not with provided email address
 * @param {string} email
 * @returns {Promise<User>}
 */
const verifyEmail = (email, excludeUserId) => new Promise((resolve, reject) => {
  model.isEmailTaken(email, excludeUserId)
    .then((e) => {
      if (e) reject(new Error('Email already exists'));
      resolve(true);
    })
    .catch((err) => reject(err));
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

/**
 * Create a user
 * @param {Object} userBody
 * @returns {Promise<User>}
 */
const createUser = (body) => new Promise((resolve, reject) => {
  let user = {};
  model.create(body)
    .then((newUser) => {
      user = newUser.toObject();
      return utils.connect(createBucket, 'POST', { bucketName: newUser._id.toHexString() });
    })
    .then(() => resolve(user))
    .catch((e) => reject(e));
});
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

const verifyEmailAndPassword = (email, password) => new Promise((resolve, reject) => {
  model.getUserByEmail(email)
    .then((user) => user.isPasswordMatch(password))
    .then((user) => resolve(user))
    .catch((err) => reject(err));
});

/**
 * Verify token and return token doc (or throw an error if it is not valid)
 * @param {string} token
 * @param {string} type
 * @returns {Promise<Token>}
 */
const verifyToken = (refreshToken) => new Promise((resolve, reject) => {
  utils.verifyJWTToken(refreshToken, config.jwt.secret)
    .then((decoded) => token.model.findToken({
      token: refreshToken, type: token.types.REFRESH, user: decoded.sub, blacklisted: false,
    }))
    .then((tokenResponse) => resolve(tokenResponse))
    .catch((err) => reject(err));
});

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

const createUserBucket = (bucketName) => utils.connect(createBucket, 'POST', { bucketName });

module.exports = {
  isEmailTaken,
  verifyEmailAndPassword,
  verifyEmail,
  createUser,
  getUserById,
  getUserByEmail,
  generateAndSaveAuthToken,
  verifyToken,
  updateProfile,
  id2object,
  search,
  createUserBucket,
};
