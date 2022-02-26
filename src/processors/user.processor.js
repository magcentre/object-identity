const moment = require('moment');
const jwt = require('jsonwebtoken');
const utils = require('@magcentre/api-utils');
const { model } = require('../models/user.model');
const token = require('../models/token.model');
const config = require('../configuration/config');
const { createBucket } = require('../constants');

/**
 * verify if the email is avalible to register
 * @param {string} email
 * @returns {Promise<User>}
 */
const isEmailTaken = (email, excludeUserId) => model.isEmailTaken(email, excludeUserId);

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

/**
 * Create a bucket for the verified user
 * @param {String} bucketName Bucket name to be created
 * @returns create bucket in minio for the user
 */
const createUserBucket = (bucketName) => utils.connect(createBucket, 'POST', { bucketName });

/**
 * Generate random 6 digit otp
 * @returns {Number} random 6 digit otp
 */
const generateOTP = () => Math.floor(Math.random() * 899999 + 100000);

const verifyUserAndGenerateOTP = (mobile) => new Promise((resolve, reject) => {
  const newOTP = generateOTP();
  model.verifyMobile(mobile)
    .then((user) => model.setOTP(mobile, newOTP))
    .then((e) => console.log(e))
    .catch((e) => reject(e));
});

const verifyMobile = (mobile) => new Promise((resolve, reject) => {
  model.verifyMobile(mobile)
    .then((user) => {
      if (!user) reject(new Error({ message: 'mobile does not exists', statusCode: 400 }));
      resolve('mast');
    })
    .catch((e) => reject(e));
});

module.exports = {
  isEmailTaken,
  createUser,
  getUserById,
  getUserByEmail,
  generateAndSaveAuthToken,
  verifyToken,
  updateProfile,
  id2object,
  search,
  createUserBucket,
  verifyUserAndGenerateOTP,
  verifyMobile,
};
