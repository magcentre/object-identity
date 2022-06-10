const moment = require('moment');
const jwt = require('jsonwebtoken');
const utils = require('@magcentre/api-utils');
const { getRichError } = require('@magcentre/response-helper');
const logger = require('@magcentre/logger-helper');
const { UserModel } = require('../models/user.model');
const { TokenModel, tokenTypes } = require('../models/token.model');
const config = require('../configuration/config');
const {
  bucketExists, createBucket, sendOTP, otpTemplate,
} = require('../constants');

/**
 * verify if the email is avalible to register
 * @param {string} email
 * @returns {Promise<User>}
 */
const verifyEmail = (email, excludeUserId) => UserModel.isEmailTaken(email, excludeUserId)
  .then((user) => {
    if (user) {
      const message = 'Account with same Email already exists';
      throw getRichError('Parameter', 'Validation', { email: user.email, message }, message, 'error', null);
    }
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
const generateToken = (userId, role, expires, type, secret = config.jwt.secret) => {
  // payload to generate jwt token
  const payload = {
    sub: userId,
    iat: moment().unix(),
    exp: expires.unix(),
    role,
    type,
  };

  return jwt.sign(payload, secret);
};

/**
 * Create a new bucket with provided bucket name
 * @param {String} bucketName bucketName to be created
 * @returns Axios response
 */
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
    .then(() => UserModel.verifyMobile(body.mobile))
    .then((userSearched) => {
      if (userSearched) {
        const errorMessage = 'Account with same mobile number already exists';
        throw getRichError('ParameterError', errorMessage, { mobile: body.mobile, message: errorMessage }, errorMessage, 'error', null);
      }
      return userSearched;
    })
    .then(() => UserModel.createUser(body))
    .then((newUser) => {
      user = newUser.toObject();
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
const getUserById = (id) => UserModel.getUserById(id);

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
  const accessToken = generateToken(user._id, user.role, accessTokenExpires, tokenTypes.ACCESS);

  // generate refresh token expiry
  const refreshTokenExpires = moment().add(config.jwt.refreshExpirationDays, 'days');

  // generate refresh token
  const refreshToken = generateToken(user._id, user.role, refreshTokenExpires, tokenTypes.REFRESH);

  // return promise and store token in database
  return TokenModel.createToken({
    token: refreshToken,
    user: user._id,
    expires: refreshTokenExpires.toDate(),
    type: tokenTypes.REFRESH,
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

/**
 * Verify if the bucket of the user exists before allowing user to login into the portl
 * @param {String} userId userid of user to verify the bucket present in minio via container
 * @param {*} user user object to return if the user bucket exists
 * @returns
 */
const verifyBucket = (userId, user) => utils.connect(bucketExists, 'POST', { bucketName: userId })
  .catch((err) => {
    throw getRichError('System', 'Bucket does not exists for the user', { userId, user }, err, 'error', null);
  })
  .then(() => user);

/**
 * Authenticate user with email and password
 * verify email address if exists
 * match provided password and registered password
 * verify the bucket of the user in minio
 * generate the access token and refresh token
 * @param {String} email Registered email address
 * @param {String} password Password
 * @returns User
 */

const authenticate = (email, password, fcmToken) => UserModel.getUserByEmail(email)
  .then((user) => {
    if (!user) throw getRichError('ParameterError', 'Invalid email', { email }, null, 'error', null);
    return user;
  })
  .then((user) => user.isPasswordMatch(password))
  .then((userWithPassword) => {
    if (!userWithPassword.match) throw getRichError('ParameterError', 'Invalid password', { match: userWithPassword.match }, null, 'error', null);
    if (!userWithPassword.isVerified) {
      throw getRichError('ParameterError', 'Your account is not verified, please verify account and try again', { verified: userWithPassword.isVerified }, null, 'error', null);
    }
    if (userWithPassword.isBlocked) {
      throw getRichError('ParameterError', 'Your account is blocked, please contact support', { blocked: userWithPassword.isBlocked }, null, 'error', null);
    }
    return userWithPassword;
  })
  .then((user) => verifyBucket(user._id, user))
  .then((user) => UserModel.updateProfile(user._id, { fcmToken }))
  .then((user) => generateAndSaveAuthToken(user.toObject()));

/**
 * Verify Token
 * Verify currently provided refresh token
 * delete existing token from the db
 * create new refresh token and access token and store into database
 * @param {string} token
 * @returns {Promise<Token>}
 */
const getAccessToken = (refreshToken) => utils.verifyJWTToken(refreshToken, config.jwt.secret)
  .catch((err) => {
    throw getRichError('UnAuthorized', 'Failed to verify refresh token', { err }, null, 'error', null);
  })
  .then((decoded) => TokenModel.findToken({
    token: refreshToken, type: tokenTypes.REFRESH, user: decoded.sub, blacklisted: false,
  }))
  .then((oldToken) => {
    if (!oldToken) throw getRichError('UnAuthorized', 'Not a valid refresh token', { oldToken }, null, 'error', null);
    return oldToken.remove();
  })
  .then((oldToken) => {
    const { user } = oldToken;
    return generateAndSaveAuthToken(user);
  });

/**
 * Update the user profile
 * verify email if email is getting updated
 * update user profile into db
 * fetch updated information and return
 * @param {string} id user id
 * @param {string} param json object of field and values to be updated
 * @returns {Promise<Token>}
 */
const updateProfile = (email, id, param) => verifyEmail(email, [id])
  .then(() => UserModel.updateProfile(id, param))
  .then(() => getUserById(id));

/**
 * Convert list of userIds into objects
 * @param {List<String>} ids user id
 * * @param {List<String>} display display parameters
 * @returns {Promise<List<User>>}
 */
const id2object = (ids, display) => UserModel.findUser(ids, display);

/**
 * Convert list of userIds into objects
 * @param {List<String>} ids user id
 * * @param {List<String>} display display parameters
 * @returns {Promise<List<User>>}
 */
const search = (q) => UserModel.searchUsers(q);

/**
 * Generate random 6 digit otp
 * @returns {Number} random 6 digit otp
 */
const generateOTP = () => Math.floor(Math.random() * 899999 + 100000);

const verifyUserAndGenerateOTP = (mobile) => new Promise((resolve, reject) => {
  const newOTP = generateOTP();
  UserModel.verifyMobile(mobile)
    .then((user) => {
      if (user) {
        return UserModel.setOTP(mobile, newOTP);
      }
      return UserModel.createuserAndSendOTP(mobile, newOTP);
    })
    .then(() => resolve({ mobile, otp: newOTP }))
    .catch((e) => {
      reject(e);
    });
});

const verifyMobile = (mobile) => new Promise((resolve, reject) => {
  UserModel.verifyMobile(mobile)
    .then((user) => {
      if (!user) reject(new Error('mobile does not exists'));
      resolve(mobile);
    })
    .catch((e) => reject(e));
});

const verifyOtp = (mobile, otp) => new Promise((resolve, reject) => {
  UserModel.getUserByMobile(mobile)
    .then((user) => {
      if (user.otp === parseInt(otp, 10)) {
        resolve(user);
      }
      reject(new Error({ message: 'Invalid OTP!!', statusCode: 400 }));
    })
    .catch((e) => reject(e));
});

const isNewRegistration = (user) => new Promise((resolve, reject) => {
  if (user.isVerified) {
    resolve(user);
  }
  UserModel.updateProfile(user._id, { isVerified: true })
    .then(() => createUserBucket(user._id))
    .then(() => updateProfile(user._id, { isVerified: true }))
    .then(() => {
      delete user.isVerified;
      resolve(user);
    })
    .catch((err) => reject(err));
});

/**
 * Verify OTP and user account
 * @param {String} mobile mobile number to be verified
 * @param {String} otp OTP to verify with the mobile number
 * @returns Promise
 */
const verifyOTPAndUser = (mobile, otp) => verifyOtp(mobile, otp)
  .then((user) => isNewRegistration(user))
  .then((user) => generateAndSaveAuthToken(user.toObject()))
  .catch((user) => getRichError('System', 'error while verifying user otp', { user }, null, 'error', null));

module.exports = {
  authenticate,
  verifyEmail,
  createUser,
  getUserById,
  getAccessToken,
  updateProfile,
  id2object,
  search,
  createUserBucket,
  verifyUserAndGenerateOTP,
  verifyMobile,
  verifyOtp,
  isNewRegistration,
  verifyOTPAndUser,
};
