const moment = require('moment');
const jwt = require('jsonwebtoken');
const utils = require('@magcentre/api-utils');
const { getRichError } = require('@magcentre/response-helper');
const logger = require('@magcentre/logger-helper');
const { model } = require('../models/user.model');
const token = require('../models/token.model');
const config = require('../configuration/config');
const { bucketExists, createBucket, sendOTP, otpTemplate } = require('../constants');

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
    .then(() => model.createUserAccount(body))
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
  const accessToken = generateToken(user._id, user.role, accessTokenExpires, token.types.ACCESS);

  // generate refresh token expiry
  const refreshTokenExpires = moment().add(config.jwt.refreshExpirationDays, 'days');

  // generate refresh token
  const refreshToken = generateToken(user._id, user.role, refreshTokenExpires, token.types.REFRESH);

  // return promise and store token in database
  return token.model.createToken({
    token: refreshToken,
    user: user._id,
    expires: refreshTokenExpires.toDate(),
    type: token.types.REFRESH,
    blacklisted: false,
  })
    .then((newToken) => ({
      ...user.toObject(),
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
const verifyBucket = (userId, user) => {
  return utils.connect(bucketExists, 'POST', { bucketName: userId })
    .catch((err) => {
      throw getRichError('System', 'Bucket does not exists for the user', { userId, user }, err, 'error', null);
    })
    .then(() => user);
}

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

const authenticate = (email, password, fcmToken) => model.getUserByEmail(email)
  .then((user) => {
    if (!user) throw getRichError('ParameterError', 'Invalid email', { email }, null, 'error', null);
    return user;
  })
  .then((user) => user.isPasswordMatch(password))
  .then((userWithPassword) => {
    if (!userWithPassword.match) throw getRichError('ParameterError', 'Invalid password', { match: userWithPassword.match }, null, 'error', null);
    if (!userWithPassword.isVerified) throw getRichError('ParameterError', 'Your account is not verified, please verify account and try again', { verified: userWithPassword.isVerified }, null, 'error', null);
    return userWithPassword;
  })
  .then((user) => model.updateProfile(user._id, { fcmToken }))
  .then((user) => generateAndSaveAuthToken(user));

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
  .then((decoded) => token.model.findToken({
    token: refreshToken, type: token.types.REFRESH, user: decoded.sub, blacklisted: false,
  }))
  .then((oldToken) => {
    if (!oldToken) throw getRichError('UnAuthorized', 'Not a valid refresh token', { oldToken }, null, 'error', null);
    return oldToken.remove();
  })
  .then((oldToken) => {
    const { user } = oldToken;
    return generateAndSaveAuthToken({
      _id: user,
    });
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
  .then(() => model.updateUserById(id, param))
  .then(() => getUserById(id));

/**
 * Convert list of userIds into objects
 * @param {List<String>} ids user id
 * * @param {List<String>} display display parameters
 * @returns {Promise<List<User>>}
 */
const id2object = (ids, display) => model.findUserAccounts({ _id: { $in: ids } }, display);

/**
 * Convert list of userIds into objects
 * @param {List<String>} ids user id
 * * @param {List<String>} display display parameters
 * @returns {Promise<List<User>>}
 */
const search = (q) => model.searchUserAccounts(q);

/**
 * Generate random 6 digit otp
 * @returns {Number} random 6 digit otp
 */
const generateOTP = () => Math.floor(Math.random() * 899999 + 100000);

/**
 * Check if account exists or not with provided mobile number
 * @param {string} mobile mobiler number to verify if exists or not
 * @returns {Promise<User>}
 */
const verifyMobile = (mobile) => model.verifyMobile(mobile)
  .then((user) => {
    if (!user) throw getRichError('Parameter', 'Mobile does not exists', { user }, null, 'error', null);
    return user;
  });

/**
 * Verify OTP for the provided mobile number
 * @param {String} mobile mobile number to verify otp with
 * @param {String} otp Otp to verify
 * @returns Promise
 */
const verifyOtp = (mobile, otp) => model.getUserByMobile(mobile)
  .then((user) => {
    if (!user) {
      throw getRichError('Parameter', 'Mobile does not exists', { mobile, otp }, null, 'error', null);
    }
    if (Date.now() <= parseInt(user.otpExpiry)) {
      if (user.otp === parseInt(otp, 10)) {
        return user;
      }
      throw getRichError('Parameter', 'Invalid otp, please try again', { mobile, otp }, null, 'error', null);
    }
    throw getRichError('Parameter', 'OTP is expired', { mobile, otp }, null, 'error', null);

  });

/**
 * Verify if the user is newly registered or not based on the verification
 * @param {Object} user user object from db
 * @returns Promise
 */
const isNewRegistration = (user) => {
  if (user.isBucketCreated) {
    return model.updateProfile(user._id, { isVerified: true, isBucketCreated: true, otp: '', otpExpiry: '' })
      .then(() => {
        return user;
      });
  }
  return createUserBucket(user._id)
    .then(() => model.updateProfile(user._id, { isVerified: true, isBucketCreated: true, otp: '', otpExpiry: '' }))
    .then(() => {
      delete user.isVerified;
      return user;
    });
};

/**
 * Generate OTP for verification
 * if the user does not exists with the provided mobile nubmer
 * new user is created otherwise OTP is set for existsing user
 * @param {String} mobile Mobile number to verify and generate otp
 * @returns Promise
 */
const verifyUserAndGenerateOTP = (mobile) => {
  const otp = generateOTP();
  return model.verifyMobile(mobile)
    .then((user) => {
      const otpExpiry = Date.now() + config.jwt.otpExpiryTimeInMinutes * 60000;
      if (user) return model.setOTP(mobile, otp, otpExpiry);
      return model.createUserAccount({
        mobile, otp, otpExpiry,
      });
    })
    .then(() => utils.connect(sendOTP, 'POST', { to: [mobile], content: otpTemplate(otp, config.jwt.otpExpiryTimeInMinutes) }))
    .then(() => ({ mobile, otp }));
};

/**
 * Verify OTP and user account
 * @param {String} mobile mobile number to be verified
 * @param {String} otp OTP to verify with the mobile number
 * @returns Promise
 */
const verifyOTPAndUserAccount = (mobile, otp) => verifyOtp(mobile, otp)
  .then((user) => isNewRegistration(user))
  .then((user) => generateAndSaveAuthToken(user))
  .catch((err) => getRichError('System', 'error while verifying user otp', { err }, err, 'error', null));

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
  verifyOTPAndUserAccount,
  isNewRegistration,
};
