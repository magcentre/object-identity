/* eslint-disable func-names */
const { mongoose } = require('@magcentre/mongoose-helper');
const { getRichError } = require('@magcentre/response-helper');

const bcrypt = require('bcryptjs');

const userTypes = {
  USER: 'user',
  ADMIN: 'admin',
};

const userSchema = mongoose.Schema(
  {
    firstName: {
      type: String,
      required: true,
      trim: true,
    },
    lastName: {
      type: String,
      required: true,
      trim: true,
    },
    email: {
      type: String,
      required: true,
      unique: true,
      trim: true,
      lowercase: true,
      validate(value) {
        const e = String(value)
          .toLowerCase()
          .match(
            /^(([^<>()[\]\\.,;:\s@"]+(\.[^<>()[\]\\.,;:\s@"]+)*)|(".+"))@((\[[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\])|(([a-zA-Z\-0-9]+\.)+[a-zA-Z]{2,}))$/,
          );

        if (!e) {
          throw getRichError('ParameterError', 'Invalid email', { value }, null, 'error', null);
        }
      },
    },
    password: {
      type: String,
      required: true,
      trim: true,
      minlength: 8,
      validate(value) {
        if (!value.match(/\d/) || !value.match(/[a-zA-Z]/)) {
          throw getRichError('ParameterError', 'Password must contain at least one letter and one number', { value }, null, 'error', null);
        }
      },
    },
    role: {
      type: String,
      enum: [userTypes.ADMIN, userTypes.USER],
      default: userTypes.USER,
    },
    profile: {
      type: String,
      trim: true,
    },
    isBlocked: {
      type: Boolean,
      default: false,
    },
  },
  {
    timestamps: true,
    versionKey: false,
  },
);

userSchema.pre('save', function (next) {
  const user = this;
  if (user.isModified('password')) {
    bcrypt.hash(user.password, 8)
      .then((hash) => {
        user.password = hash;
        next();
      })
      .catch((err) => {
        throw getRichError('System', 'error while generating the password hasg', { err }, err, 'error', null);
      });
  }
});

/**
 * Check if password matches the user's password
 * @param {string} password
 * @returns {Promise<Object>}
 */
userSchema.methods.isPasswordMatch = function (password) {
  const user = this;
  return bcrypt.compare(password, user.password)
    .then((isValid) => ({ match: isValid, ...user.toObject() }))
    .catch((err) => {
      throw getRichError('System', 'error matching the user password', { err }, err, 'error', null);
    });
};

/**
 * @typedef User
 */
const UserAccount = mongoose.model('Users', userSchema);

/**
 * Check if email is taken
 * @param {string} email - The user's email
 * @param {ObjectId} [excludeUserId] - The id of the user to be excluded
 * @returns {Promise<boolean>}
 */
UserAccount.isEmailTaken = (email, excludeUserId) => UserAccount.findOne({ email, _id: { $ne: excludeUserId } })
  .catch((err) => {
    throw getRichError('System', 'error while finding the email address', { email }, err, 'error', null);
  });

/**
 * update profile of the user with token
 * @param {string} id - Users mongoId
 * @param {Object}  params - The json config of the update values
 * @returns {Promise<User>}
 */
UserAccount.updateProfile = (id, params) => UserAccount.findByIdAndUpdate(id, { $set: params })
  .catch((err) => {
    throw getRichError('System', 'error while finding and updateing the profile with mongo id', { id, params }, err, 'error', null);
  });

/**
 * seach user by email address and return
 * @param {string} id - Users mongoId
 * @param {Object}  params - The json config of the update values
 * @returns {Promise<User>}
 */
UserAccount.getUserByEmail = (email) => UserAccount.findOne({ email })
  .catch((err) => {
    throw getRichError('System', 'error while finding and updateing the profile with mongo id', { err }, err, 'error', null);
  });

/**
 * Create new user account
 * @param {Object}  body - user information
 * @returns {Promise<User>}
 */
UserAccount.createUserAccount = (body) => UserAccount.create(body)
  .catch((err) => {
    throw getRichError('System', 'error while creating new user account', { err }, err, 'error', null);
  });

/**
 * Get user by mongo id
 * @param {String}  id - user information
 * @returns {Promise<User>}
 */
UserAccount.getUserById = (id) => UserAccount.findById(id, { password: 0 })
  .catch((err) => {
    throw getRichError('System', 'error while fetching user with id', { err, id }, err, 'error', null);
  });

/**
 * Update user with id
 * @param {String}  id - user mongo id
 * @param {Object}  id - parameters to update
 * @returns {Promise<User>}
 */
UserAccount.updateUserById = (id, param) => UserAccount.update({ _id: id }, { $set: param })
  .catch((err) => {
    throw getRichError('System', 'error while updating user with id', { err, id, param }, err, 'error', null);
  });

/**
 * finding users with id
 * @param {List<String>}  ids - list of user ids
 * @param {Object}  display - objects to be displayed
 * @returns {Promise<User>}
 */
UserAccount.findUserAccounts = (ids, display) => UserAccount.find({ _id: { $in: ids } }, display)
  .catch((err) => {
    throw getRichError('System', 'error while finding users with id', { err, ids, display }, err, 'error', null);
  });

/**
 * search user with text
 * @param {String}  q - objects to be displayed
 * @returns {Promise<User>}
 */
UserAccount.searchUserAccounts = (q) => UserAccount.find({ $or: [{ firstName: { $regex: q } }, { lastName: { $regex: q } }] }, { firstName: 1, lastName: 1, email: 1 })
  .catch((err) => {
    throw getRichError('System', 'error while searching users with query', { err, q }, err, 'error', null);
  });

module.exports = {
  model: UserAccount,
  types: userTypes,
};
