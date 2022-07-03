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
      trim: true,
    },
    lastName: {
      type: String,
      trim: true,
    },
    email: {
      type: String,
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
      trim: true,
      minlength: 8,
      validate(value) {
        if (!value.match(/^(?=.*\d)(?=.*[a-z])(?=.*[A-Z])(?=.*[a-zA-Z]).{8,}$/)) {
          const message = 'Password shoud be Minimum eight characters, at least one letter and one number';
          throw getRichError('ParameterError', message, { message }, null, 'error', null);
        }
      },
    },
    role: {
      type: String,
      enum: [userTypes.ADMIN, userTypes.USER],
      default: userTypes.USER,
    },
    isVerified: {
      type: Boolean,
      default: false,
    },
    mobile: {
      type: String,
      required: true,
      unique: true,
      trim: true,
      validate(value) {
        if (!value.match(/\d/) || !value.match(/^(?:(?:\+|0{0,2})91(\s*|[-])?|[0]?)?([6789]\d{2}([ -]?)\d{3}([ -]?)\d{4})$/)) {
          throw getRichError('Parameter', 'Enter valid mobile number', { value }, null, 'error', null);
        }
      },
    },
    otp: {
      type: Number,
    },
    avatar: {
      type: String,
      trim: true,
    },
    isBlocked: {
      type: Boolean,
      default: false,
    },
    fcmToken: {
      type: String,
    },
    subscriptions: {
      type: mongoose.Schema.Types.Array,
      ref: 'Subscription',
      required: true,
    },
    activeSubscription: {
      type: String,
    },
  },
  {
    timestamps: true,
    versionKey: false,
  },
);

userSchema.pre('save', (next) => {
  const user = this;
  if (user.password) {
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
  }
  else {
    next();
  }
});

/**
 * Check if password matches the user's password
 * @param {string} password
 * @returns {Promise<Object>}
 */
userSchema.methods.isPasswordMatch = (password) => {
  const user = this;
  return bcrypt.compare(password, user.password)
    .then((isValid) => ({ match: isValid, ...user.toObject() }))
    .catch((err) => {
      throw getRichError('System', 'error matching the user password', { err }, err, 'error', null);
    });
};

/**
 * verify mobile number, if mobile exists return the user object otherwise throw error
 * @param {Number} mobile - Mobile number of registreed user
 * @returns {Promise<boolean>}
 */
// userSchema.statics.verifyMobile = (mobile) => this.findOne({ mobile });

// userSchema.statics.setOTP = (mobile, otp) => this.findOneAndUpdate({ mobile }, { $set: { otp } });

// userSchema.statics.getUserByMobile = (mobile, otp) => this.findOne({ mobile });
/**
 * @typedef User
 */
const User = mongoose.model('Users', userSchema);

User.createuserAndSendOTP = (mobile, otp) => User.create({ mobile, otp, isVerified: false });
/**
 * Check if email is taken
 * @param {string} email - The user's email
 * @param {ObjectId} [excludeUserId] - The id of the user to be excluded
 * @returns {Promise<boolean>}
 */
User.isEmailTaken = (email, excludeUserId) => User.findOne({ email, _id: { $ne: excludeUserId } })
  .catch((err) => {
    throw getRichError('System', 'error while finding the email address', { email }, err, 'error', null);
  });

/**
 * update profile of the user with token
 * @param {string} id - Users mongoId
 * @param {Object}  params - The json config of the update values
 * @returns {Promise<User>}
 */
User.updateProfile = (id, params) => {
  if (params.password) {
    return bcrypt.hash(params.password, 8)
      .then((hash) => {
        params.password = hash;
        return params;
      })
      .then(() => User.findByIdAndUpdate(id, { $set: params }, { new: true }))
      .catch((err) => {
        throw getRichError('System', 'error while generating the password hasg', { err }, err, 'error', null);
      });
  }
  return User.findByIdAndUpdate(id, { $set: params }, { new: true })
    .catch((err) => {
      throw getRichError('System', 'error while finding and updateing the profile with mongo id', { id, params }, err, 'error', null);
    });
};

/**
 * seach user by email address and return
 * @param {string} id - Users mongoId
 * @param {Object}  params - The json config of the update values
 * @returns {Promise<User>}
 */
User.getUserByEmail = (email) => User.findOne({ email })
  .catch((err) => {
    throw getRichError('System', 'error while finding and updateing the profile with mongo id', { err }, err, 'error', null);
  });

/**
 * Create new user account
 * @param {Object}  body - user information
 * @returns {Promise<User>}
 */
// User.createUser = (body) => User.create(body)
//   .catch((err) => {
//     throw getRichError('System', 'error while creating new user account', { err }, err, 'error', null);
//   });

/**
 * Get user by mongo id
 * @param {String}  id - user information
 * @returns {Promise<User>}
 */
User.getUserById = (id) => User.findById(id, { password: 0 })
  .catch((err) => {
    throw getRichError('System', 'error while fetching user with id', { err, id }, err, 'error', null);
  });

/**
 * finding users with id
 * @param {List<String>}  ids - list of user ids
 * @param {Object}  display - objects to be displayed
 * @returns {Promise<User>}
 */
User.findUsers = (ids, display) => User.find({ _id: { $in: ids } }, display)
  .catch((err) => {
    throw getRichError('System', 'error while finding users with id', { err, ids, display }, err, 'error', null);
  });

/**
 * search user with text
 * @param {String}  q - objects to be displayed
 * @returns {Promise<User>}
 */
User.searchUsers = (q) => User.find({ $or: [{ firstName: { $regex: q } }, { lastName: { $regex: q } }] }, { firstName: 1, lastName: 1, email: 1 })
  .catch((err) => {
    throw getRichError('System', 'error while searching users with query', { err, q }, err, 'error', null);
  });

/**
 * verify mobile number, if mobile exists return the user object otherwise throw error
 * @param {Number} mobile - Mobile number of registreed user
 * @returns {Promise<boolean>}
*/
User.verifyMobile = (mobile) => User.findOne({ mobile })
  .catch((err) => {
    throw getRichError('System', 'error while finding user with mobile', { err, mobile }, err, 'error', null);
  });
/**
 * Set newly generated OTP to the user to verify
 * @param {String} mobile Mobile number of the registed user
 * @param {String} otp OTP to set for the user
 * @returns Promise
 */
User.setOTP = (mobile, otp, expiry) => User.findOneAndUpdate({ mobile }, { $set: { otp, otpExpiry: expiry } })
  .catch((err) => {
    throw getRichError('System', 'error while finding user with mobile', { err, mobile }, err, 'error', null);
  });

/**
 * Find user by mobile number
 * @param {String} mobile search user by mobile number
 * @returns Promise
 */
User.getUserByMobile = (mobile) => User.findOne({ mobile })
  .catch((err) => {
    throw getRichError('System', 'error while finding user with mobile', { err, mobile }, err, 'error', null);
  });

/**
 * Find user by mobile number
 * @param {String} mobile search user by mobile number
 * @returns Promise
 */
User.getUsersList = () => User.find({}, { otp: 0, otpExpiry: 0, password: 0 })
  .catch((err) => {
    throw getRichError('System', 'error while fetching all users list user with mobile', {}, err, 'error', null);
  });

/**
* Find user by mobile number
* @param {String} mobile search user by mobile number
* @returns Promise
*/
User.updateUserById = (userId, properties) => User.findByIdAndUpdate(userId, properties)
  .catch((err) => {
    throw getRichError('System', 'error while updating the user details', { userId, properties }, err, 'error', null);
  });

User.createSubscription = (userId, subscription) => User.findByIdAndUpdate(userId, {
  $addToSet: {
    subscriptions: subscription._id,
  },
  activeSubscription: subscription._id,
}, { new: true })
  .catch((err) => {
    throw getRichError('System', 'error while creating subscription', { userId, subscription }, err, 'error', null);
  });

module.exports = {
  UserModel: User,
  types: userTypes,
};
