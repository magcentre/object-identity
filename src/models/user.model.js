/* eslint-disable func-names */
const { mongoose } = require('@magcentre/mongoose-helper');

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
          throw Error({ statuCode: 400, message: 'Invalid email' });
        }
      },
    },
    password: {
      type: String,
      trim: true,
      minlength: 8,
      validate(value) {
        if (!value.match(/\d/) || !value.match(/[a-zA-Z]/)) {
          throw Error({ statuCode: 400, message: 'Password must contain at least one letter and one number' });
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
        if (!value.match(/\d/) || !value.match(/^(?:(?:\+|0{0,2})91(\s*|[\-])?|[0]?)?([6789]\d{2}([ -]?)\d{3}([ -]?)\d{4})$/)) {
          throw Error({ statuCode: 400, message: 'Enter valid mobile number' });
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
  },
  {
    timestamps: true,
    versionKey: false,
  },
);

/**
 * Check if email is taken
 * @param {string} email - The user's email
 * @param {ObjectId} [excludeUserId] - The id of the user to be excluded
 * @returns {Promise<boolean>}
 */
userSchema.statics.isEmailTaken = function (email, excludeUserId) {
  return this.findOne({ email, _id: { $ne: excludeUserId } });
};

/**
 * Check if password matches the user's password
 * @param {string} password
 * @returns {Promise<Object>}
 */
userSchema.methods.isPasswordMatch = function (password) {
  const user = this;
  return new Promise((resolve, reject) => {
    bcrypt.compare(password, user.password, (err, isValid) => {
      if (err) return reject(err);
      return resolve({ match: isValid, ...user.toObject() });
    });
  });
};

userSchema.pre('save', async function (next) {
  const user = this;
  if (user.isModified('password')) {
    user.password = await bcrypt.hash(user.password, 8);
  }
  next();
});

/**
 * update profile of the user with token
 * @param {string} id - Users mongoId
 * @param {Object}  params - The json config of the update values
 * @returns {Promise<boolean>}
 */
userSchema.statics.updateProfile = function (id, params) {
  return this.findByIdAndUpdate(id, { $set: params });
};

/**
 * verify mobile number, if mobile exists return the user object otherwise throw error
 * @param {Number} mobile - Mobile number of registreed user
 * @returns {Promise<boolean>}
 */
userSchema.statics.verifyMobile = function (mobile) {
  return this.findOne({ mobile });
};

userSchema.statics.setOTP = function (mobile, otp) {
  return this.findOneAndUpdate({ mobile }, { $set: { otp } });
};

userSchema.statics.createuserAndSendOTP = function (mobile, otp) {
  return this.create({ mobile, otp, isVerified: false });
};


userSchema.statics.getUserByMobile = function (mobile, otp) {
  return this.findOne({ mobile });
};
/**
 * @typedef User
 */
const User = mongoose.model('Users', userSchema);

module.exports = {
  model: User,
  types: userTypes,
};
