const { mongoose } = require('@magcentre/mongoose-helper');

const tokenTypes = {
  ACCESS: 'access',
  REFRESH: 'refresh',
  RESET_PASSWORD: 'resetPassword',
  VERIFY_EMAIL: 'verifyEmail',
};

const tokenSchema = mongoose.Schema(
  {
    token: {
      type: String,
      required: true,
      index: true,
    },
    user: {
      type: mongoose.SchemaTypes.ObjectId,
      ref: 'User',
      required: true,
    },
    type: {
      type: String,
      enum: [tokenTypes.REFRESH, tokenTypes.RESET_PASSWORD, tokenTypes.VERIFY_EMAIL],
      required: true,
    },
    expires: {
      type: Date,
      required: true,
    },
    blacklisted: {
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
 * Create and save access token
 * @param {object} tokenConfig - javscript object with all required parameters to create token
 * @param {function(err, model)} cb - Callback function
 * @returns {Promise<Token>} -
 */
tokenSchema.statics.createToken = function (tokenConfig) {
  return this.create(tokenConfig);
};

/**
 * Create and save access token
 * @param {object} tokenConfig - javscript object with all required parameters to create token
 * @param {function(err, model)} cb - Callback function
 * @returns {Promise<Token>} -
 */
tokenSchema.statics.findToken = async function (tokenConfig, cb) {
  const token = await this.findOne(tokenConfig);
  if (token) return token;
  throw new Error('Not a valid refresh token');
};

/**
 * @typedef Token
 */
const Token = mongoose.model('Token', tokenSchema);

module.exports = {
  model: Token,
  types: tokenTypes,
};
