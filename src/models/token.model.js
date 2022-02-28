const { mongoose } = require('@magcentre/mongoose-helper');
const { getRichError } = require('@magcentre/response-helper');

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
 * @typedef Token
 */
const Token = mongoose.model('Token', tokenSchema);

/**
 * Create and save access token
 * @param {object} tokenConfig - javscript object with all required parameters to create token
 * @param {function(err, model)} cb - Callback function
 * @returns {Promise<Token>} -
 */
Token.createToken = (tokenConfig) => Token.create(tokenConfig)
  .catch((err) => {
    throw getRichError('System', 'error while creating new token', { tokenConfig }, err, 'error', null);
  });

/**
 * Create and save access token
 * @param {object} tokenConfig - javscript object with all required parameters to create token
 * @param {function(err, model)} cb - Callback function
 * @returns {Promise<Token>} -
 */
Token.findToken = (tokenConfig) => Token.findOne(tokenConfig)
  .catch((err) => {
    throw getRichError('System', 'error while finding the token', { tokenConfig }, err, 'error', null);
  });

module.exports = {
  model: Token,
  types: tokenTypes,
};
