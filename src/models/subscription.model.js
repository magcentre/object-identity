const { mongoose } = require('@magcentre/mongoose-helper');
const { getRichError } = require('@magcentre/response-helper');

const subscriptionSchema = mongoose.Schema(
  {
    title: {
      type: String,
      required: true,
      index: true,
    },
    price: {
      type: Number,
      required: true,
    },
    size: {
      type: Number,
      required: true,
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
const Subscription = mongoose.model('Subscription', subscriptionSchema);

/**
 * Create and save access token
 * @param {object} tokenConfig - javscript object with all required parameters to create token
 * @param {function(err, model)} cb - Callback function
 * @returns {Promise<Token>} -
 */
Subscription.validSubscription = (subscriptionId) => Subscription.findOne({ _id: subscriptionId })
  .catch((err) => {
    throw getRichError('System', 'error while getting valid subscription', { subscriptionId }, err, 'error', null);
  });

module.exports = {
  SubscriptionModel: Subscription,
};
