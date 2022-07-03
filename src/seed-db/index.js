const { mongoose } = require('@magcentre/mongoose-helper');
const config = require('../configuration/config');
// const { port, db, secret }    = require('../config/env');
// mongoose.Promise = require('bluebird');
mongoose.connect(config.database.url);

const { SubscriptionModel } = require('../models/subscription.model');

SubscriptionModel.collection.drop();

SubscriptionModel.create([{
  title: 'Free Plan',
  size: 30,
  price: 0,
}, {
  title: 'Basic Plan',
  size: 100,
  price: 10,
}])
  .then((user) => {
    console.log(`${user.length} users created`);
  })
  .catch((err) => {
    console.log(err);
  })
  .finally(() => {
    mongoose.connection.close();
  });