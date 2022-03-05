const app = require('express')();

const path = require('path');

const initServer = require('@magcentre/init');

const logger = require('@magcentre/logger-helper');

const { initDatabase } = require('@magcentre/mongoose-helper');

const config = require('./configuration/config');

initDatabase(config.database, path.join(__dirname, 'models'))
  .then(() => initServer(app, __dirname, config))
  .then(() => {
    logger.info(`identity-service started on port ${config.port}`);
  })
  .catch((err) => {
    logger.log(err);
    logger.error('Failed to start identity-service');
  });

module.exports = app;
