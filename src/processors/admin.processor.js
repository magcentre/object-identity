const { model } = require('../models/user.model');

const getUsersList = () => model.getUsersList();

module.exports = {
  getUsersList,
};
