const { model } = require('../models/user.model');

/**
 * All users list
 * @returns Array of all users objects
 */
const getUsersList = () => model.getUsersList();

/**
 * Update the user by id
 * @param {String} userId mongouserid to be updated
 * @param {Object} props properties to be updated
 * @returns rethrn doc of the user after updation
 */
const updateUser = (userId, props) => model.updateUserById(userId, props);

module.exports = {
  getUsersList,
  updateUser,
};
