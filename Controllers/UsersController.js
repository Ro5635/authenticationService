/**
 * UsersController
 *
 *
 *
 */

const logger = require('../Helpers/LogHelper').getLogger(__filename);

const userModel = require('../Models/userModel');

/**
 * handleUserCreate
 *
 *
 * @returns {Promise<all>}
 */
exports.handleCreateUser = function (callingUserID, password, email, firstName, lastName, age, rights, jwtPayload) {
    return new Promise(async (resolve, reject) => {

        try {

            logger.debug('Checking user has required rights to create a user');

            // Get the callingUser's User Model
            const callingUser = await userModel.getUserByID(callingUserID);

            // check the user has the required rights...

            const newUser = await userModel.createNewUser(password, email, firstName, lastName, age, rights, jwtPayload);


            return resolve({'userID': newUser.getUserID()});


        } catch (err) {

            // Check for the errors that can be externally exposed
            if (err.message === 'User Exists') {
                return reject({status: 409, response: {Error: "UserExists"}});

            }

            return reject({status: 401, response: {Error: "AuthenticationFailure"}});


        }

    });
};


module.exports = exports;