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
        } catch (err) {

            logger.error('Failed to get calling users rights');
            logger.error('Could not authenticate calling user');
            return reject({status: 401, response: {Error: "AuthenticationFailure"}});


        }


        // Create the new user
        try {


            const newUser = await userModel.createNewUser(password, email, firstName, lastName, age, rights, jwtPayload);


            return resolve({'userID': newUser.getUserID()});


        } catch (err) {

            logger.error('Process of creating user failed');
            logger.error(err);

            // Check for the errors that can be externally exposed
            if (err.message === 'User Exists') {
                return reject({status: 409, response: {Error: "UserExists"}});

            }

            return reject({status: 500, response: {Error: "UnexpectedFailure"}});


        }

    });
};


module.exports = exports;