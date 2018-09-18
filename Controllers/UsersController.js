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

        const requiredRight = {'userControl': {'accountCreate': 1}};

        try {

            logger.debug('Checking user has required rights to create a user');

            // Don't use the rights on the validated JWT, take the userID and get the most up to date user rights
            // for most other purposes rights would be taken from the JWT.

            logger.debug('Getting the calling users User Model');
            const callingUser = await userModel.getUserByID(callingUserID);

            // Check the user has the required rights to create a new user
            logger.debug('Checking calling users rights');
            const hasRequiredRights = callingUser.hasRequiredRights(requiredRight);

            if (!hasRequiredRights) {
                logger.error('Calling user does not have the required right');
                logger.error('Caller lacked Right: ' + JSON.stringify(requiredRight, null, 2));
                logger.error('Returning Unauthorised');

                return reject({status: 401, response: {Error: "AuthenticationFailure"}});
            }

            logger.debug('Calling user has sufficient rights for requested operation');



        } catch (err) {

            logger.error('Failed to get calling users rights');
            logger.error(err);
            logger.error('Could not authenticate calling user');

            return reject({status: 401, response: {Error: "AuthenticationFailure"}});


        }


        // Create the new user
        try {


            logger.debug('Requesting creation of new user');
            const newUser = await userModel.createNewUser(password, email, firstName, lastName, age, rights, jwtPayload);

            logger.debug('Returning newly created user\'s userID to caller');
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