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
exports.handleCreateUser = function (callingUserID, email, firstName, lastName, age, rights, jwtPayload) {
    return new Promise(async (resolve, reject) => {

        try {

            logger.debug('Checking user has required rights to create a user');

            // Get the callingUser's User Model
            const callingUser = await userModel.getUserByID(callingUserID);


            resolve({'egg': 'sand'})


        } catch (err) {

            return reject({status: 401, response: {Error: "AuthenticationFailure"}});


        }

    });
};


module.exports = exports;