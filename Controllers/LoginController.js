/**
 * LoginController
 *
 *
 *
 */

const logger = require('../Helpers/LogHelper').getLogger(__filename);

const userModel = require('../Models/userModel');
const authTokenProvider = require('../Models/authTokenProvider');

/**
 * handleLogin
 *
 * Takes the supplied userEmail and userPassword and attempts to find a matching account
 * if the supplied credentials match an account then a JWT will be created for that user.
 *
 * @param userEmail
 * @param userPassword
 * @returns {Promise<JWT>}          returns a JWT for the authenticated user
 */
exports.handleLogin = function (userEmail, userPassword) {
    return new Promise(async (resolve, reject) => {

        try {

            // Attempt to get user model with the provided credentials
            const user = await userModel.getUserByEmail(userEmail, userPassword);

            logger.debug('Successfully got User from User Model');

            logger.debug('requesting JWT');

            let jwtPayload = {};

            jwtPayload.iat = Math.floor(Date.now() / 1000);
            jwtPayload.iss = "authenticationService";
            // Set expiry an hour from now
            jwtPayload.exp = Math.floor(Date.now() / 1000) + (60 * 60);

            jwtPayload.userID = user.getUserID();
            jwtPayload.email = user.getEmail();
            jwtPayload.firstName = user.getFirstName();
            jwtPayload.lastName = user.getLastName();
            jwtPayload.age = user.getAge();
            jwtPayload.rights = user.getRights();
            jwtPayload.jwtPayload = user.getJWTPayload();

            const token = await authTokenProvider.getToken(jwtPayload);

            const responseObject = {jwt: token};

            return resolve(responseObject);

        } catch (err) {

            logger.error('Failed to login');
            logger.error(err);

            if (err.message === "AuthenticationFailure") {
                logger.error('Returning authentication failure to caller');
                return reject({status: 401, response: {Error: "AuthenticationFailure"}});

            } else if(err.message ===  "AuthenticationBlocked-AccountLocked") {
                logger.error('Returning authentication failure to caller due to account lock');
                return reject({status: 401, response: {Error: "AuthenticationBlocked-AccountLocked"}});

            }

            logger.error('Unexpected unknown error in login resource');
            logger.error('Returning unexpected error to caller');

            return reject({status: 500, response: {Error: "Unexpected Error"}});

        }

    });
};


module.exports = exports;