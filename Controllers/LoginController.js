/**
 * LoginController
 *
 *
 *
 */

const logger = require('../Helpers/LogHelper').getLogger(__filename);

const userModel = require('../Models/userModel');
const authTokenProvider = require('../Models/authTokenProvider');

exports.handleLogin = function (userEmail, userPassword) {
    return new Promise(async (resolve, reject) => {

        try {

            // Attempt to get user model with the provided credentials
            const user = await userModel.getUser(userEmail, userPassword);

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

            }

            logger.error('Unexpected unknown error in login resource');
            logger.error('Returning unexpected error to caller');

            return reject({status: 500, response: {Error: "Unexpected Error"}});

        }

    });
};


module.exports = exports;