/**
 * userModel
 *
 * Models a user and associated user based actions and metadata
 *
 */

const logger = require('../Helpers/LogHelper').getLogger(__filename);
const bcrypt = require('bcrypt');
const dbWrapper = require('@ro5635/dynamodbwrapper');
const usersDBTable = 'globalUsersTable';

/**
 * Returns a user object if the provided authentication details match a user account
 *
 * @param userEmail                     user email
 * @param userPassword                  plain text user password
 * @returns {Promise<any>}
 */
exports.getUser = function (userEmail, userPassword) {
    return new Promise(async (resolve, reject) => {
        try {

            // Validate that userEmail and userPassword where passed
            if (!userEmail || userEmail.length <= 0) return reject(new Error('AuthenticationFailure'));
            if (!userPassword || userPassword.length <= 0) return reject(new Error('AuthenticationFailure'));

            let userData = {};

            try {
                userData = await getUserAttributesFromDBByEmail(userEmail);

            } catch (err) {
                logger.error('Error in getting user');
                logger.error('Supplied details: userName: ' + userName + ' userPassword: ' + userPassword);

                if (err.message === 'AuthenticationFailure') {

                    logger.error('Invalid authentication details supplied for user');

                    return reject(err);

                }

                logger.error('Failed to get user attributes from DB for unexpected reason');
                logger.error(err);
                return reject(new Error('Failed to get user'));

            }

            // Check the supplied password matches the account that matches the userEmail supplied
            const suppliedCredentialsCorrect = await validateAuthenticationCredentials(userPassword, userData.userPasswordHash);

            // If login credentials where correct create a user and return it
            if (suppliedCredentialsCorrect) {
                // Create the User object
                logger.debug('Crating a new User instance from the user data');
                const callersUser = new User(userData.userEmail, userData.userFirstName, userData.userLastName, userData.userAge, userData.userRights, userData.userJWTPayload);

                // return the new User object
                return resolve(callersUser);

            }

            // Authentication details were incorrect, return AuthenticationFailure
            logger.debug('Supplied password did not match supplied username');
            logger.debug('Returning AuthenticationFailure');

            reject(new Error('AuthenticationFailure'));

        } catch (err) {
            // Catch any unexpected errors in the above block
            logger.error('Unexpected error occurred in getUser');
            logger.error(err);

            return reject(new Error('Unexpected error in getting user'));
        }
    });
};

/**
 * getUserAttributesFromDBByEmail
 *
 * Gets a user from the DB if one is dound matching the supplied userEmail
 *
 * @param userEmail
 * @returns {Promise<userData>}     JSON Object containing the DBs user data fro the supplied userEmail
 */
function getUserAttributesFromDBByEmail(userEmail) {
    return new Promise(async (resolve, reject) => {

        const baseQuery = '#userEmail = :userEmail';
        const attributeNames = {'#userEmail': 'userEmail'};
        const attributeValues = {':userEmail': userEmail};
        const queryIndex = 'userEmail-index';

        let acquiredUser = {};

        try {
            // Attempt to get user object for supplied userID by calling the DB
            const dbQueryResult = await dbWrapper.query(baseQuery, attributeNames, attributeValues, usersDBTable, queryIndex);

            logger.debug({
                dbRequestStats: {
                    'retrievedItems': dbQueryResult.Count,
                    'itemsScanned': dbQueryResult.ScannedCount
                }
            });

            if (dbQueryResult.Count === 1) {

                logger.debug('Found user in db');
                acquiredUser = dbQueryResult.Items[0];

                // return user item
                return resolve(acquiredUser);

            } else if (dbQueryResult.Count === 0) {
                logger.debug('No User found matching query parameters');
                logger.debug('Returning incorrect authentication details');
                throw new Error('AuthenticationFailure');

            }

            logger.error('Error in querying DB, unexpected count of users found');
            logger.error('Returning unexpected error to caller');
            return new Error('Unexpected Error');


        } catch (err) {
            logger.error('Failed to query DB for user');
            logger.error(err);

            return reject(err);
        }

    });
}

/**
 * validateAuthenticationCredentials
 *
 * Takes teh provided plain text password and salt and produces a password hash that is then compared against
 * the supplied password hash, if they match returns TRUE, else FALSE.
 *
 * @param suppliedPassword              plain text password
 * @param passwordHash                  password Hash for end comparison, bcrypt packages salt snd cipher text together for convenience
 * @returns {Promise<Boolean>}          Boolean - Password Correct?
 */
function validateAuthenticationCredentials(suppliedPassword, passwordHash) {
    return new Promise(async (resolve, reject) => {
        try {
            // The first 22 characters of the hash decode to a 16-byte value for the salt
            // where the fist few characters separated by $ encode the algorithm type
            // The salt is added to the front of the cipher text.
            const passwordMatches = await bcrypt.compare(suppliedPassword, passwordHash);

            if (passwordMatches) {
                // Passwords match, return true
                return resolve(true);
            } else {
                // Passwords supplied did not match users password
                // Authentication details supplied incorrect, return false
                return resolve(false);

            }

        } catch (err) {
            logger.error('unexpected error in validation of user credentials');

            return reject(new Error('Unexpected Error in validating credentials'));

        }

    });
}

/**
 * User Object
 *
 * Models a user within the system and the interactions that can be completed on a user
 *
 * @param email
 * @param firstName
 * @param lastName
 * @param age
 * @param rights                    JSON Object detail users rights
 * @param jwtPayload                JSON Object with additional payload
 * @constructor
 */
function User(email, firstName, lastName, age, rights, jwtPayload) {
    this._email = 'ro5635@gmail.com';
    this._firstname = 'Barry';
    this._lastName = 'Smith';
    this._age = 22;
    this._rights = {};
    this._jwtPayload = {};


    this.getFirstName = function () {
        return this._firstname;
    };

    this.getLastName = function () {
        return this._lastName;
    };

    this.getAge = function () {
        return this._age;
    };

    this.getEmail = function () {
        return this._email;
    };

    this.getRights = function () {
        return this._rights;
    };

    this.getJWTPayload = function () {
        return this._jwtPayload;
    }

}

module.exports = exports;