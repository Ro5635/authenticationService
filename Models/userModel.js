/**
 * userModel
 *
 * Models a user and associated user based actions and metadata
 *
 */

const logger = require('../Helpers/LogHelper').getLogger(__filename);

/**
 * Returns a user object if the provided authentication details match a user account
 *
 * @param userName
 * @param userPassword
 * @returns {Promise<any>}
 */
exports.getUser = function (userName, userPassword) {
    return new Promise((resolve, reject) => {

        // Verify supplied credentials with db
        getUserAttributesFromDB(userName, userPassword)
            .then(userData => {

                logger.debug('Got user attributes from DB using supplied credentials');

                // return a new Users instance
                return resolve(new User(userData.userName, userData.userFirstName, userData.userLastName, userData.userAge, userData.userEmail, userData.userRights, userData.userJWTPayload));

            })
            .catch(err => {

                logger.error('Error in getting user');
                logger.error('Supplied details: userName: ' + userName + ' userPassword: ' + userPassword);

                if(err.message === 'AuthenticationFailure'){

                    logger.error('Invalid authentication details supplied for user');

                    return reject(err);

                }

                logger.error('Failed to get user attributes from DB for unexpected reason');
                logger.error(err);
                return reject(new Error('Failed to get user'));

            });


    });




};

/**
 * getUserAttributesFromDB
 *
 * Attempts to get the user attributes from the DB, if the authentication details match a user in the table then
 * the whole user item will be returned.
 *
 * @param userName
 * @param userPassword              plaintext user password
 * @returns {Promise<userData>}     JSON Object containing the DBs user data fro the supplied username
 */
function getUserAttributesFromDB(userName, userPassword) {
    return new Promise((resolve, reject) => {
        // TODO: Implement getUserAttributesFromDB logic

        // Attempt to get user object for supplied userID

        // Check password by taking the users salt and hashing the supplied password

        // Authentication details correct
        // return user item
        return resolve({
            userName: 'Robert',
            userEmail: 'robert@robertcurran.co.uk',
            userFirstName: 'Robert',
            userLastName: 'Curran',
            userAge: 22,
            userRights: {},
            userJWTPayload: {}
        });



        // Authentication details supplied incorrect

        // return reject(new Error('AuthenticationFailure'));


    });
}

/**
 * User Object
 *
 * Models a user within the system and the interactions that can be completed on a user
 *
 * @param userName
 * @param firstName
 * @param lastName
 * @param age
 * @param email
 * @param rights                    JSON Object detail users rights
 * @param jwtPayload                JSON Object with additional payload
 * @constructor
 */
function User(userName, firstName, lastName, age, email, rights, jwtPayload) {
    this._userName = 'ro5635';
    this._firstname = 'Barry';
    this._lastName = 'Smith';
    this._age = 22;
    this._email = 'ro5635@gmail.com';
    this._rights = {};
    this._jwtPayload = {};


    this.getUserName = function () {
        return this._userName;
    };

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