/**
 * userModel
 *
 * Models a user and associated user based actions and metadata
 *
 */

const logger = require('../Helpers/LogHelper').getLogger(__filename);
const bcrypt = require('bcrypt');
const uuidv1 = require('uuid/v1');
const dbWrapper = require('@ro5635/dynamodbwrapper');

// Slowly going to move away from using @ro5635/dynamodbwrapper, this was useful as a learning tool but I will now just
// directly use the docClient directly, as a transitional stage docClient is exposed by @ro5635/dynamodbwrapper.
const docClient = dbWrapper.AWSDocClient;

const usersDBTable = process.env.USERSTABLE;
const usersEventsDBTable = process.env.USERSEVENTSTABLE;

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

            // Check for suspicious activity on account
            const userHasSuspiciousActivity = await detectFishyUserActivity(userData.userID);

            if (userHasSuspiciousActivity) {
                logger.error('Suspicious activity detected on account');
                logger.error('Aborting authentication process and returning account locked');

                reject(new Error('AuthenticationBlocked-AccountLocked'));

                // Once the response has been made to the caller complete the cleanup
                await putUserEvent(userData.userID, 'FailedLoginAttempt', getCurrentUnixTime());
                return;

            }


            // Check the supplied password matches the account that matches the userEmail supplied
            logger.debug('Checking user credentials');
            const suppliedCredentialsCorrect = await validateAuthenticationCredentials(userPassword, userData.userPasswordHash);

            // If login credentials where correct create a user and return it
            if (suppliedCredentialsCorrect) {

                logger.debug('Supplied password matched hash');

                // Create the User object
                logger.debug('Creating a new User instance from the user data');
                const callersUser = new User(userData.userID, userData.userEmail, userData.userFirstName, userData.userLastName, userData.userAge, userData.userRights, userData.userJWTPayload);

                // return the new User object
                resolve(callersUser);

                // After caller has had user object returned clean up by adding successful authentication event to the db
                logger.debug('Putting successfulAuthentication event to users events');
                await putUserEvent(userData.userID, 'successfulAuthentication', getCurrentUnixTime());

                return;

            }

            // Authentication details were incorrect, return AuthenticationFailure
            logger.debug('Supplied password did not match supplied username');
            logger.debug('Returning AuthenticationFailure');

            reject(new Error('AuthenticationFailure'));

            // Clean up by adding the authentication failure to the users events
            await putUserEvent(userData.userID, 'FailedLoginAttempt', getCurrentUnixTime());


        } catch (err) {
            // Catch any unexpected errors in the above block
            logger.error('Unexpected error occurred in getUser');
            logger.error(err);

            return reject(new Error('Unexpected error in getting user'));
        }

    });
};

/**
 * detectFishyUserActivity
 *
 * Checks for fishy activity on the users account, this currently is only for a number of failed
 * authentications in a time period.
 *
 * Returns a boolean to denote if the user has suspicious activity and authentication should be stalled.
 *
 *
 * @returns {Promise<boolean>}
 */
function detectFishyUserActivity(userID) {
    return new Promise(async (resolve, reject) => {

        try {

            const maxFailedAuthenticationAttempts = 10;

            // Get the last successful user authentication
            const successfulAuthentications = await getUserEvents(userID, 'successfulAuthentication');
            const lastSuccessfulAuthentication = successfulAuthentications[successfulAuthentications.length - 1];

            const threeMonthsAgoInUnix = Math.floor(addMonthsToDate(new Date(), -3) / 1000);

            // Search period is either up to the last successful authentication or 3 months, whichever is shortest
            const searchPeriodStartDateInUnix = lastSuccessfulAuthentication.eventOccuredAt > threeMonthsAgoInUnix ? lastSuccessfulAuthentication.eventOccuredAt : threeMonthsAgoInUnix

            logger.debug('Getting failedLoginAttempts for user');
            const failedLoginAttemptsInPeriod = await getUserFailedLoginAttemptsInPeriod(userID, searchPeriodStartDateInUnix);

            logger.debug(`User has ${failedLoginAttemptsInPeriod.length} failed authentications in search period`);

            // Has there been an unacceptable number of failed attempted logins?
            if (failedLoginAttemptsInPeriod.length > maxFailedAuthenticationAttempts) {
                logger.error('Too manny failed login attempts detected');

                return resolve(true);
            }

            //TODO: Add more account checks

            logger.debug('No fishy activity detected on account');
            return resolve(false)

        } catch (err) {

            logger.error('Error in detecting fishy user activity');
            logger.error(err);

            return reject(new Error('Failed to query for fishy user activity'));

        }

    });

    // Additional Functions used

    function addMonthsToDate(date, months) {
        date.setMonth(date.getMonth() + months);
        return date;
    }

}

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
 * get User Events
 *
 * Gets user events from the user events table for the provided userID and search eventType
 *
 * Limits: Will only return a maximum of 500 events
 *
 * @param userID        User Identifier
 * @param eventType     Event type to bring back (eg: 'FailedLoginAttempt', 'PasswordChange')
 * @returns {Promise<aquiredUserEvents>}        Array of acquired Events
 */
function getUserEvents(userID, eventType) {
    return new Promise(async (resolve, reject) => {

        const baseQuery = '#userID = :userID and #eventType = :eventType';
        const attributeNames = {'#userID': 'userID', '#eventType': 'eventType'};
        const attributeValues = {':userID': userID, ':eventType': eventType};

        try {

            logger.debug('Querying user Events Table');

            let requestParams = {};

            requestParams.TableName = usersEventsDBTable;
            requestParams.KeyConditionExpression = baseQuery;
            requestParams.ExpressionAttributeNames = attributeNames;
            requestParams.ExpressionAttributeValues = attributeValues;
            requestParams.Limit = 500;
            requestParams.IndexName = 'userID-eventType-index';

            const dbQueryResult = await docClient.query(requestParams).promise();

            logger.debug({
                dbRequestStats: {
                    'retrievedItems': dbQueryResult.Count,
                    'itemsScanned': dbQueryResult.ScannedCount
                }
            });

            const acquiredUserEvents = dbQueryResult.Items;

            logger.debug('Sorting events by eventOccuredAt');
            acquiredUserEvents.sort((a, b) => a.eventOccuredAt - b.eventOccuredAt);

            logger.debug('Successfully queried user events table');
            logger.debug('Returning user events');
            return resolve(acquiredUserEvents);


        } catch (err) {
            logger.error('Failed to query user Events Table');
            logger.error(err);
            logger.error('Returning Error from getUserEvents');
            return reject(err);

        }

    });

}

/**
 * putUserEvent
 *
 * Puts a new user event to the user events table
 *
 * @param userID
 * @param eventType
 * @param occurredAt
 * @param additionalParams      JSON object of any additional parameters to be included
 * @returns {Promise<any>}
 */
function putUserEvent(userID, eventType, occurredAt, additionalParams = {}) {
    return new Promise(async (resolve, reject) => {
        try {

            // Validation
            if (!userID || userID.length <= 0) return reject('No userID was supplied to putUserEvent, aborting.');
            if (!eventType || eventType.length <= 0) return reject('No eventType was supplied to putUserEvent, aborting.');
            if (!occurredAt || occurredAt.length <= 0) return reject('No occurredAt was supplied to putUserEvent, aborting.');

            // Create a new eventID
            // the put will then be conditional on this not existing, if it exists in the table then the put will fail.
            // It is the callers responsibility to re-call in the very rare case of UUID collision.
            const newEventID = uuidv1();

            // Build the database request object
            let requestParams = {};

            requestParams.TableName = usersEventsDBTable;
            requestParams.Item = {
                'eventID': newEventID,
                userID,
                eventType,
                'eventOccuredAt': occurredAt, ...additionalParams
            };

            // Add expression to ensure that it cannot overwrite an item on the case of a eventID collision
            requestParams.ConditionExpression = "attribute_not_exists(eventID)";

            logger.debug('Attempting to put new user event to database');
            const dbPut = await docClient.put(requestParams).promise();

            console.log(dbPut);

            return resolve();


        } catch (err) {
            logger.error('Failed to putUserEvent');
            logger.error(err);

            return reject(new Error('Failed to putUserEvent'));

        }

    });
}

/**
 * get getUserFailedLoginAttemptsInPeriod
 *
 * Gets user FailedLoginAttempts from the user events table for the provided userID in the specified period
 * If no periodEndInUnix is passed then the current time is used
 *
 * The parameter periodEndInUnix is optional and the current time will be used by default
 *
 * With regards to dynamoDB costing on this query the initial key query of the userID and EventType consume the read
 * capacity units, dynamoDB then handles filtering the data resulting from this query down as per the filter expression
 * and then returns the filtered data set, there is no additional consumed read capacity units for this additional
 * filtering.
 *
 * @param userID                                User Identifier
 * @param periodStartInUnix                     Unix Epoch timestamp in seconds that events brought back should AFTER
 * @param periodEndInUnix                       Unix Epoch timestamp in seconds that events brought back should BEFORE
 * @returns {Promise<aquiredUserEvents>}        Array of aquired Events
 */
function getUserFailedLoginAttemptsInPeriod(userID, periodStartInUnix, periodEndInUnix) {
    return new Promise(async (resolve, reject) => {

        // If the periodEndInUnix is not passed use the current time as the search end date
        periodEndInUnix = (typeof periodEndInUnix === 'undefined') ? getCurrentUnixTime() : periodEndInUnix;

        // Construct the query
        const baseQuery = '#userID = :userID and #eventType = :eventType';
        const filterExpression = "#eventOccuredAt  > :EventsAfterUnixStamp and #eventOccuredAt < :EventsBeforeUnixStamp";

        const attributeNames = {
            '#userID': 'userID',
            '#eventType': 'eventType',
            '#eventOccuredAt': 'eventOccuredAt',
        };
        const attributeValues = {
            ':userID': userID,
            ':eventType': 'FailedLoginAttempt',
            ':EventsAfterUnixStamp': periodStartInUnix,
            ':EventsBeforeUnixStamp': periodEndInUnix
        };

        try {

            logger.debug('Querying user Events Table for FailedLoginAttempts');
            logger.debug(`In Period starting: ${periodStartInUnix} and ending: ${periodEndInUnix}`);

            requestParams = {};

            requestParams.TableName = usersEventsDBTable;
            requestParams.KeyConditionExpression = baseQuery;
            requestParams.ExpressionAttributeNames = attributeNames;
            requestParams.ExpressionAttributeValues = attributeValues;
            requestParams.FilterExpression = filterExpression;
            requestParams.IndexName = 'userID-eventType-index';

            const dbQueryResult = await docClient.query(requestParams).promise();

            logger.debug({
                dbRequestStats: {
                    'retrievedItems': dbQueryResult.Count,
                    'itemsScanned': dbQueryResult.ScannedCount
                }
            });

            const acquiredUserEvents = dbQueryResult.Items;

            logger.debug('Sorting events by eventOccuredAt');
            acquiredUserEvents.sort((a, b) => a.eventOccuredAt - b.eventOccuredAt);

            logger.debug('Successfully queried user FailedLoginAttempts on user Events table');
            logger.debug('Returning user FailedLoginAttempts');
            return resolve(acquiredUserEvents);


        } catch (err) {
            logger.error('Failed to query user Events Table for FailedLoginAttempts');
            logger.error(err);
            logger.error('Returning Error from getting FailedLoginAttemptsInPeriod');
            return reject(err);

        }

        // Function to get the current Unix time
        function getCurrentUnixTime() {
            // Javascript gives in milliseconds by default
            // convert to seconds and return
            return Math.floor(new Date() / 1000);
        }

    });

}

/**
 * getCurrentUnixTime
 *
 * Gets the current time in the unix time stamp format
 *
 * @returns {number}
 */
function getCurrentUnixTime() {
    // Javascript gives in milliseconds by default
    // convert to seconds and return
    return Math.floor(new Date() / 1000);
}

/**
 * User Object
 *
 * Models a user within the system and the interactions that can be completed on a user
 *
 * @param userID
 * @param email
 * @param firstName
 * @param lastName
 * @param age
 * @param rights                    JSON Object detail users rights
 * @param jwtPayload                JSON Object with additional payload
 * @constructor
 */
function User(userID, email, firstName, lastName, age, rights, jwtPayload) {
    this._userID = userID;
    this._email = email;
    this._firstname = firstName;
    this._lastName = lastName;
    this._age = age;
    this._rights = rights;
    this._jwtPayload = jwtPayload;


    this.getUserID = function () {
        return this._userID;
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