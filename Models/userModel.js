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
const config = require('../config');

// Slowly going to move away from using @ro5635/dynamodbwrapper, this was useful as a learning tool but I will now just
// directly use the docClient directly, as a transitional stage docClient is exposed by @ro5635/dynamodbwrapper.
const docClient = dbWrapper.AWSDocClient;

const usersDBTable = config.USERSTABLE;
const usersEventsDBTable = config.USERSEVENTSTABLE;
const usersDBUserEmailIndex = config.USERS_TABLE_USEREMAIL_INDEX;
const usersEventsDBUserIDEventTypeIndex = config.USEREVENTS_TABLE_USERID_EVENTTYPE_INDEX;


/**
 * getUserByEmail
 *
 * Returns a user object if the provided authentication details match a user account
 *
 * There is currently a race condition where if two user accounts are requested at approximately the same time
 * two accounts will be created with the same email, these accounts will cause the login process for that
 * account to fail. To knockout this race condition the createUser function could check for duplicates on close and
 * then remove its own newly created account on the event of duplicates, however this would require a
 * delete account function...
 *
 * @param userEmail                     user email
 * @param userPassword                  plain text user password
 * @returns {Promise<any>}
 */
exports.getUserByEmail = function (userEmail, userPassword) {
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
                logger.error('Supplied details: userEmail: ' + userEmail + ' userPassword: ' + userPassword);

                if (err.message === 'No User Found') {

                    logger.error('Invalid authentication details supplied for user, could not find user for supplied email');

                    // There is no need to log the failed authentication attempt as there is no user to log it against
                    return reject(new Error('AuthenticationFailure'));

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

                // logger.debug('Adding authenticationFailure to userEvent log');
                await putUserEvent(userData.userID, 'FailedLoginAttempt', getCurrentUnixTime());

                return reject(new Error('AuthenticationBlocked-AccountLocked'));

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

                // Add successful authentication event to the db
                logger.debug('Putting successfulAuthentication event to users events');
                await putUserEvent(userData.userID, 'successfulAuthentication', getCurrentUnixTime());

                // return the new User object
                return resolve(callersUser);


            }

            // Authentication details were incorrect, return AuthenticationFailure
            logger.debug('Supplied password did not match supplied username');

            logger.debug('Adding authenticationFailure to userEvent log');
            await putUserEvent(userData.userID, 'FailedLoginAttempt', getCurrentUnixTime());

            logger.debug('Returning AuthenticationFailure');
            return reject(new Error('AuthenticationFailure'));


        } catch (err) {
            // Catch any unexpected errors in the above block
            logger.error('Unexpected error occurred in getUserByEmail');
            logger.error(err);

            return reject(new Error('Unexpected error in getting userByEmail'));
        }

    });
};


/**
 * Get a User by userID
 *
 * This function does not require authentication details for the requested user and is designed to be used internally
 * The userID passed to this function therefore must be a trusted value, for example from a signed and valid JWT issued
 * from a trusted source.
 *
 * @param userID        Users UserID, this should be trusted from a valid JWT
 */
exports.getUserByID = function (userID) {
    return new Promise(async (resolve, reject) => {
        try {

            // Validate that the userID was passed
            if (!userID || userID.length <= 0) return reject(new Error('AuthenticationFailure'));

            // Get the user data from the DB
            let userData = {};

            try {
                userData = await getUserAttributesFromDBByID(userID);

            } catch (err) {
                logger.error('Error in getting user');
                logger.error('Supplied details: userID: ' + userID);

                if (err.message === 'AuthenticationFailure') {

                    logger.error('Invalid authentication details supplied for user');

                    // There is no need to log the failed authentication attempt as there is no user to log it against
                    return reject(err);

                }

                logger.error('Failed to get user attributes from DB for unexpected reason');
                logger.error(err);
                return reject(new Error('Failed to get user'));

            }

            logger.debug('Acquired User data from DB for supplied UserID');

            // Create the User object
            logger.debug('Creating a new User instance from the user data');

            const callersUser = new User(userData.userID, userData.userEmail, userData.userFirstName, userData.userLastName, userData.userAge, userData.userRights, userData.userJWTPayload);

            // Add account access event to the db
            logger.debug('Putting AccountAccessed event to users events');
            await putUserEvent(userData.userID, 'AccountAccessed', getCurrentUnixTime(), {"eventSource": "authenticationService"});

            return resolve(callersUser);


        } catch (err) {
            // Catch any unexpected errors in the above block
            logger.error('Unexpected error occurred in getUserByID');
            logger.error(err);

            return reject(new Error('Unexpected error in getting user'));
        }
    });
};

/**
 * createNewUser
 *
 * Creates a new user in the system, the calling function is responsible for ensuring that the calling user has the
 * necessary rights to create a new user.
 *
 * Constraints:
 * A new user cannot be created where the email is already allocated to an existing user
 *
 * @param password              Plain text password for hash generation
 * @param email
 * @param firstName
 * @param lastName
 * @param age
 * @param rights                JSON Object
 * @param jwtPayload            JSON Object
 */
exports.createNewUser = function (password, email, firstName, lastName, age, rights, jwtPayload) {
    return new Promise(async (resolve, reject) => {

        // Create an object to hold details of the new users creation
        const creationDetails = {CreatedAt: getCurrentUnixTime(), createdBy: 'authenticationService'};

        try {

            // Validation
            if (!email || email.length <= 0) return reject(new Error('ValidationFailed'));
            if (!firstName || firstName.length <= 0) return reject(new Error('ValidationFailed'));
            if (!lastName || lastName.length <= 0) return reject(new Error('ValidationFailed'));
            if (!age || age.length <= 0) return reject(new Error('ValidationFailed'));

            if (!rights) return reject(new Error('ValidationFailed'));
            if (!jwtPayload) return reject(new Error('ValidationFailed'));


            // Check that there is not an existing user with the provided email address
            // dynamoDB can only enforce unique constraints on the hash key, so we must
            // enforce the integrity of the hash key ourselves.
            logger.debug('Checking for existing user with provided email address');


            try {
                // If a user is not found then this call will throw and exception
                await getUserAttributesFromDBByEmail(email);
                logger.error('User found using passed email address, cannot create new user with provided email address');
                throw new Error('User Exists');

            } catch (err) {
                if (err.message === 'No User Found') {
                    logger.debug('No existing user was found with the supplied new email');
                    // Resuming process to create user

                } else if (err.message === 'Multiple Accounts Found') {
                    logger.error('Multiple existing users found using new email address');
                    logger.error('Cannot create account with address already in use');
                    throw new Error('User Exists');

                } else if (err.message === 'User Exists') {
                    // This could do with some refactoring, its not particularly clear code...
                    // re-throw error to be caught by outer catch
                    throw err;

                } else {
                    logger.error('Unexpected error in getting user details by email from DB');
                    throw new Error('Error In Testing For Existing User Email');
                }
            }


            // Get a new userID
            // the put will then be conditional on this not existing, if it exists in the table then the put will fail.
            // It is the callers responsibility to re-call in the very rare case of UUID collision.
            const newUserID = uuidv1();

            logger.debug('Generating password hash');
            const hashedPassword = await generatePasswordHash(password);

            logger.debug('Attempting to create new user on DB');

            // Build the database request object
            let requestParams = {};

            requestParams.TableName = usersDBTable;
            requestParams.Item = {
                "userID": newUserID,
                "userEmail": email,
                "userPasswordHash": hashedPassword,
                "userFirstName": firstName,
                "userLastName": lastName,
                "userAge": age,
                "userRights": rights,
                "userJWTPayload": jwtPayload,
                creationDetails
            };

            // Add expression to ensure that it cannot overwrite an item on the case of a userID collision
            requestParams.ConditionExpression = "attribute_not_exists(userID)";

            logger.debug('Attempting to put new user to database');
            await docClient.put(requestParams).promise();

            logger.debug('Successfully created new user');
            logger.debug('Creating new User object from new user');

            const newUser = await this.getUserByID(newUserID);

            logger.debug('Successfully got new  User object with newly created user');

            logger.debug('Putting account creation event to new user events');
            await putUserEvent(newUser.getUserID(), 'AccountCreated', getCurrentUnixTime(), {"eventSource": "authenticationService"});

            return resolve(newUser);


        } catch (err) {
            logger.error('Failed to create new user');
            logger.error(err);

            // Check to see if it is one of the expected errors
            if (err.message === 'User Exists') {
                return reject(err);
            }

            // Unexpected error, return a general error
            return reject(new Error('FailedToCreateUser'));


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
            const threeMonthsAgoInUnix = Math.floor(addMonthsToDate(new Date(), -3) / 1000);

            // Get the last successful user authentication
            const successfulAuthentications = await getUserEvents(userID, 'successfulAuthentication');

            let searchPeriodStartDateInUnix;

            // If there is no previous successful authentication then use the default time period
            if (successfulAuthentications.length > 0) {
                const lastSuccessfulAuthentication = successfulAuthentications[successfulAuthentications.length - 1];

                // Search period is either up to the last successful authentication or 3 months, whichever is shortest
                searchPeriodStartDateInUnix = lastSuccessfulAuthentication.eventOccurredAt > threeMonthsAgoInUnix ? lastSuccessfulAuthentication.eventOccurredAt : threeMonthsAgoInUnix

            } else {
                // There is no previous successful login recorded, use default time period
                searchPeriodStartDateInUnix = threeMonthsAgoInUnix;

            }


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
 * getUserAttributesFromDBByID
 *
 * Get userData from the DB by userID
 *
 * @param userID            userID of the User to get from the DB
 * @returns {Promise<userData>}
 */
function getUserAttributesFromDBByID(userID) {
    return new Promise(async (resolve, reject) => {

        logger.debug('Querying users table by userID');

        try {

            if (!userID || userID.length <= 0) throw new Error('Cannot get undefined User');

            let requestParams = {};

            requestParams.TableName = usersDBTable;
            requestParams.Key = {"userID": userID};

            const dbQueryResult = await docClient.get(requestParams).promise();

            logger.debug('Successfully queried Users table for user data');

            // logger.debug({
            //     dbRequestStats: {
            //         'retrievedItems': dbQueryResult.Count,
            //         'itemsScanned': dbQueryResult.ScannedCount
            //     }
            // });

            if (dbQueryResult.Item) {
                logger.debug('Single user matching supplied userID found');
                const acquiredUserData = dbQueryResult.Item;

                return resolve(acquiredUserData);

            }

            logger.debug('No user was found for the supplied userID');
            logger.debug('returning UserNotFound error');
            return reject(new Error('UserNotFound'));


        } catch (err) {
            logger.error('Failed to query DB for user');
            logger.error(err);

            return reject(err);
        }

    });
}

/**
 * getUserAttributesFromDBByEmail
 *
 * Gets a user from the DB if one is found matching the supplied userEmail
 *
 * @param userEmail
 * @returns {Promise<userData>}     JSON Object containing the DBs user data for the supplied userEmail
 */
function getUserAttributesFromDBByEmail(userEmail) {
    return new Promise(async (resolve, reject) => {

        const baseQuery = '#userEmail = :userEmail';
        const attributeNames = {'#userEmail': 'userEmail'};
        const attributeValues = {':userEmail': userEmail};

        try {
            // Attempt to get user object for supplied userID by calling the DB
            const dbQueryResult = await dbWrapper.query(baseQuery, attributeNames, attributeValues, usersDBTable, usersDBUserEmailIndex);

            logger.debug({
                dbRequestStats: {
                    'retrievedItems': dbQueryResult.Count,
                    'itemsScanned': dbQueryResult.ScannedCount
                }
            });

            if (dbQueryResult.Count === 1) {

                logger.debug('Found user in db');
                const acquiredUser = dbQueryResult.Items[0];

                // return user item
                return resolve(acquiredUser);

            } else if (dbQueryResult.Count === 0) {
                logger.debug('No User found matching query parameters');
                logger.debug('Returning incorrect authentication details');
                throw new Error('No User Found');

            } else if (dbQueryResult.Count > 1) {
                logger.error('Error in querying DB, unexpected count of users found');
                logger.error('More than one user found matching email');
                logger.error('Returning multiple accounts matched error to user');
                throw new Error('Multiple Accounts Found');

            }

            logger.error('Error in querying DB, unexpected count of users found');
            logger.error('Returning unexpected error to caller');
            throw new Error('Unexpected User Count');


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

function generatePasswordHash(plainTextPassword) {
    return new Promise(async (resolve, reject) => {

        const saltRounds = 10;

        try {
            // The first 22 characters of the hash decode to a 16-byte value for the salt
            // where the fist few characters separated by $ encode the algorithm type
            // The salt is added to the front of the cipher text.
            const newHash = await bcrypt.hash(plainTextPassword, saltRounds);

            return resolve(newHash);

        } catch (err) {
            logger.error('unexpected error in password hash generation');
            logger.error(err);

            return reject(new Error('Unexpected Error In Hashing Password'));

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
 * @returns {Promise<acquiredUserEvents>}        Array of acquired Events
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
            requestParams.IndexName = usersEventsDBUserIDEventTypeIndex;

            const dbQueryResult = await docClient.query(requestParams).promise();

            logger.debug({
                dbRequestStats: {
                    'retrievedItems': dbQueryResult.Count,
                    'itemsScanned': dbQueryResult.ScannedCount
                }
            });

            const acquiredUserEvents = dbQueryResult.Items;

            logger.debug('Sorting events by eventOccurredAt');
            acquiredUserEvents.sort((a, b) => a.eventOccurredAt - b.eventOccurredAt);

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
                'eventOccurredAt': occurredAt, ...additionalParams
            };

            // Add expression to ensure that it cannot overwrite an item on the case of a eventID collision
            requestParams.ConditionExpression = "attribute_not_exists(eventID)";

            logger.debug('Attempting to put new user event to database');
            await docClient.put(requestParams).promise();

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
 * @returns {Promise<acquiredUserEvents>}        Array of acquired Events
 */
function getUserFailedLoginAttemptsInPeriod(userID, periodStartInUnix, periodEndInUnix) {
    return new Promise(async (resolve, reject) => {

        // If the periodEndInUnix is not passed use the current time as the search end date
        periodEndInUnix = (typeof periodEndInUnix === 'undefined') ? getCurrentUnixTime() : periodEndInUnix;

        // Construct the query
        const baseQuery = '#userID = :userID and #eventType = :eventType';
        const filterExpression = "#eventOccurredAt  > :EventsAfterUnixStamp and #eventOccurredAt < :EventsBeforeUnixStamp";

        const attributeNames = {
            '#userID': 'userID',
            '#eventType': 'eventType',
            '#eventOccurredAt': 'eventOccurredAt',
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
            requestParams.IndexName = usersEventsDBUserIDEventTypeIndex;

            const dbQueryResult = await docClient.query(requestParams).promise();

            logger.debug({
                dbRequestStats: {
                    'retrievedItems': dbQueryResult.Count,
                    'itemsScanned': dbQueryResult.ScannedCount
                }
            });

            const acquiredUserEvents = dbQueryResult.Items;

            logger.debug('Sorting events by eventOccurredAt');
            acquiredUserEvents.sort((a, b) => a.eventOccurredAt - b.eventOccurredAt);

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
    };

    /**
     * hasRequiredRights
     *
     * Check that the caller has the required rights, if the user does not have the supplied right then false is returned.
     * If the user does have the required right then this will resolve true.
     *
     * @param requiredRights        Rights the caller needs to match, example: {'MachineAccess': {'read': 1}};
     * @returns {boolean}
     */
    this.hasRequiredRights = (requiredRights) => {

        // Checking callers rights
        // Get the users rights
        const grantedRights = this.getRights();

        // If the rights where not found return false
        if (!grantedRights) return false;


        for (let rightGroup in requiredRights) {

            // Check that the right group exists
            if(!grantedRights[rightGroup]) {
                return false;
            }

            // Check user has each of the rights in the right group
            for (let right in  requiredRights[rightGroup]) {

                if (grantedRights[rightGroup][right] !== 1) {
                    // console.error('Caller failed rights check');
                    // console.error('Caller had: ' + grantedRights);
                    // console.error('Caller required: ' + requiredRights);
                    // console.error('Failed right: ' + grantedRights[rightGroup][right]);

                    return false;
                }

            }

        }

        return true;


    };

}

module.exports = exports;