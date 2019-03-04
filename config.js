/**
 * Master configuration file
 *
 * Parameters in defaultConfig can be overridden in the environment specific declarations
 */

const env = process.env.NODE_ENV;

const defaultConfig = {
    AWS_API_CONFIG: {}

};

const dev = {
    AUTH_JWT_SECRET: "EggsAndHamAreNice",
    USERSTABLE: "globalUsersTable",
    USERSEVENTSTABLE: "globalUserEvents2",
    AWS_API_CONFIG: {region: "local", endpoint: 'http://localhost:8000'},
    USEREVENTS_TABLE_USERID_EVENTTYPE_INDEX: 'userID-eventType-index',
    USERS_TABLE_USEREMAIL_INDEX: 'userEmail-index'

};

const devSAMLocal = {
    AUTH_JWT_SECRET: "EggsAndHamAreNice",
    USERSTABLE: "globalUsersTable",
    USERSEVENTSTABLE: "globalUserEvents2",
    AWS_API_CONFIG: {region: "local", endpoint: 'http://dynamodb-local:8000'},
    USEREVENTS_TABLE_USERID_EVENTTYPE_INDEX: 'userID-eventType-index',
    USERS_TABLE_USEREMAIL_INDEX: 'userEmail-index'

};


const test = {
    AUTH_JWT_SECRET: "EggsAndHamAreNice",
    USERSTABLE: "globalUsersTable",
    USERSEVENTSTABLE: "globalUserEvents2",
    AWS_API_CONFIG: {region: "local", endpoint: 'http://dynamodb-local:8000'},
    USEREVENTS_TABLE_USERID_EVENTTYPE_INDEX: 'userID-eventType-index',
    USERS_TABLE_USEREMAIL_INDEX: 'userEmail-index'

};

const prod = {
    AUTH_JWT_SECRET: process.env.AUTH_JWT_SECRET,
    USERSTABLE: process.env.USERSTABLE,
    USERSEVENTSTABLE: process.env.USERSEVENTSTABLE,
    USEREVENTS_TABLE_USERID_EVENTTYPE_INDEX: 'userID-eventType-index',
    USERS_TABLE_USEREMAIL_INDEX: 'userEmail-index'

};

const config = {
    dev,
    devSAMLocal,
    test,
    prod
};

const currentConfig = Object.assign(defaultConfig, config[env]);

module.exports = currentConfig;
