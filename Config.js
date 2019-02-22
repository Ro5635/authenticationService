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
    AUTH_JWT_SECRET: = "EggsAndHamAreNice",
    USERSTABLE: "globalUsersTable",
    USERSEVENTSTABLE: "globalUserEvents2",
    AWS_API_CONFIG: {region: "local", endpoint: 'http://localhost:8000'}

};

const devSAMLocal = {
    BOREHOLES_TABLE_NAME: "boreholesTable",
    AWS_API_CONFIG: {region: "local", endpoint: 'http://dynamodb-local:8000'}

};


const test = {
    BOREHOLES_TABLE_NAME: "boreholesTable",
    AWS_API_CONFIG: {region: "local", endpoint: 'http://dynamodb-local:8000'}

};

const prod = {
    BOREHOLES_TABLE_NAME: process.env.BOREHOLE_TABLE_NAME

};

const config = {
    dev,
    devSAMLocal,
    test,
    prod
};

const currentConfig = Object.assign(defaultConfig, config[env]);

module.exports = currentConfig;

AUTH_JWT_SECRET=EggsAndHamAreNice;USERSTABLE=globalUsersTable;USERSEVENTSTABLE=globalUserEvents2