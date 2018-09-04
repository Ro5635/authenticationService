/**
 * authTokenProvider
 *
 * This model is responsible for creating a valid singed JWT.
 */

const jwt = require('jsonwebtoken');
const logger = require('../Helpers/LogHelper').getLogger(__filename);
const JWT_SECRET = process.env.AUTH_JWT_SECRET;

if (JWT_SECRET.length < 8) {
    logger.error('Supplied JWT secret fails complexity test');
    logger.error('Fatal Error');
    logger.error('Aborting');
    logger.error('Please supply a more complex JWT secret in the environment variables');
    process.exit(1);
}

exports.getToken = (payload) => {
    return new Promise((resolve, reject) => {

        const token = jwt.sign(payload, JWT_SECRET);

        logger.info('Singed new JWT');

        resolve(token);

    });
};


module.exports = exports;