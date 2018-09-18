/**
 * authTokenProvider
 *
 * This model is responsible for creating a valid singed JWT.
 *
 * ToDO: Extract this out into the helpers and rename to better represent its function as the JWT helper
 * TODO: Extract middleware jwt verification function to a better location
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

// Handle JWT
exports.validateJWT = (req, res, next) => {

    // Do not validate JWT for login path
    if (req.path === '/login') {
        logger.debug('JWT not required');
        return next();
    }

    logger.debug('Validating provided JWT');

    const passedJWT = req.headers.jwt;

    jwt.verify(passedJWT, JWT_SECRET, function (err, decoded) {
        if (err) {
            // The JWT was invalid
            logger.error('An Invalid JWT was supplied');
            logger.error(err);
            logger.error('Supplied JWT: ' + passedJWT);
            logger.error('Returning Access Unauthorised');
            return res.status(401).send();
        }

        logger.debug('Successfully validated JWT');

        req.validatedJWT = decoded;

        next();

    });

};

module.exports = exports;