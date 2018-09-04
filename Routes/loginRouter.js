/**
 * Login Router
 *
 * Handles the login routes for the authentication API
 */

const express = require('express');
const router = express.Router();
const logger = require('../Helpers/LogHelper').getLogger(__filename);

const userModel = require('../Models/userModel');
const authTokenProvider = require('../Models/authTokenProvider');

/**
 * POST to /login/
 */
router.post('/', async function (req, res) {

    logger.debug('Request received to login route');
    logger.debug('Processing login attempt');

    // TODO: Extract logic from router


    try {

        // Attempt to get user model with the provided credentials
        const user = await userModel.getUser('Robert', 'password');

        logger.debug('Successfully got user from User Model');

        logger.debug('requesting JWT');

        let jwtPayload = {};

        jwtPayload.userName = user.getUserName();
        jwtPayload.firstName = user.getFirstName();
        jwtPayload.lastName = user.getLastName();
        jwtPayload.age = user.getAge();
        jwtPayload.email = user.getEmail();
        jwtPayload.rights = user.getRights();
        jwtPayload.jwtPayload = user.getJWTPayload();

        const token = await authTokenProvider.getToken(jwtPayload);

        res.send(token);



    } catch (err) {

        logger.error('Failed to login');
        logger.error(err);

        if (err.message === "AuthenticationFailure") {
            logger.error('Returning authentication failure to caller');
            return res.status(401).send({Error: "AuthenticationFailure"});
        }

        logger.error('Unexpected unknown error in login resource');
        logger.error('Returning unexpected error to caller');

        return res.status(500).send({Error: "Unexpected Error"});


    }

});


module.exports = router;