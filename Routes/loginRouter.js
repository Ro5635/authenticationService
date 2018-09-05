/**
 * Login Router
 *
 * Handles the login routes for the authentication API
 */

const express = require('express');
const router = express.Router();
const logger = require('../Helpers/LogHelper').getLogger(__filename);

const loginLogic = require('../Controllers/LoginController');

/**
 * POST to /login/
 */
router.post('/', async function (req, res) {

    logger.debug('Request received to login route');
    logger.debug('Processing login attempt');

    const passedUserEmail = req.body.userEmail;
    const passedUserPassword = req.body.userPassword;

    try {

        const responseObject = await loginLogic.handleLogin(passedUserEmail, passedUserPassword);

        logger.debug('Returning signed JWT to caller');
        res.send(responseObject);

    } catch (err) {

        if (err.status > 0) {
            return res.status(err.status).send(err.response);
        }

        logger.error('Unexpected error');
        logger.error(err);
        logger.error('Returning unexpected Error to caller');

        // unexpected error format, return unexpected error
        return res.status(500).send({Error: "Unexpected Error"});

    }


});


module.exports = router;