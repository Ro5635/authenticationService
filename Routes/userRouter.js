/**
 * User Router
 *
 * Handles the user routes for the authentication API
 */

const express = require('express');
const router = express.Router();
const logger = require('../Helpers/LogHelper').getLogger(__filename);

// Validation and sanitation modules
const {check, validationResult} = require('express-validator/check');
const createDOMPurify = require('dompurify');
const {JSDOM} = require('jsdom');
const window = (new JSDOM('')).window;
const DOMPurify = createDOMPurify(window);

// UserLogic
const UserLogic = require('../Controllers/UsersController');


/**
 * POST to /user/create
 */
router.post('/create', [
    // username must be an email
    check('userEmail').isEmail(),
    // password must be at least 5 chars long
    check('userPassword').isLength({min: 8}),
    check('userFirstName').isLength({max: 30}),
    check('userLastName').isLength({max: 30}),
    check('userAge').isInt(),
    check('userRights').isLength({max: 3000}),
    check('userJWTPayload').isLength({max: 3000})

], async (req, res) => {

    try {

        logger.debug('Request received to /user/create route');
        logger.debug('Processing user creation attempt');
        logger.debug('Checking validation rules');

        // check request for validation errors
        const errors = validationResult(req);

        if (!errors.isEmpty()) {
            logger.error('Error parsing user input');
            logger.error(errors.array());

            logger.error('Returning to caller unacceptable input');
            return res.status(422).json({"Error": "Input Does Not Match Specification"});
        }

        logger.debug('Validation passed');

        // Sanitise to be on the safe side
        const userPassword = req.body.userPassword;
        const cleanEmail = DOMPurify.sanitize(req.body.userEmail);
        const cleanFName = DOMPurify.sanitize(req.body.userFirstName);
        const cleanLName = DOMPurify.sanitize(req.body.userLastName);
        const cleanAge = DOMPurify.sanitize(req.body.userAge);
        const cleanRightsString = DOMPurify.sanitize(JSON.stringify(req.body.userRights));
        const cleanJWTPayloadString = DOMPurify.sanitize(JSON.stringify(req.body.userJWTPayload));

        // Rebuild the JSON objects
        const cleanRights = JSON.parse(cleanRightsString);
        const cleanJWTPayload = JSON.parse(cleanJWTPayloadString);

        // Attempt to create a new user
        const response = await UserLogic.handleCreateUser(req.validatedJWT.userID, userPassword, cleanEmail, cleanFName, cleanLName, cleanAge, cleanRights, cleanJWTPayload);

        logger.debug('User creation request succeeded');
        logger.debug('Returning new User to caller');

        res.send(response);

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