/**
 * Index Router
 *
 * Handles the root path of the API
 */
const express = require('express');
const router = express.Router();
const logger = require('../Helpers/LogHelper').getLogger(__filename);
const apiVersion = require('../package').version;

router.get('/', function (req, res, next) {
    logger.debug('Responding to caller with API name and version');

    res.send({msg: 'Authentication Service API', version: apiVersion});
});


module.exports = router;