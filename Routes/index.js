/**
 * Index Router
 *
 * Handles the root path of the API
 */
const express = require('express');
const router = express.Router();
const apiVersion = require('../package').version;

router.get('/', function (req, res, next) {
    console.log('Responding to caller with API name and version');

    res.send({msg: 'Authentication Service API', version: apiVersion});
});


module.exports = router;