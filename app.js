const express = require('express');
const path = require('path');
const logger = require('morgan');
const cookieParser = require('cookie-parser');
const bodyParser = require('body-parser');
const jwt = require('jsonwebtoken');

// // Get JWT Secret
// const JWT_SECRET = process.env.JWT_SECRET;
// // Validate JWT Secret
// if (!JWT_SECRET || JWT_SECRET.length <= 8) {
//     console.error('Supplied JWT secret was not sufficiently complex');
//     console.error('Fatal Error');
//     console.error('Exiting');
//     process.exit(1)
//
// }


// Setup Routers
const index = require('./Routes/index');

const app = express();

// Middleware
app.use(logger('dev'));
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({extended: false}));
app.use(cookieParser());


app.use(function (req, res, next) {
    "use strict";
    res.setHeader('x-powered-by', 'The Geese');
    res.setHeader('content-type', 'application/json');
    res.setHeader('Access-Control-Allow-Origin', '*');
    next();
});


// Handle JWT
app.use(function (req, res, next) {

    const passedJWT = req.headers.jwt;

    // If the user supplied a JWT validate it and add it to the req object
    // because a JWT is required on only some of the paths in the routers it
    // is the responsibility of the paths them selves to check the existence and
    // suitability (regarding granted access rights) of teh callers JWT
    if (passedJWT) {
        jwt.verify(passedJWT, JWT_SECRET, function (err, decoded) {
            if (err) {
                // The JWT was invalid
                console.error('An Invalid JWT was supplied');
                console.error('Supplied JWT: ' + passedJWT);
                return res.status(401).send();
            }

            req.validatedJWT = decoded;

            next();

        });
    } else {
        next();

    }



});


// Routers
app.use('/', index);


// catch 404 and forward to error handler
app.use(function (req, res, next) {
    let err = new Error('Not Found');
    err.status = 404;
    next(err);
});

// error handler
app.use(function (err, req, res, next) {
    // set locals, only providing error in development
    res.locals.message = err.message;
    res.locals.error = req.app.get('env') === 'development' ? err : {};

    console.log(err);

    // render the error page
    res.status(err.status || 500);
    res.status(404).send({Error: 'Endpoint not found'});
});

module.exports = app;