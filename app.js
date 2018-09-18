const express = require('express');
const path = require('path');
const morganLogger = require('morgan');
const logger = require('./Helpers/LogHelper').getLogger(__filename);
const cookieParser = require('cookie-parser');
const bodyParser = require('body-parser');
const validateJWT = require('./Models/authTokenProvider').validateJWT;

// Setup Routers
const index = require('./Routes/index');
const loginRouter = require('./Routes/loginRouter');
const userRouter = require('./Routes/userRouter');

const app = express();

// Middleware
app.use(morganLogger('dev'));
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({extended: false}));
app.use(cookieParser());

app.use(function (req, res, next) {
    "use strict";
    res.setHeader('x-powered-by', 'The Geese');
    res.setHeader('content-type', 'application/json');
    // TODO: Create list of allowed origins
    res.setHeader('Access-Control-Allow-Origin', '*');
    next();
});

// validate JWT
app.all('*', validateJWT);


// Routers
app.use('/', index);
app.use('/login', loginRouter);
app.use('/user/', userRouter);

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