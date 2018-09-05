/**
 * LogHelper
 *
 * Provides the bunyan logger to modules as needed
 *
 * @type {Logger}
 */

const Logger = require('bunyan');

/**
 * Get a logger instance
 *
 * @param fileName      String - fileName of script
 * @returns {Logger}    Bunyan Logger Object
 */
exports.getLogger = (fileName) => {


    return new Logger({
        name: fileName,
        streams: [
            {
                stream: process.stdout,
                level: 'debug'
            }
        ],
        serializers: {
            req: Logger.stdSerializers.req
        },
    });

};


module.exports = exports;