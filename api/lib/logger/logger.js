const winston = require("winston");

const { LOG_LEVEL } = require("../../config");

const formats = winston.format.combine(
  winston.format.timestamp({ format: "YYYY-MM-DD HH:mm:ss.SSS" }),
  winston.format.simple(),
  winston.format.splat(),
  winston.format.printf(info=> `${info.timestamp} ${info.level.toLocaleUpperCase()}: [email:${info.message.email}]  [location:${info.message.location}] [procType:${info.message.proc_type}]` )
)

const logger = winston.createLogger({
  level: LOG_LEVEL,
  transports: [
    new (winston.transports.Console)({ format: formats })
  ]
});

module.exports = logger