/**
 * Logger Utility
 * Provides structured logging with different log levels
 * In production, this could be extended to use Winston or Pino
 */

const LOG_LEVELS = {
  ERROR: 0,
  WARN: 1,
  INFO: 2,
  DEBUG: 3
};

// Get current log level from environment (default: INFO in production, DEBUG in development)
const getCurrentLogLevel = () => {
  const env = process.env.NODE_ENV || 'development';
  const configuredLevel = process.env.LOG_LEVEL?.toUpperCase();
  
  if (configuredLevel && LOG_LEVELS[configuredLevel] !== undefined) {
    return LOG_LEVELS[configuredLevel];
  }
  
  return env === 'production' ? LOG_LEVELS.INFO : LOG_LEVELS.DEBUG;
};

/**
 * Format log message with timestamp and level
 * @param {string} level - Log level
 * @param {string} message - Log message
 * @param {Object} [meta] - Additional metadata
 * @returns {string} Formatted log string
 */
const formatLog = (level, message, meta) => {
  const timestamp = new Date().toISOString();
  const metaStr = meta ? ` ${JSON.stringify(meta)}` : '';
  return `[${timestamp}] [${level}] ${message}${metaStr}`;
};

/**
 * Log error messages (always logged)
 * @param {string} message - Error message
 * @param {Object|Error} [meta] - Additional metadata or Error object
 */
const error = (message, meta) => {
  if (getCurrentLogLevel() >= LOG_LEVELS.ERROR) {
    if (meta instanceof Error) {
      console.error(formatLog('ERROR', message, { 
        error: meta.message, 
        stack: meta.stack 
      }));
    } else {
      console.error(formatLog('ERROR', message, meta));
    }
  }
};

/**
 * Log warning messages
 * @param {string} message - Warning message
 * @param {Object} [meta] - Additional metadata
 */
const warn = (message, meta) => {
  if (getCurrentLogLevel() >= LOG_LEVELS.WARN) {
    console.warn(formatLog('WARN', message, meta));
  }
};

/**
 * Log info messages
 * @param {string} message - Info message
 * @param {Object} [meta] - Additional metadata
 */
const info = (message, meta) => {
  if (getCurrentLogLevel() >= LOG_LEVELS.INFO) {
    console.info(formatLog('INFO', message, meta));
  }
};

/**
 * Log debug messages (only in development)
 * @param {string} message - Debug message
 * @param {Object} [meta] - Additional metadata
 */
const debug = (message, meta) => {
  if (getCurrentLogLevel() >= LOG_LEVELS.DEBUG) {
    console.debug(formatLog('DEBUG', message, meta));
  }
};

module.exports = {
  error,
  warn,
  info,
  debug,
  LOG_LEVELS
};
