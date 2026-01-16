/**
 * Error Handler Middleware
 * Centralized error handling for consistent error responses
 */

const { sendError } = require('../utils/response.util');
const { HTTP_STATUS, ERROR_MESSAGES } = require('../config/constants');
const logger = require('../utils/logger.util');

/**
 * Custom application error class
 * Use this to throw errors with specific status codes
 */
class AppError extends Error {
  constructor(message, statusCode = HTTP_STATUS.INTERNAL_SERVER_ERROR, code = null) {
    super(message);
    this.statusCode = statusCode;
    this.code = code;
    this.isOperational = true; // Distinguishes from programming errors
    
    Error.captureStackTrace(this, this.constructor);
  }
}

/**
 * Not Found handler - for undefined routes
 */
const notFoundHandler = (req, res) => {
  sendError(res, {
    statusCode: HTTP_STATUS.NOT_FOUND,
    message: `Route ${req.method} ${req.path} not found`,
    code: 'NOT_FOUND'
  });
};

/**
 * Global error handler middleware
 * Must be the last middleware in the chain
 */
const errorHandler = (err, req, res, next) => {
  // Log the error
  logger.error('Error caught by global handler:', {
    message: err.message,
    code: err.code,
    stack: process.env.NODE_ENV === 'development' ? err.stack : undefined,
    path: req.path,
    method: req.method
  });
  
  // Handle known operational errors
  if (err.isOperational) {
    return sendError(res, {
      statusCode: err.statusCode,
      message: err.message,
      code: err.code
    });
  }
  
  // Handle specific error types
  
  // Database errors
  if (err.code === '23505') { // PostgreSQL unique violation
    return sendError(res, {
      statusCode: HTTP_STATUS.CONFLICT,
      message: 'Resource already exists',
      code: 'DUPLICATE_ENTRY'
    });
  }
  
  if (err.code === '23503') { // PostgreSQL foreign key violation
    return sendError(res, {
      statusCode: HTTP_STATUS.BAD_REQUEST,
      message: 'Referenced resource does not exist',
      code: 'FOREIGN_KEY_VIOLATION'
    });
  }
  
  // JWT errors (already handled by auth middleware, but safety net)
  if (err.name === 'JsonWebTokenError') {
    return sendError(res, {
      statusCode: HTTP_STATUS.UNAUTHORIZED,
      message: ERROR_MESSAGES.TOKEN_INVALID,
      code: 'INVALID_TOKEN'
    });
  }
  
  if (err.name === 'TokenExpiredError') {
    return sendError(res, {
      statusCode: HTTP_STATUS.UNAUTHORIZED,
      message: ERROR_MESSAGES.TOKEN_EXPIRED,
      code: 'TOKEN_EXPIRED'
    });
  }
  
  // Validation errors from express-validator
  if (err.array && typeof err.array === 'function') {
    return sendError(res, {
      statusCode: HTTP_STATUS.BAD_REQUEST,
      message: ERROR_MESSAGES.VALIDATION_ERROR,
      errors: err.array()
    });
  }
  
  // Syntax errors (malformed JSON)
  if (err instanceof SyntaxError && 'body' in err) {
    return sendError(res, {
      statusCode: HTTP_STATUS.BAD_REQUEST,
      message: 'Invalid JSON in request body',
      code: 'INVALID_JSON'
    });
  }
  
  // Unknown errors - don't leak details in production
  const message = process.env.NODE_ENV === 'production' 
    ? ERROR_MESSAGES.INTERNAL_ERROR 
    : err.message;
  
  sendError(res, {
    statusCode: HTTP_STATUS.INTERNAL_SERVER_ERROR,
    message,
    code: 'INTERNAL_ERROR'
  });
};

/**
 * Async handler wrapper
 * Catches errors in async route handlers and forwards to error middleware
 * 
 * @param {Function} fn - Async route handler function
 * @returns {Function} Wrapped function that catches errors
 * 
 * @example
 * router.get('/users', asyncHandler(async (req, res) => {
 *   const users = await User.findAll();
 *   res.json(users);
 * }));
 */
const asyncHandler = (fn) => {
  return (req, res, next) => {
    Promise.resolve(fn(req, res, next)).catch(next);
  };
};

module.exports = {
  AppError,
  notFoundHandler,
  errorHandler,
  asyncHandler
};
