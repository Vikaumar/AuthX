/**
 * Response Utility
 * Standardizes API responses for consistency across all endpoints
 */

const { HTTP_STATUS } = require('../config/constants');

/**
 * Send a successful response
 * 
 * @param {Object} res - Express response object
 * @param {Object} options - Response options
 * @param {number} [options.statusCode=200] - HTTP status code
 * @param {string} options.message - Success message
 * @param {Object} [options.data] - Response data payload
 */
const sendSuccess = (res, { statusCode = HTTP_STATUS.OK, message, data = null }) => {
  const response = {
    success: true,
    message
  };
  
  if (data !== null) {
    response.data = data;
  }
  
  res.status(statusCode).json(response);
};

/**
 * Send an error response
 * 
 * @param {Object} res - Express response object
 * @param {Object} options - Response options
 * @param {number} [options.statusCode=500] - HTTP status code
 * @param {string} options.message - Error message
 * @param {Array} [options.errors] - Validation or field-specific errors
 * @param {string} [options.code] - Error code for client handling
 */
const sendError = (res, { 
  statusCode = HTTP_STATUS.INTERNAL_SERVER_ERROR, 
  message, 
  errors = null,
  code = null 
}) => {
  const response = {
    success: false,
    message
  };
  
  if (code) {
    response.code = code;
  }
  
  if (errors && errors.length > 0) {
    response.errors = errors;
  }
  
  res.status(statusCode).json(response);
};

/**
 * Send a validation error response
 * 
 * @param {Object} res - Express response object
 * @param {Array} errors - Array of validation errors
 */
const sendValidationError = (res, errors) => {
  sendError(res, {
    statusCode: HTTP_STATUS.BAD_REQUEST,
    message: 'Validation failed',
    errors: errors.map(err => ({
      field: err.path || err.param,
      message: err.msg || err.message
    })),
    code: 'VALIDATION_ERROR'
  });
};

/**
 * Send an unauthorized response
 * 
 * @param {Object} res - Express response object
 * @param {string} [message='Authentication required'] - Error message
 */
const sendUnauthorized = (res, message = 'Authentication required') => {
  sendError(res, {
    statusCode: HTTP_STATUS.UNAUTHORIZED,
    message,
    code: 'UNAUTHORIZED'
  });
};

/**
 * Send a forbidden response
 * 
 * @param {Object} res - Express response object
 * @param {string} [message='Access denied'] - Error message
 */
const sendForbidden = (res, message = 'Access denied') => {
  sendError(res, {
    statusCode: HTTP_STATUS.FORBIDDEN,
    message,
    code: 'FORBIDDEN'
  });
};

/**
 * Send a rate limit exceeded response
 * 
 * @param {Object} res - Express response object
 * @param {number} [retryAfter] - Seconds until rate limit resets
 */
const sendRateLimitExceeded = (res, retryAfter = null) => {
  if (retryAfter) {
    res.set('Retry-After', String(retryAfter));
  }
  
  sendError(res, {
    statusCode: HTTP_STATUS.TOO_MANY_REQUESTS,
    message: 'Too many requests. Please try again later.',
    code: 'RATE_LIMIT_EXCEEDED'
  });
};

module.exports = {
  sendSuccess,
  sendError,
  sendValidationError,
  sendUnauthorized,
  sendForbidden,
  sendRateLimitExceeded
};
