/**
 * Application Constants
 * Centralized configuration values used throughout the application
 */

// User roles for RBAC
const ROLES = {
  USER: 'USER',
  ADMIN: 'ADMIN'
};

// Token types for identification
const TOKEN_TYPES = {
  ACCESS: 'access',
  REFRESH: 'refresh'
};

// HTTP Status codes for consistency
const HTTP_STATUS = {
  OK: 200,
  CREATED: 201,
  BAD_REQUEST: 400,
  UNAUTHORIZED: 401,
  FORBIDDEN: 403,
  NOT_FOUND: 404,
  CONFLICT: 409,
  TOO_MANY_REQUESTS: 429,
  INTERNAL_SERVER_ERROR: 500
};

// Error messages for standardized responses
const ERROR_MESSAGES = {
  // Authentication errors
  INVALID_CREDENTIALS: 'Invalid email or password',
  TOKEN_EXPIRED: 'Token has expired',
  TOKEN_INVALID: 'Invalid or malformed token',
  TOKEN_REVOKED: 'Token has been revoked',
  TOKEN_REUSE_DETECTED: 'Token reuse detected. All sessions have been invalidated for security.',
  REFRESH_TOKEN_REQUIRED: 'Refresh token is required',
  
  // Authorization errors
  ACCESS_DENIED: 'Access denied. Insufficient permissions.',
  AUTHENTICATION_REQUIRED: 'Authentication required',
  
  // User errors
  USER_EXISTS: 'User with this email already exists',
  USER_NOT_FOUND: 'User not found',
  USER_INACTIVE: 'User account is inactive',
  
  // Validation errors
  VALIDATION_ERROR: 'Validation failed',
  INVALID_INPUT: 'Invalid input data',
  
  // Rate limiting
  RATE_LIMIT_EXCEEDED: 'Too many requests. Please try again later.',
  
  // Server errors
  INTERNAL_ERROR: 'An unexpected error occurred',
  DATABASE_ERROR: 'Database operation failed'
};

// Success messages
const SUCCESS_MESSAGES = {
  REGISTERED: 'User registered successfully',
  LOGGED_IN: 'Login successful',
  LOGGED_OUT: 'Logged out successfully',
  TOKEN_REFRESHED: 'Token refreshed successfully'
};

module.exports = {
  ROLES,
  TOKEN_TYPES,
  HTTP_STATUS,
  ERROR_MESSAGES,
  SUCCESS_MESSAGES
};
