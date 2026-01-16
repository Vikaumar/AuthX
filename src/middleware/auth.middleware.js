/**
 * Authentication Middleware
 * Validates JWT access tokens and attaches user info to request
 */

const jwtUtil = require('../utils/jwt.util');
const { sendUnauthorized } = require('../utils/response.util');
const { ERROR_MESSAGES } = require('../config/constants');
const logger = require('../utils/logger.util');

/**
 * Middleware to authenticate requests using JWT access tokens
 * Extracts token from Authorization header (Bearer scheme)
 * Attaches decoded user info to req.user
 */
const authenticate = (req, res, next) => {
  try {
    // Get authorization header
    const authHeader = req.headers.authorization;
    
    if (!authHeader) {
      return sendUnauthorized(res, ERROR_MESSAGES.AUTHENTICATION_REQUIRED);
    }
    
    // Check for Bearer scheme
    const parts = authHeader.split(' ');
    
    if (parts.length !== 2 || parts[0] !== 'Bearer') {
      return sendUnauthorized(res, 'Invalid authorization header format. Use: Bearer <token>');
    }
    
    const token = parts[1];
    
    // Verify the access token
    const decoded = jwtUtil.verifyAccessToken(token);
    
    // Attach user info to request for downstream use
    req.user = {
      userId: decoded.userId,
      email: decoded.email,
      role: decoded.role
    };
    
    // Log authenticated request (debug level)
    logger.debug('Request authenticated', { 
      userId: decoded.userId, 
      path: req.path 
    });
    
    next();
    
  } catch (error) {
    // Handle specific JWT errors
    if (error.message === 'Access token expired') {
      return sendUnauthorized(res, ERROR_MESSAGES.TOKEN_EXPIRED);
    }
    
    if (error.message === 'Invalid access token') {
      return sendUnauthorized(res, ERROR_MESSAGES.TOKEN_INVALID);
    }
    
    logger.warn('Authentication failed', { 
      error: error.message, 
      path: req.path 
    });
    
    return sendUnauthorized(res, ERROR_MESSAGES.TOKEN_INVALID);
  }
};

/**
 * Optional authentication middleware
 * Like authenticate, but doesn't fail if no token is present
 * Useful for routes that work differently for authenticated vs anonymous users
 */
const optionalAuthenticate = (req, res, next) => {
  const authHeader = req.headers.authorization;
  
  // No header = continue as anonymous
  if (!authHeader) {
    req.user = null;
    return next();
  }
  
  // If header exists, validate it properly
  const parts = authHeader.split(' ');
  
  if (parts.length !== 2 || parts[0] !== 'Bearer') {
    req.user = null;
    return next();
  }
  
  try {
    const decoded = jwtUtil.verifyAccessToken(parts[1]);
    req.user = {
      userId: decoded.userId,
      email: decoded.email,
      role: decoded.role
    };
  } catch (error) {
    // Token invalid, treat as anonymous
    req.user = null;
  }
  
  next();
};

module.exports = {
  authenticate,
  optionalAuthenticate
};
