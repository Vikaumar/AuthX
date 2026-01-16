/**
 * Role-Based Access Control (RBAC) Middleware
 * Restricts access to routes based on user roles
 */

const { sendForbidden, sendUnauthorized } = require('../utils/response.util');
const { ROLES, ERROR_MESSAGES } = require('../config/constants');
const logger = require('../utils/logger.util');

/**
 * Create middleware that requires specific roles
 * Must be used AFTER authenticate middleware
 * 
 * @param {...string} allowedRoles - Roles that are allowed access
 * @returns {Function} Express middleware function
 * 
 * @example
 * // Single role
 * router.get('/admin', authenticate, requireRoles(ROLES.ADMIN), adminController);
 * 
 * // Multiple roles
 * router.get('/dashboard', authenticate, requireRoles(ROLES.USER, ROLES.ADMIN), dashboardController);
 */
const requireRoles = (...allowedRoles) => {
  return (req, res, next) => {
    // Check if user is authenticated
    if (!req.user) {
      logger.warn('RBAC check failed: No user on request', { path: req.path });
      return sendUnauthorized(res, ERROR_MESSAGES.AUTHENTICATION_REQUIRED);
    }
    
    const userRole = req.user.role;
    
    // Check if user's role is in allowed roles
    if (!allowedRoles.includes(userRole)) {
      logger.warn('RBAC check failed: Insufficient permissions', {
        userId: req.user.userId,
        userRole,
        requiredRoles: allowedRoles,
        path: req.path
      });
      
      return sendForbidden(res, ERROR_MESSAGES.ACCESS_DENIED);
    }
    
    // User has required role, proceed
    logger.debug('RBAC check passed', {
      userId: req.user.userId,
      role: userRole,
      path: req.path
    });
    
    next();
  };
};

/**
 * Middleware that requires ADMIN role
 * Convenience wrapper around requireRoles
 */
const requireAdmin = requireRoles(ROLES.ADMIN);

/**
 * Middleware that requires at least USER role
 * Effectively just ensures user is authenticated with a valid role
 */
const requireUser = requireRoles(ROLES.USER, ROLES.ADMIN);

/**
 * Middleware to check if user is accessing their own resource
 * Admins can access any resource
 * 
 * @param {Function} getResourceUserId - Function to extract resource owner ID from request
 * @returns {Function} Express middleware function
 * 
 * @example
 * // Check if user is accessing their own profile
 * router.get('/users/:id', authenticate, requireOwnerOrAdmin(req => req.params.id), getProfile);
 */
const requireOwnerOrAdmin = (getResourceUserId) => {
  return (req, res, next) => {
    if (!req.user) {
      return sendUnauthorized(res, ERROR_MESSAGES.AUTHENTICATION_REQUIRED);
    }
    
    // Admins can access anything
    if (req.user.role === ROLES.ADMIN) {
      return next();
    }
    
    // Check if user owns the resource
    const resourceUserId = getResourceUserId(req);
    
    if (req.user.userId !== resourceUserId) {
      logger.warn('Resource ownership check failed', {
        userId: req.user.userId,
        resourceOwnerId: resourceUserId,
        path: req.path
      });
      
      return sendForbidden(res, ERROR_MESSAGES.ACCESS_DENIED);
    }
    
    next();
  };
};

module.exports = {
  requireRoles,
  requireAdmin,
  requireUser,
  requireOwnerOrAdmin,
  ROLES
};
