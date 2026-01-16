/**
 * Protected Routes
 * Example routes demonstrating authentication and RBAC
 */

const express = require('express');
const router = express.Router();

// Middleware
const { authenticate } = require('../middleware/auth.middleware');
const { requireAdmin, requireUser, requireOwnerOrAdmin } = require('../middleware/rbac.middleware');
const { apiRateLimiter } = require('../middleware/rateLimiter.middleware');
const { sendSuccess } = require('../utils/response.util');
const { ROLES } = require('../config/constants');

// Apply rate limiting to all protected routes
router.use(apiRateLimiter);

// ============================================
// User Routes (Requires USER or ADMIN role)
// ============================================

/**
 * GET /protected/profile
 * Access user's own profile
 * 
 * Requires: Authentication + (USER or ADMIN role)
 */
router.get(
  '/profile',
  authenticate,
  requireUser,
  (req, res) => {
    sendSuccess(res, {
      message: 'Profile accessed successfully',
      data: {
        message: 'This is a protected route accessible by authenticated users',
        user: {
          id: req.user.userId,
          email: req.user.email,
          role: req.user.role
        },
        accessedAt: new Date().toISOString()
      }
    });
  }
);

/**
 * GET /protected/dashboard
 * Access user dashboard
 * 
 * Requires: Authentication + (USER or ADMIN role)
 */
router.get(
  '/dashboard',
  authenticate,
  requireUser,
  (req, res) => {
    sendSuccess(res, {
      message: 'Dashboard data retrieved',
      data: {
        message: 'Welcome to your dashboard!',
        user: req.user,
        stats: {
          // Example dashboard data
          lastLogin: new Date().toISOString(),
          accountType: req.user.role === ROLES.ADMIN ? 'Administrator' : 'Standard User'
        }
      }
    });
  }
);

// ============================================
// Admin Routes (Requires ADMIN role only)
// ============================================

/**
 * GET /protected/admin
 * Access admin-only content
 * 
 * Requires: Authentication + ADMIN role
 */
router.get(
  '/admin',
  authenticate,
  requireAdmin,
  (req, res) => {
    sendSuccess(res, {
      message: 'Admin area accessed',
      data: {
        message: 'This is an admin-only protected route',
        adminInfo: {
          userId: req.user.userId,
          email: req.user.email,
          role: req.user.role,
          permissions: ['read', 'write', 'delete', 'manage_users']
        }
      }
    });
  }
);

/**
 * GET /protected/admin/users
 * List all users (admin only)
 * 
 * Requires: Authentication + ADMIN role
 */
router.get(
  '/admin/users',
  authenticate,
  requireAdmin,
  async (req, res) => {
    // This is an example - in production, you'd query the database
    sendSuccess(res, {
      message: 'User list retrieved',
      data: {
        message: 'Admin can see all users here',
        note: 'In production, this would return actual user data from the database',
        requestedBy: {
          userId: req.user.userId,
          role: req.user.role
        }
      }
    });
  }
);

/**
 * GET /protected/admin/stats
 * Get system statistics (admin only)
 * 
 * Requires: Authentication + ADMIN role
 */
router.get(
  '/admin/stats',
  authenticate,
  requireAdmin,
  (req, res) => {
    sendSuccess(res, {
      message: 'System statistics retrieved',
      data: {
        serverTime: new Date().toISOString(),
        uptime: process.uptime(),
        memoryUsage: process.memoryUsage(),
        nodeVersion: process.version
      }
    });
  }
);

// ============================================
// Resource Owner Routes
// Example of checking resource ownership
// ============================================

/**
 * GET /protected/users/:userId/settings
 * Access user settings (owner or admin only)
 * 
 * Requires: Authentication + (be the owner OR ADMIN role)
 */
router.get(
  '/users/:userId/settings',
  authenticate,
  requireOwnerOrAdmin((req) => req.params.userId),
  (req, res) => {
    sendSuccess(res, {
      message: 'User settings retrieved',
      data: {
        message: 'You can only access your own settings (unless admin)',
        targetUserId: req.params.userId,
        requestedBy: req.user.userId,
        isOwner: req.params.userId === req.user.userId,
        isAdmin: req.user.role === ROLES.ADMIN
      }
    });
  }
);

module.exports = router;
