/**
 * Authentication Routes
 * Defines all authentication-related endpoints
 */

const express = require('express');
const router = express.Router();

// Controller
const authController = require('../controllers/auth.controller');

// Middleware
const { authenticate } = require('../middleware/auth.middleware');
const { 
  registerValidation, 
  loginValidation, 
  refreshValidation,
  logoutValidation 
} = require('../middleware/validator.middleware');
const { 
  loginRateLimiter, 
  refreshRateLimiter, 
  registerRateLimiter,
  createBruteForceProtection 
} = require('../middleware/rateLimiter.middleware');

// Brute force protection for login
const loginBruteForce = createBruteForceProtection({
  keyPrefix: 'bf:login'
});

// ============================================
// Public Routes (No authentication required)
// ============================================

/**
 * POST /auth/register
 * Register a new user account
 * 
 * Rate limited: 3 registrations per hour per IP
 * 
 * Request body:
 * {
 *   "email": "user@example.com",
 *   "password": "SecurePass123!"
 * }
 * 
 * Response:
 * {
 *   "success": true,
 *   "message": "User registered successfully",
 *   "data": {
 *     "user": { "id", "email", "role", "createdAt" },
 *     "accessToken": "eyJ...",
 *     "refreshToken": "eyJ...",
 *     "tokenType": "Bearer"
 *   }
 * }
 */
router.post(
  '/register',
  registerRateLimiter,
  registerValidation,
  authController.register
);

/**
 * POST /auth/login
 * Authenticate and receive tokens
 * 
 * Rate limited: 5 attempts per 15 minutes per IP+email
 * Brute force protection: Progressive delays after failures
 * 
 * Request body:
 * {
 *   "email": "user@example.com",
 *   "password": "SecurePass123!"
 * }
 * 
 * Response:
 * {
 *   "success": true,
 *   "message": "Login successful",
 *   "data": {
 *     "user": { "id", "email", "role" },
 *     "accessToken": "eyJ...",
 *     "refreshToken": "eyJ...",
 *     "tokenType": "Bearer"
 *   }
 * }
 */
router.post(
  '/login',
  loginBruteForce,
  loginRateLimiter,
  loginValidation,
  authController.login
);

/**
 * POST /auth/refresh
 * Exchange refresh token for new token pair
 * 
 * Rate limited: 10 attempts per 15 minutes per IP
 * 
 * Security: Token rotation is performed - old token is revoked
 * Security: Reuse of revoked token invalidates ALL user sessions
 * 
 * Request body:
 * {
 *   "refreshToken": "eyJ..."
 * }
 * 
 * Response:
 * {
 *   "success": true,
 *   "message": "Token refreshed successfully",
 *   "data": {
 *     "accessToken": "eyJ...",
 *     "refreshToken": "eyJ...",
 *     "tokenType": "Bearer"
 *   }
 * }
 */
router.post(
  '/refresh',
  refreshRateLimiter,
  refreshValidation,
  authController.refresh
);

// ============================================
// Protected Routes (Authentication required)
// ============================================

/**
 * POST /auth/logout
 * Revoke refresh token(s)
 * 
 * Can be called with or without authentication:
 * - With refreshToken in body: Revokes that specific token
 * - With allDevices: true + auth: Revokes ALL user's tokens
 * 
 * Request body:
 * {
 *   "refreshToken": "eyJ...",     // Optional if allDevices is true
 *   "allDevices": false           // Optional, requires authentication
 * }
 */
router.post(
  '/logout',
  authenticate,
  logoutValidation,
  authController.logout
);

/**
 * GET /auth/me
 * Get current user's profile
 * 
 * Requires: Valid access token
 * 
 * Response:
 * {
 *   "success": true,
 *   "message": "User retrieved successfully",
 *   "data": {
 *     "user": {
 *       "id": "uuid",
 *       "email": "user@example.com",
 *       "role": "USER",
 *       "isActive": true,
 *       "createdAt": "timestamp",
 *       "updatedAt": "timestamp"
 *     }
 *   }
 * }
 */
router.get(
  '/me',
  authenticate,
  authController.getMe
);

module.exports = router;
