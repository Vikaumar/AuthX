/**
 * Authentication Controller
 * Handles HTTP requests for authentication endpoints
 */

const authService = require('../services/auth.service');
const { sendSuccess, sendError } = require('../utils/response.util');
const { HTTP_STATUS, SUCCESS_MESSAGES, ERROR_MESSAGES } = require('../config/constants');
const { asyncHandler } = require('../middleware/errorHandler.middleware');
const { recordFailedAttempt, resetFailedAttempts } = require('../middleware/rateLimiter.middleware');
const logger = require('../utils/logger.util');

/**
 * POST /auth/register
 * Register a new user account
 */
const register = asyncHandler(async (req, res) => {
  const { email, password } = req.body;
  
  try {
    const result = await authService.register({ email, password });
    
    sendSuccess(res, {
      statusCode: HTTP_STATUS.CREATED,
      message: SUCCESS_MESSAGES.REGISTERED,
      data: {
        user: result.user,
        accessToken: result.accessToken,
        refreshToken: result.refreshToken,
        tokenType: 'Bearer'
      }
    });
    
  } catch (error) {
    // Handle specific errors
    if (error.code === 'USER_EXISTS') {
      return sendError(res, {
        statusCode: HTTP_STATUS.CONFLICT,
        message: error.message,
        code: error.code
      });
    }
    
    if (error.code === 'WEAK_PASSWORD') {
      return sendError(res, {
        statusCode: HTTP_STATUS.BAD_REQUEST,
        message: error.message,
        code: error.code,
        errors: error.details
      });
    }
    
    throw error;
  }
});

/**
 * POST /auth/login
 * Authenticate user and issue tokens
 */
const login = asyncHandler(async (req, res) => {
  const { email, password } = req.body;
  const clientIp = req.ip;
  
  try {
    const result = await authService.login({ email, password });
    
    // Reset failed attempts on successful login
    await resetFailedAttempts(clientIp);
    
    sendSuccess(res, {
      statusCode: HTTP_STATUS.OK,
      message: SUCCESS_MESSAGES.LOGGED_IN,
      data: {
        user: result.user,
        accessToken: result.accessToken,
        refreshToken: result.refreshToken,
        tokenType: 'Bearer'
      }
    });
    
  } catch (error) {
    // Record failed attempt for brute force protection
    if (error.code === 'INVALID_CREDENTIALS') {
      await recordFailedAttempt(clientIp);
    }
    
    // Handle specific errors
    if (error.code === 'INVALID_CREDENTIALS' || error.code === 'USER_INACTIVE') {
      return sendError(res, {
        statusCode: HTTP_STATUS.UNAUTHORIZED,
        message: error.message,
        code: error.code
      });
    }
    
    throw error;
  }
});

/**
 * POST /auth/refresh
 * Refresh access token using refresh token
 */
const refresh = asyncHandler(async (req, res) => {
  const { refreshToken } = req.body;
  
  if (!refreshToken) {
    return sendError(res, {
      statusCode: HTTP_STATUS.BAD_REQUEST,
      message: ERROR_MESSAGES.REFRESH_TOKEN_REQUIRED,
      code: 'MISSING_TOKEN'
    });
  }
  
  try {
    const result = await authService.refreshTokens(refreshToken);
    
    sendSuccess(res, {
      statusCode: HTTP_STATUS.OK,
      message: SUCCESS_MESSAGES.TOKEN_REFRESHED,
      data: {
        accessToken: result.accessToken,
        refreshToken: result.refreshToken,
        tokenType: 'Bearer'
      }
    });
    
  } catch (error) {
    // Handle token reuse detection (security breach)
    if (error.securityBreach) {
      logger.warn('Security breach: Token reuse detected', {
        ip: req.ip,
        userAgent: req.headers['user-agent']
      });
      
      return sendError(res, {
        statusCode: HTTP_STATUS.UNAUTHORIZED,
        message: ERROR_MESSAGES.TOKEN_REUSE_DETECTED,
        code: 'TOKEN_REUSE'
      });
    }
    
    if (error.code === 'INVALID_TOKEN') {
      return sendError(res, {
        statusCode: HTTP_STATUS.UNAUTHORIZED,
        message: error.message,
        code: error.code
      });
    }
    
    throw error;
  }
});

/**
 * POST /auth/logout
 * Revoke refresh token(s)
 */
const logout = asyncHandler(async (req, res) => {
  const { refreshToken, allDevices } = req.body;
  
  // User info from JWT (if authenticated)
  const userId = req.user?.userId;
  
  // For logout from all devices, user must be authenticated
  if (allDevices && !userId) {
    return sendError(res, {
      statusCode: HTTP_STATUS.UNAUTHORIZED,
      message: 'Authentication required for logout from all devices',
      code: 'AUTH_REQUIRED'
    });
  }
  
  // For single device logout, need either refresh token or auth
  if (!allDevices && !refreshToken) {
    return sendError(res, {
      statusCode: HTTP_STATUS.BAD_REQUEST,
      message: 'Refresh token required for logout',
      code: 'MISSING_TOKEN'
    });
  }
  
  await authService.logout(refreshToken, allDevices, userId);
  
  sendSuccess(res, {
    statusCode: HTTP_STATUS.OK,
    message: SUCCESS_MESSAGES.LOGGED_OUT
  });
});

/**
 * GET /auth/me
 * Get current authenticated user info
 */
const getMe = asyncHandler(async (req, res) => {
  const userId = req.user.userId;
  
  const user = await authService.getUserById(userId);
  
  if (!user) {
    return sendError(res, {
      statusCode: HTTP_STATUS.NOT_FOUND,
      message: ERROR_MESSAGES.USER_NOT_FOUND,
      code: 'USER_NOT_FOUND'
    });
  }
  
  sendSuccess(res, {
    statusCode: HTTP_STATUS.OK,
    message: 'User retrieved successfully',
    data: {
      user: {
        id: user.id,
        email: user.email,
        role: user.role,
        isActive: user.is_active,
        createdAt: user.created_at,
        updatedAt: user.updated_at
      }
    }
  });
});

module.exports = {
  register,
  login,
  refresh,
  logout,
  getMe
};
