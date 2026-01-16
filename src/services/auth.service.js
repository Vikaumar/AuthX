/**
 * Authentication Service
 * Business logic for user registration, login, token refresh, and logout
 */

const db = require('../config/database');
const tokenService = require('./token.service');
const passwordUtil = require('../utils/password.util');
const jwtUtil = require('../utils/jwt.util');
const logger = require('../utils/logger.util');
const { ROLES, ERROR_MESSAGES } = require('../config/constants');

/**
 * Register a new user
 * 
 * @param {Object} userData - User registration data
 * @param {string} userData.email - User's email address
 * @param {string} userData.password - User's password (plain text)
 * @param {string} [userData.role='USER'] - User's role
 * @returns {Promise<Object>} Created user (without password) and tokens
 */
const register = async ({ email, password, role = ROLES.USER }) => {
  // Check if user already exists
  const existingUser = await db.query(
    'SELECT id FROM users WHERE email = $1',
    [email.toLowerCase()]
  );
  
  if (existingUser.rows.length > 0) {
    const error = new Error(ERROR_MESSAGES.USER_EXISTS);
    error.code = 'USER_EXISTS';
    throw error;
  }
  
  // Validate password strength
  const passwordValidation = passwordUtil.validatePasswordStrength(password);
  if (!passwordValidation.isValid) {
    const error = new Error('Password does not meet requirements');
    error.code = 'WEAK_PASSWORD';
    error.details = passwordValidation.errors;
    throw error;
  }
  
  // Hash the password
  const passwordHash = await passwordUtil.hashPassword(password);
  
  // Insert new user
  const insertQuery = `
    INSERT INTO users (email, password_hash, role)
    VALUES ($1, $2, $3)
    RETURNING id, email, role, is_active, created_at
  `;
  
  const result = await db.query(insertQuery, [
    email.toLowerCase(),
    passwordHash,
    role
  ]);
  
  const user = result.rows[0];
  
  logger.info('New user registered', { userId: user.id, email: user.email });
  
  // Generate tokens for immediate login
  const accessToken = jwtUtil.generateAccessToken({
    userId: user.id,
    email: user.email,
    role: user.role
  });
  
  const { refreshToken } = await tokenService.createRefreshToken(user.id);
  
  return {
    user: {
      id: user.id,
      email: user.email,
      role: user.role,
      createdAt: user.created_at
    },
    accessToken,
    refreshToken
  };
};

/**
 * Authenticate a user and issue tokens
 * 
 * @param {Object} credentials - Login credentials
 * @param {string} credentials.email - User's email
 * @param {string} credentials.password - User's password
 * @returns {Promise<Object>} User data and tokens
 */
const login = async ({ email, password }) => {
  // Find user by email
  const query = `
    SELECT id, email, password_hash, role, is_active, created_at
    FROM users
    WHERE email = $1
  `;
  
  const result = await db.query(query, [email.toLowerCase()]);
  
  if (result.rows.length === 0) {
    // Use generic message to prevent email enumeration
    const error = new Error(ERROR_MESSAGES.INVALID_CREDENTIALS);
    error.code = 'INVALID_CREDENTIALS';
    throw error;
  }
  
  const user = result.rows[0];
  
  // Check if account is active
  if (!user.is_active) {
    const error = new Error(ERROR_MESSAGES.USER_INACTIVE);
    error.code = 'USER_INACTIVE';
    throw error;
  }
  
  // Verify password
  const isPasswordValid = await passwordUtil.comparePassword(
    password,
    user.password_hash
  );
  
  if (!isPasswordValid) {
    logger.warn('Failed login attempt', { email: user.email });
    const error = new Error(ERROR_MESSAGES.INVALID_CREDENTIALS);
    error.code = 'INVALID_CREDENTIALS';
    throw error;
  }
  
  // Generate tokens
  const accessToken = jwtUtil.generateAccessToken({
    userId: user.id,
    email: user.email,
    role: user.role
  });
  
  // Create new refresh token (new family since it's a fresh login)
  const { refreshToken } = await tokenService.createRefreshToken(user.id);
  
  logger.info('User logged in', { userId: user.id, email: user.email });
  
  return {
    user: {
      id: user.id,
      email: user.email,
      role: user.role
    },
    accessToken,
    refreshToken
  };
};

/**
 * Refresh access token using a valid refresh token
 * Implements token rotation - old token is revoked, new one issued
 * 
 * @param {string} refreshToken - Current refresh token
 * @returns {Promise<Object>} New access and refresh tokens
 */
const refreshTokens = async (refreshToken) => {
  // Validate the refresh token
  const validation = await tokenService.validateRefreshToken(refreshToken);
  
  if (!validation.valid) {
    const error = new Error(
      validation.securityBreach 
        ? ERROR_MESSAGES.TOKEN_REUSE_DETECTED 
        : ERROR_MESSAGES.TOKEN_INVALID
    );
    error.code = validation.securityBreach ? 'TOKEN_REUSE' : 'INVALID_TOKEN';
    error.securityBreach = validation.securityBreach || false;
    throw error;
  }
  
  const { user, tokenRecord } = validation;
  const oldTokenHash = jwtUtil.hashToken(refreshToken);
  
  // Rotate the refresh token (revoke old, issue new in same family)
  const { refreshToken: newRefreshToken } = await tokenService.rotateRefreshToken(
    oldTokenHash,
    user.id,
    tokenRecord.family_id
  );
  
  // Generate new access token
  const accessToken = jwtUtil.generateAccessToken({
    userId: user.id,
    email: user.email,
    role: user.role
  });
  
  logger.debug('Tokens refreshed', { userId: user.id });
  
  return {
    accessToken,
    refreshToken: newRefreshToken
  };
};

/**
 * Logout a user by revoking their refresh token
 * 
 * @param {string} refreshToken - Refresh token to revoke
 * @param {boolean} [allDevices=false] - If true, revoke all user's tokens
 * @param {string} [userId] - User ID (required if allDevices is true)
 * @returns {Promise<boolean>} True if logout successful
 */
const logout = async (refreshToken, allDevices = false, userId = null) => {
  if (allDevices && userId) {
    // Logout from all devices
    const revokedCount = await tokenService.revokeAllUserTokens(userId);
    logger.info('User logged out from all devices', { userId, revokedCount });
    return true;
  }
  
  // Logout from current device only
  const tokenHash = jwtUtil.hashToken(refreshToken);
  const revoked = await tokenService.revokeToken(tokenHash);
  
  if (revoked) {
    logger.debug('User logged out', { tokenHash: tokenHash.substring(0, 10) + '...' });
  }
  
  return revoked;
};

/**
 * Get user by ID
 * 
 * @param {string} userId - User's UUID
 * @returns {Promise<Object|null>} User data or null
 */
const getUserById = async (userId) => {
  const query = `
    SELECT id, email, role, is_active, created_at, updated_at
    FROM users
    WHERE id = $1
  `;
  
  const result = await db.query(query, [userId]);
  
  if (result.rows.length === 0) {
    return null;
  }
  
  return result.rows[0];
};

/**
 * Update user's role (admin function)
 * 
 * @param {string} userId - User's UUID
 * @param {string} newRole - New role to assign
 * @returns {Promise<Object>} Updated user
 */
const updateUserRole = async (userId, newRole) => {
  if (!Object.values(ROLES).includes(newRole)) {
    const error = new Error('Invalid role');
    error.code = 'INVALID_ROLE';
    throw error;
  }
  
  const query = `
    UPDATE users 
    SET role = $1
    WHERE id = $2
    RETURNING id, email, role, updated_at
  `;
  
  const result = await db.query(query, [newRole, userId]);
  
  if (result.rows.length === 0) {
    const error = new Error(ERROR_MESSAGES.USER_NOT_FOUND);
    error.code = 'USER_NOT_FOUND';
    throw error;
  }
  
  logger.info('User role updated', { userId, newRole });
  
  return result.rows[0];
};

module.exports = {
  register,
  login,
  refreshTokens,
  logout,
  getUserById,
  updateUserRole
};
