/**
 * JWT Utility
 * Handles JWT token generation and verification for access and refresh tokens
 */

const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const logger = require('./logger.util');
const { TOKEN_TYPES } = require('../config/constants');

// Token configuration from environment
const ACCESS_TOKEN_SECRET = process.env.ACCESS_TOKEN_SECRET || 'default_access_secret_change_me';
const REFRESH_TOKEN_SECRET = process.env.REFRESH_TOKEN_SECRET || 'default_refresh_secret_change_me';
const ACCESS_TOKEN_EXPIRY = process.env.ACCESS_TOKEN_EXPIRY || '15m';
const REFRESH_TOKEN_EXPIRY_DAYS = parseInt(process.env.REFRESH_TOKEN_EXPIRY_DAYS, 10) || 7;

/**
 * Generate an access token for a user
 * Short-lived token for API authentication
 * 
 * @param {Object} payload - Data to include in token
 * @param {string} payload.userId - User's unique identifier
 * @param {string} payload.email - User's email
 * @param {string} payload.role - User's role (USER, ADMIN)
 * @returns {string} Signed JWT access token
 */
const generateAccessToken = (payload) => {
  const tokenPayload = {
    userId: payload.userId,
    email: payload.email,
    role: payload.role,
    type: TOKEN_TYPES.ACCESS
  };
  
  return jwt.sign(tokenPayload, ACCESS_TOKEN_SECRET, {
    expiresIn: ACCESS_TOKEN_EXPIRY,
    algorithm: 'HS256'
  });
};

/**
 * Generate a refresh token for a user
 * Long-lived token for obtaining new access tokens
 * 
 * @param {Object} payload - Data to include in token
 * @param {string} payload.userId - User's unique identifier
 * @param {string} payload.tokenId - Unique token identifier (for tracking)
 * @param {string} payload.familyId - Token family ID (for rotation tracking)
 * @returns {string} Signed JWT refresh token
 */
const generateRefreshToken = (payload) => {
  const tokenPayload = {
    userId: payload.userId,
    tokenId: payload.tokenId,
    familyId: payload.familyId,
    type: TOKEN_TYPES.REFRESH
  };
  
  return jwt.sign(tokenPayload, REFRESH_TOKEN_SECRET, {
    expiresIn: `${REFRESH_TOKEN_EXPIRY_DAYS}d`,
    algorithm: 'HS256'
  });
};

/**
 * Verify an access token
 * 
 * @param {string} token - JWT access token to verify
 * @returns {Object} Decoded token payload if valid
 * @throws {Error} If token is invalid or expired
 */
const verifyAccessToken = (token) => {
  try {
    const decoded = jwt.verify(token, ACCESS_TOKEN_SECRET);
    
    // Ensure it's an access token
    if (decoded.type !== TOKEN_TYPES.ACCESS) {
      throw new Error('Invalid token type');
    }
    
    return decoded;
  } catch (error) {
    if (error.name === 'TokenExpiredError') {
      throw new Error('Access token expired');
    }
    if (error.name === 'JsonWebTokenError') {
      throw new Error('Invalid access token');
    }
    throw error;
  }
};

/**
 * Verify a refresh token
 * 
 * @param {string} token - JWT refresh token to verify
 * @returns {Object} Decoded token payload if valid
 * @throws {Error} If token is invalid or expired
 */
const verifyRefreshToken = (token) => {
  try {
    const decoded = jwt.verify(token, REFRESH_TOKEN_SECRET);
    
    // Ensure it's a refresh token
    if (decoded.type !== TOKEN_TYPES.REFRESH) {
      throw new Error('Invalid token type');
    }
    
    return decoded;
  } catch (error) {
    if (error.name === 'TokenExpiredError') {
      throw new Error('Refresh token expired');
    }
    if (error.name === 'JsonWebTokenError') {
      throw new Error('Invalid refresh token');
    }
    throw error;
  }
};

/**
 * Hash a token for secure storage
 * Uses SHA-256 for consistent, one-way hashing
 * 
 * @param {string} token - Token to hash
 * @returns {string} Hashed token (hex encoded)
 */
const hashToken = (token) => {
  return crypto.createHash('sha256').update(token).digest('hex');
};

/**
 * Generate a unique token ID
 * 
 * @returns {string} UUID v4
 */
const generateTokenId = () => {
  return crypto.randomUUID();
};

/**
 * Calculate refresh token expiry date
 * 
 * @returns {Date} Expiry date
 */
const getRefreshTokenExpiry = () => {
  const expiry = new Date();
  expiry.setDate(expiry.getDate() + REFRESH_TOKEN_EXPIRY_DAYS);
  return expiry;
};

module.exports = {
  generateAccessToken,
  generateRefreshToken,
  verifyAccessToken,
  verifyRefreshToken,
  hashToken,
  generateTokenId,
  getRefreshTokenExpiry,
  ACCESS_TOKEN_EXPIRY,
  REFRESH_TOKEN_EXPIRY_DAYS
};
