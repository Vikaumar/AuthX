/**
 * Token Service
 * Handles refresh token storage, validation, rotation, and revocation
 */

const { v4: uuidv4 } = require('uuid');
const db = require('../config/database');
const jwtUtil = require('../utils/jwt.util');
const logger = require('../utils/logger.util');

/**
 * Create and store a new refresh token for a user
 * 
 * @param {string} userId - User's UUID
 * @param {string|null} familyId - Token family ID (null for new login, existing for rotation)
 * @returns {Promise<Object>} Object containing the refresh token and token record
 */
const createRefreshToken = async (userId, familyId = null) => {
  // Generate new token identifiers
  const tokenId = uuidv4();
  const newFamilyId = familyId || uuidv4(); // New family for fresh login
  const expiresAt = jwtUtil.getRefreshTokenExpiry();
  
  // Generate the JWT refresh token
  const refreshToken = jwtUtil.generateRefreshToken({
    userId,
    tokenId,
    familyId: newFamilyId
  });
  
  // Hash the token for secure storage
  const tokenHash = jwtUtil.hashToken(refreshToken);
  
  // Store in database
  const query = `
    INSERT INTO refresh_tokens (id, user_id, token_hash, expires_at, family_id)
    VALUES ($1, $2, $3, $4, $5)
    RETURNING id, user_id, expires_at, family_id, created_at
  `;
  
  const result = await db.query(query, [
    tokenId,
    userId,
    tokenHash,
    expiresAt,
    newFamilyId
  ]);
  
  logger.debug('Created refresh token', { userId, tokenId, familyId: newFamilyId });
  
  return {
    refreshToken,
    tokenRecord: result.rows[0]
  };
};

/**
 * Validate a refresh token and check if it's been revoked
 * Implements token reuse detection
 * 
 * @param {string} refreshToken - The refresh token to validate
 * @returns {Promise<Object>} Validation result with user data or error
 */
const validateRefreshToken = async (refreshToken) => {
  try {
    // First, verify the JWT signature and decode
    const decoded = jwtUtil.verifyRefreshToken(refreshToken);
    const tokenHash = jwtUtil.hashToken(refreshToken);
    
    // Look up the token in database
    const query = `
      SELECT 
        rt.id,
        rt.user_id,
        rt.token_hash,
        rt.expires_at,
        rt.is_revoked,
        rt.family_id,
        rt.created_at,
        u.email,
        u.role,
        u.is_active
      FROM refresh_tokens rt
      JOIN users u ON rt.user_id = u.id
      WHERE rt.token_hash = $1
    `;
    
    const result = await db.query(query, [tokenHash]);
    
    if (result.rows.length === 0) {
      logger.warn('Refresh token not found in database', { tokenId: decoded.tokenId });
      return { valid: false, error: 'Token not found' };
    }
    
    const tokenRecord = result.rows[0];
    
    // Check if token has been revoked - THIS IS TOKEN REUSE DETECTION
    if (tokenRecord.is_revoked) {
      logger.warn('TOKEN REUSE DETECTED! Revoking entire token family', {
        userId: tokenRecord.user_id,
        familyId: tokenRecord.family_id
      });
      
      // Revoke ALL tokens in this family - security measure
      await revokeTokenFamily(tokenRecord.family_id);
      
      return { 
        valid: false, 
        error: 'Token reuse detected',
        securityBreach: true 
      };
    }
    
    // Check if token has expired
    if (new Date(tokenRecord.expires_at) < new Date()) {
      logger.debug('Refresh token expired', { tokenId: tokenRecord.id });
      return { valid: false, error: 'Token expired' };
    }
    
    // Check if user is still active
    if (!tokenRecord.is_active) {
      logger.debug('User account is inactive', { userId: tokenRecord.user_id });
      return { valid: false, error: 'User account inactive' };
    }
    
    return {
      valid: true,
      tokenRecord,
      user: {
        id: tokenRecord.user_id,
        email: tokenRecord.email,
        role: tokenRecord.role
      }
    };
    
  } catch (error) {
    logger.error('Token validation error:', error);
    return { valid: false, error: error.message };
  }
};

/**
 * Rotate a refresh token - revoke old, issue new
 * This is called after successful token validation during refresh
 * 
 * @param {string} oldTokenHash - Hash of the token being rotated
 * @param {string} userId - User's UUID
 * @param {string} familyId - Token family ID to maintain chain
 * @returns {Promise<Object>} New refresh token
 */
const rotateRefreshToken = async (oldTokenHash, userId, familyId) => {
  const client = await db.getClient();
  
  try {
    await client.query('BEGIN');
    
    // Revoke the old token
    await client.query(`
      UPDATE refresh_tokens 
      SET is_revoked = TRUE, revoked_at = CURRENT_TIMESTAMP
      WHERE token_hash = $1 AND is_revoked = FALSE
    `, [oldTokenHash]);
    
    // Create new token in the same family
    const tokenId = uuidv4();
    const expiresAt = jwtUtil.getRefreshTokenExpiry();
    
    const refreshToken = jwtUtil.generateRefreshToken({
      userId,
      tokenId,
      familyId
    });
    
    const newTokenHash = jwtUtil.hashToken(refreshToken);
    
    await client.query(`
      INSERT INTO refresh_tokens (id, user_id, token_hash, expires_at, family_id)
      VALUES ($1, $2, $3, $4, $5)
    `, [tokenId, userId, newTokenHash, expiresAt, familyId]);
    
    await client.query('COMMIT');
    
    logger.debug('Rotated refresh token', { userId, familyId, newTokenId: tokenId });
    
    return { refreshToken };
    
  } catch (error) {
    await client.query('ROLLBACK');
    logger.error('Token rotation failed:', error);
    throw error;
  } finally {
    client.release();
  }
};

/**
 * Revoke a specific refresh token
 * 
 * @param {string} tokenHash - Hash of token to revoke
 * @returns {Promise<boolean>} True if token was revoked
 */
const revokeToken = async (tokenHash) => {
  const query = `
    UPDATE refresh_tokens 
    SET is_revoked = TRUE, revoked_at = CURRENT_TIMESTAMP
    WHERE token_hash = $1 AND is_revoked = FALSE
    RETURNING id
  `;
  
  const result = await db.query(query, [tokenHash]);
  
  if (result.rows.length > 0) {
    logger.debug('Revoked token', { tokenId: result.rows[0].id });
    return true;
  }
  
  return false;
};

/**
 * Revoke all tokens in a family (for reuse detection response)
 * 
 * @param {string} familyId - Token family to revoke
 * @returns {Promise<number>} Number of tokens revoked
 */
const revokeTokenFamily = async (familyId) => {
  const query = `
    UPDATE refresh_tokens 
    SET is_revoked = TRUE, revoked_at = CURRENT_TIMESTAMP
    WHERE family_id = $1 AND is_revoked = FALSE
    RETURNING id
  `;
  
  const result = await db.query(query, [familyId]);
  
  logger.warn('Revoked token family', { 
    familyId, 
    tokensRevoked: result.rows.length 
  });
  
  return result.rows.length;
};

/**
 * Revoke all tokens for a user (logout from all devices)
 * 
 * @param {string} userId - User's UUID
 * @returns {Promise<number>} Number of tokens revoked
 */
const revokeAllUserTokens = async (userId) => {
  const query = `
    UPDATE refresh_tokens 
    SET is_revoked = TRUE, revoked_at = CURRENT_TIMESTAMP
    WHERE user_id = $1 AND is_revoked = FALSE
    RETURNING id
  `;
  
  const result = await db.query(query, [userId]);
  
  logger.info('Revoked all user tokens', { 
    userId, 
    tokensRevoked: result.rows.length 
  });
  
  return result.rows.length;
};

/**
 * Get active token count for a user
 * 
 * @param {string} userId - User's UUID
 * @returns {Promise<number>} Count of active tokens
 */
const getActiveTokenCount = async (userId) => {
  const query = `
    SELECT COUNT(*) as count 
    FROM refresh_tokens 
    WHERE user_id = $1 
      AND is_revoked = FALSE 
      AND expires_at > CURRENT_TIMESTAMP
  `;
  
  const result = await db.query(query, [userId]);
  return parseInt(result.rows[0].count, 10);
};

module.exports = {
  createRefreshToken,
  validateRefreshToken,
  rotateRefreshToken,
  revokeToken,
  revokeTokenFamily,
  revokeAllUserTokens,
  getActiveTokenCount
};
