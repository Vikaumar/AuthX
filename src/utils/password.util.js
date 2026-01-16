/**
 * Password Utility
 * Handles secure password hashing and verification using bcrypt
 */

const bcrypt = require('bcrypt');
const logger = require('./logger.util');

// Get salt rounds from environment or use secure default
const SALT_ROUNDS = parseInt(process.env.BCRYPT_SALT_ROUNDS, 10) || 12;

/**
 * Hash a plain text password
 * Uses bcrypt with configurable salt rounds for security
 * 
 * @param {string} plainPassword - Plain text password to hash
 * @returns {Promise<string>} Hashed password
 * @throws {Error} If hashing fails
 */
const hashPassword = async (plainPassword) => {
  try {
    const hashedPassword = await bcrypt.hash(plainPassword, SALT_ROUNDS);
    return hashedPassword;
  } catch (error) {
    logger.error('Password hashing failed:', error);
    throw new Error('Password hashing failed');
  }
};

/**
 * Compare plain text password with hashed password
 * Uses timing-safe comparison to prevent timing attacks
 * 
 * @param {string} plainPassword - Plain text password to verify
 * @param {string} hashedPassword - Stored hashed password
 * @returns {Promise<boolean>} True if passwords match
 */
const comparePassword = async (plainPassword, hashedPassword) => {
  try {
    const isMatch = await bcrypt.compare(plainPassword, hashedPassword);
    return isMatch;
  } catch (error) {
    logger.error('Password comparison failed:', error);
    return false;
  }
};

/**
 * Validate password strength
 * Enforces minimum security requirements
 * 
 * @param {string} password - Password to validate
 * @returns {Object} Validation result with isValid and errors array
 */
const validatePasswordStrength = (password) => {
  const errors = [];
  
  if (!password || password.length < 8) {
    errors.push('Password must be at least 8 characters long');
  }
  
  if (!/[A-Z]/.test(password)) {
    errors.push('Password must contain at least one uppercase letter');
  }
  
  if (!/[a-z]/.test(password)) {
    errors.push('Password must contain at least one lowercase letter');
  }
  
  if (!/[0-9]/.test(password)) {
    errors.push('Password must contain at least one number');
  }
  
  if (!/[!@#$%^&*(),.?":{}|<>]/.test(password)) {
    errors.push('Password must contain at least one special character');
  }
  
  return {
    isValid: errors.length === 0,
    errors
  };
};

module.exports = {
  hashPassword,
  comparePassword,
  validatePasswordStrength
};
