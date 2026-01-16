/**
 * Request Validation Middleware
 * Uses express-validator for input validation
 */

const { body, validationResult } = require('express-validator');
const { sendValidationError } = require('../utils/response.util');

/**
 * Middleware to check validation results
 * Use after validation chains
 */
const validate = (req, res, next) => {
  const errors = validationResult(req);
  
  if (!errors.isEmpty()) {
    return sendValidationError(res, errors.array());
  }
  
  next();
};

/**
 * Validation rules for user registration
 */
const registerValidation = [
  body('email')
    .trim()
    .notEmpty()
    .withMessage('Email is required')
    .isEmail()
    .withMessage('Please provide a valid email address')
    .normalizeEmail()
    .isLength({ max: 255 })
    .withMessage('Email must not exceed 255 characters'),
  
  body('password')
    .notEmpty()
    .withMessage('Password is required')
    .isLength({ min: 8 })
    .withMessage('Password must be at least 8 characters long')
    .isLength({ max: 128 })
    .withMessage('Password must not exceed 128 characters')
    .matches(/[A-Z]/)
    .withMessage('Password must contain at least one uppercase letter')
    .matches(/[a-z]/)
    .withMessage('Password must contain at least one lowercase letter')
    .matches(/[0-9]/)
    .withMessage('Password must contain at least one number')
    .matches(/[!@#$%^&*(),.?":{}|<>]/)
    .withMessage('Password must contain at least one special character'),
  
  validate
];

/**
 * Validation rules for user login
 */
const loginValidation = [
  body('email')
    .trim()
    .notEmpty()
    .withMessage('Email is required')
    .isEmail()
    .withMessage('Please provide a valid email address')
    .normalizeEmail(),
  
  body('password')
    .notEmpty()
    .withMessage('Password is required'),
  
  validate
];

/**
 * Validation rules for token refresh
 */
const refreshValidation = [
  body('refreshToken')
    .notEmpty()
    .withMessage('Refresh token is required')
    .isString()
    .withMessage('Refresh token must be a string'),
  
  validate
];

/**
 * Validation rules for logout
 */
const logoutValidation = [
  body('refreshToken')
    .optional()
    .isString()
    .withMessage('Refresh token must be a string'),
  
  body('allDevices')
    .optional()
    .isBoolean()
    .withMessage('allDevices must be a boolean'),
  
  validate
];

/**
 * Custom validation: UUID format
 */
const isUUID = (value) => {
  const uuidRegex = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
  return uuidRegex.test(value);
};

/**
 * Validation for UUID parameters
 */
const uuidParamValidation = (paramName) => [
  body(paramName)
    .custom((value) => {
      if (!isUUID(value)) {
        throw new Error(`${paramName} must be a valid UUID`);
      }
      return true;
    }),
  
  validate
];

module.exports = {
  validate,
  registerValidation,
  loginValidation,
  refreshValidation,
  logoutValidation,
  uuidParamValidation,
  isUUID
};
