/**
 * Rate Limiter Middleware
 * Uses Redis to implement rate limiting with brute-force protection
 */

const { redisClient, isRedisReady } = require('../config/redis');
const { sendRateLimitExceeded } = require('../utils/response.util');
const logger = require('../utils/logger.util');

// Default configuration
const DEFAULT_WINDOW_MS = parseInt(process.env.RATE_LIMIT_WINDOW_MS, 10) || 15 * 60 * 1000; // 15 minutes
const DEFAULT_MAX_ATTEMPTS = parseInt(process.env.RATE_LIMIT_MAX_ATTEMPTS, 10) || 5;

/**
 * Create a rate limiter middleware with configurable options
 * 
 * @param {Object} options - Rate limiter options
 * @param {number} [options.windowMs=900000] - Time window in milliseconds
 * @param {number} [options.maxAttempts=5] - Maximum attempts in the window
 * @param {string} [options.keyPrefix='rl'] - Redis key prefix
 * @param {Function} [options.keyGenerator] - Custom key generator function
 * @param {boolean} [options.skipSuccessfulRequests=false] - Don't count successful requests
 * @returns {Function} Express middleware
 */
const createRateLimiter = (options = {}) => {
  const {
    windowMs = DEFAULT_WINDOW_MS,
    maxAttempts = DEFAULT_MAX_ATTEMPTS,
    keyPrefix = 'rl',
    keyGenerator = (req) => req.ip,
    skipSuccessfulRequests = false
  } = options;
  
  const windowSeconds = Math.ceil(windowMs / 1000);
  
  return async (req, res, next) => {
    // Skip rate limiting if Redis is not available
    if (!isRedisReady()) {
      logger.warn('Rate limiter bypassed: Redis not ready');
      return next();
    }
    
    try {
      // Generate unique key for this client
      const identifier = keyGenerator(req);
      const key = `${keyPrefix}:${identifier}`;
      
      // Get current count
      const current = await redisClient.get(key);
      const attempts = current ? parseInt(current, 10) : 0;
      
      // Check if limit exceeded
      if (attempts >= maxAttempts) {
        const ttl = await redisClient.ttl(key);
        
        logger.warn('Rate limit exceeded', { 
          identifier, 
          attempts, 
          ttlSeconds: ttl 
        });
        
        return sendRateLimitExceeded(res, ttl);
      }
      
      // Increment counter
      if (!skipSuccessfulRequests) {
        // Always increment before request
        await incrementCounter(key, windowSeconds);
      } else {
        // Store key for later incrementing on failure
        res.locals.rateLimitKey = key;
        res.locals.rateLimitWindow = windowSeconds;
      }
      
      // Add rate limit headers
      res.set({
        'X-RateLimit-Limit': String(maxAttempts),
        'X-RateLimit-Remaining': String(Math.max(0, maxAttempts - attempts - 1)),
        'X-RateLimit-Reset': String(Math.ceil(Date.now() / 1000) + windowSeconds)
      });
      
      next();
      
    } catch (error) {
      // On Redis error, allow the request but log the issue
      logger.error('Rate limiter error:', error);
      next();
    }
  };
};

/**
 * Increment the counter for a key
 * @param {string} key - Redis key
 * @param {number} expireSeconds - TTL in seconds
 */
const incrementCounter = async (key, expireSeconds) => {
  const multi = redisClient.multi();
  multi.incr(key);
  multi.expire(key, expireSeconds);
  await multi.exec();
};

/**
 * Mark a rate-limited request as failed (for skipSuccessfulRequests mode)
 * Call this in error handlers when authentication fails
 * 
 * @param {Object} res - Express response object
 */
const markRateLimitFailure = async (res) => {
  const { rateLimitKey, rateLimitWindow } = res.locals;
  
  if (rateLimitKey && isRedisReady()) {
    try {
      await incrementCounter(rateLimitKey, rateLimitWindow);
    } catch (error) {
      logger.error('Failed to mark rate limit failure:', error);
    }
  }
};

/**
 * Pre-configured rate limiter for login endpoint
 * More strict: 5 attempts per 15 minutes per IP
 */
const loginRateLimiter = createRateLimiter({
  windowMs: 15 * 60 * 1000, // 15 minutes
  maxAttempts: 5,
  keyPrefix: 'rl:login',
  keyGenerator: (req) => `${req.ip}:${req.body?.email || 'unknown'}`
});

/**
 * Pre-configured rate limiter for refresh endpoint
 * Moderate: 10 attempts per 15 minutes per IP
 */
const refreshRateLimiter = createRateLimiter({
  windowMs: 15 * 60 * 1000, // 15 minutes
  maxAttempts: 10,
  keyPrefix: 'rl:refresh'
});

/**
 * Pre-configured rate limiter for registration
 * Strict to prevent mass account creation: 3 per hour per IP
 */
const registerRateLimiter = createRateLimiter({
  windowMs: 60 * 60 * 1000, // 1 hour
  maxAttempts: 3,
  keyPrefix: 'rl:register'
});

/**
 * General API rate limiter
 * More permissive: 100 requests per 15 minutes
 */
const apiRateLimiter = createRateLimiter({
  windowMs: 15 * 60 * 1000,
  maxAttempts: 100,
  keyPrefix: 'rl:api'
});

/**
 * Brute force protection - progressive delays
 * After failed attempts, require increasingly longer waits
 * 
 * @param {Object} options - Options
 * @param {string} options.keyPrefix - Redis key prefix
 * @param {number[]} options.delays - Array of delays in seconds [after 1st fail, 2nd, 3rd, ...]
 */
const createBruteForceProtection = (options = {}) => {
  const {
    keyPrefix = 'bf',
    delays = [0, 0, 0, 30, 60, 120, 300, 600] // Delays after nth failure
  } = options;
  
  return async (req, res, next) => {
    if (!isRedisReady()) {
      return next();
    }
    
    try {
      const identifier = req.ip;
      const key = `${keyPrefix}:${identifier}`;
      
      // Get failure count
      const failCount = await redisClient.get(key);
      const failures = failCount ? parseInt(failCount, 10) : 0;
      
      if (failures > 0 && failures < delays.length) {
        const requiredDelay = delays[failures];
        const lastAttemptKey = `${key}:lastAttempt`;
        const lastAttempt = await redisClient.get(lastAttemptKey);
        
        if (lastAttempt) {
          const elapsed = (Date.now() - parseInt(lastAttempt, 10)) / 1000;
          
          if (elapsed < requiredDelay) {
            const waitTime = Math.ceil(requiredDelay - elapsed);
            
            logger.warn('Brute force protection: Request throttled', {
              identifier,
              failures,
              waitTime
            });
            
            res.set('Retry-After', String(waitTime));
            return sendRateLimitExceeded(res, waitTime);
          }
        }
      }
      
      // Store attempt time
      await redisClient.set(`${key}:lastAttempt`, Date.now().toString(), {
        EX: 3600 // 1 hour
      });
      
      next();
      
    } catch (error) {
      logger.error('Brute force protection error:', error);
      next();
    }
  };
};

/**
 * Record a failed authentication attempt for brute force tracking
 * 
 * @param {string} identifier - Client identifier (usually IP)
 * @param {string} [keyPrefix='bf'] - Redis key prefix
 */
const recordFailedAttempt = async (identifier, keyPrefix = 'bf') => {
  if (!isRedisReady()) return;
  
  try {
    const key = `${keyPrefix}:${identifier}`;
    const multi = redisClient.multi();
    multi.incr(key);
    multi.expire(key, 3600); // Reset after 1 hour of no failures
    await multi.exec();
  } catch (error) {
    logger.error('Failed to record failed attempt:', error);
  }
};

/**
 * Reset failed attempts after successful authentication
 * 
 * @param {string} identifier - Client identifier
 * @param {string} [keyPrefix='bf'] - Redis key prefix
 */
const resetFailedAttempts = async (identifier, keyPrefix = 'bf') => {
  if (!isRedisReady()) return;
  
  try {
    const key = `${keyPrefix}:${identifier}`;
    await redisClient.del(key, `${key}:lastAttempt`);
  } catch (error) {
    logger.error('Failed to reset failed attempts:', error);
  }
};

module.exports = {
  createRateLimiter,
  markRateLimitFailure,
  loginRateLimiter,
  refreshRateLimiter,
  registerRateLimiter,
  apiRateLimiter,
  createBruteForceProtection,
  recordFailedAttempt,
  resetFailedAttempts
};
