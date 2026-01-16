/**
 * Redis Client Configuration
 * Sets up Redis connection for rate limiting and session management
 */

const { createClient } = require('redis');
const logger = require('../utils/logger.util');

// Create Redis client with environment configuration
const redisClient = createClient({
  socket: {
    host: process.env.REDIS_HOST || 'localhost',
    port: parseInt(process.env.REDIS_PORT, 10) || 6379,
    reconnectStrategy: (retries) => {
      // Exponential backoff with max 30 seconds
      if (retries > 10) {
        logger.error('Redis: Max reconnection attempts reached');
        return new Error('Redis max retries reached');
      }
      return Math.min(retries * 100, 30000);
    }
  },
  password: process.env.REDIS_PASSWORD || undefined
});

// Event handlers for connection lifecycle
redisClient.on('connect', () => {
  logger.debug('Redis client connecting...');
});

redisClient.on('ready', () => {
  logger.info('✓ Redis connection established');
});

redisClient.on('error', (err) => {
  logger.error('Redis client error:', err.message);
});

redisClient.on('reconnecting', () => {
  logger.warn('Redis client reconnecting...');
});

redisClient.on('end', () => {
  logger.info('Redis client disconnected');
});

/**
 * Connect to Redis server
 * @returns {Promise<void>}
 */
const connectRedis = async () => {
  try {
    await redisClient.connect();
  } catch (error) {
    logger.error('Failed to connect to Redis:', error.message);
    throw error;
  }
};

/**
 * Disconnect from Redis server gracefully
 * @returns {Promise<void>}
 */
const disconnectRedis = async () => {
  try {
    if (redisClient.isOpen) {
      await redisClient.quit();
    }
  } catch (error) {
    logger.error('Error disconnecting from Redis:', error);
  }
};

/**
 * Check if Redis is connected and ready
 * @returns {boolean}
 */
const isRedisReady = () => {
  return redisClient.isReady;
};

module.exports = {
  redisClient,
  connectRedis,
  disconnectRedis,
  isRedisReady
};
