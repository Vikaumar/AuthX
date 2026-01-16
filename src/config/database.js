/**
 * PostgreSQL Database Configuration
 * Sets up connection pool with proper error handling and graceful shutdown
 */

const { Pool } = require('pg');
const logger = require('../utils/logger.util');
const isProduction = process.env.NODE_ENV === 'production';

// Create connection pool with environment configuration
const pool = new Pool(
  process.env.DATABASE_URL
    ? {
        connectionString: process.env.DATABASE_URL,
        ssl: isProduction ? { rejectUnauthorized: false } : false,
        max: 20,
        idleTimeoutMillis: 30000,
        connectionTimeoutMillis: 5000,
      }
    : {
        host: process.env.DB_HOST || 'localhost',
        port: parseInt(process.env.DB_PORT, 10) || 5432,
        database: process.env.DB_NAME || 'authx',
        user: process.env.DB_USER || 'postgres',
        password: process.env.DB_PASSWORD || '',
        ssl: isProduction ? { rejectUnauthorized: false } : false,
        max: 20,
        idleTimeoutMillis: 30000,
        connectionTimeoutMillis: 5000,
      }
);

// Log pool errors (don't crash the app)
pool.on('error', (err) => {
  logger.error('Unexpected database pool error:', err);
});

// Log successful connection
pool.on('connect', () => {
  logger.debug('New database client connected');
});

/**
 * Execute a parameterized query
 * @param {string} text - SQL query text with $1, $2, etc. placeholders
 * @param {Array} params - Array of parameter values
 * @returns {Promise<Object>} Query result
 */
const query = async (text, params) => {
  const start = Date.now();
  try {
    const result = await pool.query(text, params);
    const duration = Date.now() - start;
    logger.debug(`Query executed in ${duration}ms: ${text.substring(0, 50)}...`);
    return result;
  } catch (error) {
    logger.error('Database query error:', { query: text, error: error.message });
    throw error;
  }
};

/**
 * Get a client from the pool for transactions
 * Remember to release the client after use!
 * @returns {Promise<Object>} Database client
 */
const getClient = async () => {
  const client = await pool.connect();
  return client;
};

/**
 * Test database connection
 * @returns {Promise<boolean>} True if connection successful
 */
const testConnection = async () => {
  try {
    await pool.query('SELECT NOW()');
    logger.info('✓ Database connection established');
    return true;
  } catch (error) {
    logger.error('✗ Database connection failed:', {
      message: error.message,
      code: error.code,
      stack: error.stack,
    });
    return false;
  }
};

/**
 * Gracefully close all pool connections
 */
const closePool = async () => {
  try {
    await pool.end();
    logger.info('Database pool closed');
  } catch (error) {
    logger.error('Error closing database pool:', error);
  }
};

module.exports = {
  query,
  getClient,
  testConnection,
  closePool,
  pool
};
