/**
 * AuthX - Enterprise Authentication System
 * Main Application Entry Point
 */

// Load environment variables first
require('dotenv').config();

const express = require('express');
const helmet = require('helmet');
const cors = require('cors');

// Configuration
const { testConnection, closePool } = require('./config/database');
const { connectRedis, disconnectRedis } = require('./config/redis');
const logger = require('./utils/logger.util');

// Middleware
const { notFoundHandler, errorHandler } = require('./middleware/errorHandler.middleware');

// Routes
const authRoutes = require('./routes/auth.routes');
const protectedRoutes = require('./routes/protected.routes');

// Initialize Express app
const app = express();

// ============================================
// Security Middleware
// ============================================

// Helmet: Set security-related HTTP headers
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      styleSrc: ["'self'", "'unsafe-inline'"],
      scriptSrc: ["'self'"],
      imgSrc: ["'self'", 'data:', 'https:']
    }
  },
  hsts: {
    maxAge: 31536000, // 1 year
    includeSubDomains: true,
    preload: true
  }
}));

// CORS configuration
app.use(cors({
  origin: process.env.CORS_ORIGIN || '*',
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH'],
  allowedHeaders: ['Content-Type', 'Authorization'],
  exposedHeaders: ['X-RateLimit-Limit', 'X-RateLimit-Remaining', 'X-RateLimit-Reset', 'Retry-After'],
  credentials: true,
  maxAge: 86400 // 24 hours
}));

// ============================================
// Request Parsing Middleware
// ============================================

// Parse JSON bodies
app.use(express.json({ limit: '10kb' })); // Limit body size for security

// Parse URL-encoded bodies
app.use(express.urlencoded({ extended: true, limit: '10kb' }));

// Trust proxy (for correct IP in rate limiting behind reverse proxy)
app.set('trust proxy', 1);

// ============================================
// Request Logging (Development)
// ============================================

if (process.env.NODE_ENV !== 'production') {
  app.use((req, res, next) => {
    logger.debug(`${req.method} ${req.path}`, {
      query: req.query,
      ip: req.ip
    });
    next();
  });
}

// ============================================
// Health Check Endpoint
// ============================================

app.get('/health', (req, res) => {
  res.json({
    status: 'ok',
    timestamp: new Date().toISOString(),
    uptime: process.uptime(),
    environment: process.env.NODE_ENV || 'development'
  });
});

// ============================================
// API Routes
// ============================================

// Authentication routes
app.use('/auth', authRoutes);

// Protected routes (examples)
app.use('/protected', protectedRoutes);

// ============================================
// Error Handling
// ============================================

// 404 handler for undefined routes
app.use(notFoundHandler);

// Global error handler
app.use(errorHandler);

// ============================================
// Server Startup
// ============================================

const PORT = parseInt(process.env.PORT, 10) || 3000;
const HOST = process.env.HOST || '0.0.0.0';

/**
 * Initialize database and Redis connections, then start server
 */
const startServer = async () => {
  try {
    logger.info('Starting AuthX server...');
    
    // Test database connection
    const dbConnected = await testConnection();
    if (!dbConnected) {
      logger.error('Failed to connect to database. Check your configuration.');
      process.exit(1);
    }
    
    // Connect to Redis
    try {
      await connectRedis();
    } catch (redisError) {
      logger.warn('Redis connection failed. Rate limiting will be disabled.', {
        error: redisError.message
      });
      // Continue without Redis - rate limiting will be bypassed
    }
    
    // Start HTTP server
    const server = app.listen(PORT, HOST, () => {
      logger.info(`
╔════════════════════════════════════════════════════════════╗
║                                                            ║
║   🔐 AuthX Authentication Server                           ║
║                                                            ║
║   Server running at: http://${HOST}:${PORT}                   ║
║   Environment: ${process.env.NODE_ENV || 'development'}                              ║
║                                                            ║
║   Endpoints:                                               ║
║   • POST /auth/register  - Create account                  ║
║   • POST /auth/login     - Get tokens                      ║
║   • POST /auth/refresh   - Refresh tokens                  ║
║   • POST /auth/logout    - Revoke tokens                   ║
║   • GET  /auth/me        - Get user profile                ║
║   • GET  /protected/*    - Protected routes                ║
║   • GET  /health         - Health check                    ║
║                                                            ║
╚════════════════════════════════════════════════════════════╝
      `);
    });
    
    // Graceful shutdown handler
    const gracefulShutdown = async (signal) => {
      logger.info(`${signal} received. Starting graceful shutdown...`);
      
      server.close(async () => {
        logger.info('HTTP server closed');
        
        // Close database connections
        await closePool();
        
        // Close Redis connection
        await disconnectRedis();
        
        logger.info('Graceful shutdown completed');
        process.exit(0);
      });
      
      // Force shutdown after 30 seconds
      setTimeout(() => {
        logger.error('Forced shutdown after timeout');
        process.exit(1);
      }, 30000);
    };
    
    // Listen for shutdown signals
    process.on('SIGTERM', () => gracefulShutdown('SIGTERM'));
    process.on('SIGINT', () => gracefulShutdown('SIGINT'));
    
    // Handle uncaught exceptions
    process.on('uncaughtException', (error) => {
      logger.error('Uncaught Exception:', error);
      gracefulShutdown('UNCAUGHT_EXCEPTION');
    });
    
    // Handle unhandled promise rejections
    process.on('unhandledRejection', (reason, promise) => {
      logger.error('Unhandled Rejection:', { reason, promise });
    });
    
  } catch (error) {
    logger.error('Failed to start server:', error);
    process.exit(1);
  }
};

// Start the server
startServer();

// Export app for testing
module.exports = app;
