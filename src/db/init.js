/**
 * Database Initialization Script
 * Runs the schema.sql to set up database tables
 * 
 * Usage: npm run db:init
 */

require('dotenv').config();

const fs = require('fs');
const path = require('path');
const { pool } = require('../config/database');
const logger = require('../utils/logger.util');

const initDatabase = async () => {
  logger.info('Starting database initialization...');
  
  try {
    // Read the schema file
    const schemaPath = path.join(__dirname, 'schema.sql');
    const schema = fs.readFileSync(schemaPath, 'utf8');
    
    // Execute the schema
    await pool.query(schema);
    
    logger.info('✓ Database schema created successfully');
    
    // Verify tables were created
    const tablesResult = await pool.query(`
      SELECT table_name 
      FROM information_schema.tables 
      WHERE table_schema = 'public' 
      AND table_type = 'BASE TABLE'
    `);
    
    logger.info('Created tables:', tablesResult.rows.map(r => r.table_name));
    
  } catch (error) {
    logger.error('Database initialization failed:', error);
    process.exit(1);
  } finally {
    await pool.end();
    logger.info('Database connection closed');
  }
};

// Run if called directly
if (require.main === module) {
  initDatabase()
    .then(() => {
      logger.info('Database initialization complete');
      process.exit(0);
    })
    .catch((error) => {
      logger.error('Initialization error:', error);
      process.exit(1);
    });
}

module.exports = { initDatabase };
