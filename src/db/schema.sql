-- ============================================
-- AuthX Database Schema
-- PostgreSQL schema for authentication system
-- ============================================

-- Enable UUID extension for generating UUIDs
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- ============================================
-- Users Table
-- Stores user account information
-- ============================================
CREATE TABLE IF NOT EXISTS users (
    -- Primary identifier using UUID for security (non-sequential)
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    
    -- User credentials
    email VARCHAR(255) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    
    -- Role for RBAC (USER, ADMIN)
    role VARCHAR(50) NOT NULL DEFAULT 'USER',
    
    -- Account status
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    
    -- Timestamps
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    
    -- Constraints
    CONSTRAINT users_email_check CHECK (email ~* '^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$'),
    CONSTRAINT users_role_check CHECK (role IN ('USER', 'ADMIN'))
);

-- Index for faster email lookups during login
CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);

-- ============================================
-- Refresh Tokens Table
-- Stores hashed refresh tokens for validation
-- ============================================
CREATE TABLE IF NOT EXISTS refresh_tokens (
    -- Primary identifier
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    
    -- Foreign key to users table
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    
    -- Token hash (SHA-256 of the actual token)
    -- We store hash, not the actual token, for security
    token_hash VARCHAR(255) NOT NULL,
    
    -- Token expiration timestamp
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
    
    -- Revocation status and timestamp
    is_revoked BOOLEAN NOT NULL DEFAULT FALSE,
    revoked_at TIMESTAMP WITH TIME ZONE,
    
    -- Token family ID for rotation tracking
    -- All tokens in a refresh chain share the same family_id
    -- This enables detection of token reuse attacks
    family_id UUID NOT NULL,
    
    -- Timestamps
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    
    -- Constraints
    CONSTRAINT refresh_tokens_expiry_check CHECK (expires_at > created_at)
);

-- Index for faster token lookups
CREATE INDEX IF NOT EXISTS idx_refresh_tokens_token_hash ON refresh_tokens(token_hash);

-- Index for finding all tokens in a family (for mass revocation)
CREATE INDEX IF NOT EXISTS idx_refresh_tokens_family_id ON refresh_tokens(family_id);

-- Index for finding all user tokens (for logout all devices)
CREATE INDEX IF NOT EXISTS idx_refresh_tokens_user_id ON refresh_tokens(user_id);

-- Index for cleanup of expired tokens
CREATE INDEX IF NOT EXISTS idx_refresh_tokens_expires_at ON refresh_tokens(expires_at) 
    WHERE is_revoked = FALSE;

-- ============================================
-- Function: Update updated_at timestamp
-- Automatically updates the updated_at column
-- ============================================
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = CURRENT_TIMESTAMP;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- Trigger to auto-update updated_at on users table
DROP TRIGGER IF EXISTS trigger_users_updated_at ON users;
CREATE TRIGGER trigger_users_updated_at
    BEFORE UPDATE ON users
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

-- ============================================
-- Function: Cleanup expired tokens
-- Run periodically to remove old tokens
-- ============================================
CREATE OR REPLACE FUNCTION cleanup_expired_tokens()
RETURNS INTEGER AS $$
DECLARE
    deleted_count INTEGER;
BEGIN
    DELETE FROM refresh_tokens 
    WHERE expires_at < CURRENT_TIMESTAMP 
       OR (is_revoked = TRUE AND revoked_at < CURRENT_TIMESTAMP - INTERVAL '7 days');
    
    GET DIAGNOSTICS deleted_count = ROW_COUNT;
    RETURN deleted_count;
END;
$$ LANGUAGE plpgsql;

-- ============================================
-- Sample Admin User (password: Admin@123456)
-- Uncomment to create a default admin user
-- ============================================
-- INSERT INTO users (email, password_hash, role) VALUES (
--     'admin@authx.com',
--     '$2b$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/X4.CQ/JqYXbXZxZxS',
--     'ADMIN'
-- ) ON CONFLICT (email) DO NOTHING;
