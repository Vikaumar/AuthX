# AuthX - Enterprise Authentication System

A production-ready, enterprise-grade authentication system built with Node.js, Express, PostgreSQL, Redis, and JWT. Implements secure Access Token + Refresh Token architecture with token rotation, reuse detection, RBAC, and rate limiting.

## 🔐 Features

- **Access Token + Refresh Token Architecture**
  - Short-lived access tokens (15 minutes)
  - Long-lived refresh tokens (7 days)
  - Automatic token rotation on refresh

- **Security**
  - Password hashing with bcrypt (12 salt rounds)
  - JWT signing with HS256
  - Token reuse detection (invalidates all sessions on breach)
  - Refresh tokens stored as SHA-256 hashes
  - Helmet.js for secure HTTP headers

- **Rate Limiting & Brute Force Protection**
  - Redis-based rate limiting
  - Progressive delays after failed login attempts
  - Configurable limits per endpoint

- **Role-Based Access Control (RBAC)**
  - USER and ADMIN roles
  - Middleware for route protection
  - Resource ownership validation

## 📋 Prerequisites

- **Node.js** 18.x or higher
- **PostgreSQL** 13.x or higher
- **Redis** 6.x or higher

## 🚀 Quick Start

### 1. Clone and Install

```bash
cd AuthX
npm install
```

### 2. Configure Environment

```bash
# Copy the example environment file
cp .env.example .env

# Edit .env with your database credentials
# IMPORTANT: Change the JWT secrets!
```

### 3. Create Database

```sql
-- Connect to PostgreSQL and create the database
CREATE DATABASE authx;
```

### 4. Initialize Schema

```bash
npm run db:init
```

### 5. Start the Server

```bash
# Development (with auto-reload)
npm run dev

# Production
npm start
```

The server will start at `http://localhost:3000`

## 📡 API Endpoints

### Authentication

| Method | Endpoint | Description | Auth Required |
|--------|----------|-------------|---------------|
| POST | `/auth/register` | Create new user account | No |
| POST | `/auth/login` | Authenticate and get tokens | No |
| POST | `/auth/refresh` | Get new token pair | Refresh Token |
| POST | `/auth/logout` | Revoke refresh token(s) | Access Token |
| GET | `/auth/me` | Get current user profile | Access Token |

### Protected Routes (Examples)

| Method | Endpoint | Description | Required Role |
|--------|----------|-------------|---------------|
| GET | `/protected/profile` | User profile | USER, ADMIN |
| GET | `/protected/dashboard` | User dashboard | USER, ADMIN |
| GET | `/protected/admin` | Admin area | ADMIN only |
| GET | `/protected/admin/stats` | System stats | ADMIN only |

### Health Check

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/health` | Server health status |

## 📝 API Examples

### Register a New User

```bash
curl -X POST http://localhost:3000/auth/register \
  -H "Content-Type: application/json" \
  -d '{
    "email": "user@example.com",
    "password": "SecurePass123!"
  }'
```

**Response:**
```json
{
  "success": true,
  "message": "User registered successfully",
  "data": {
    "user": {
      "id": "550e8400-e29b-41d4-a716-446655440000",
      "email": "user@example.com",
      "role": "USER",
      "createdAt": "2024-01-01T00:00:00.000Z"
    },
    "accessToken": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
    "refreshToken": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
    "tokenType": "Bearer"
  }
}
```

### Login

```bash
curl -X POST http://localhost:3000/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "email": "user@example.com",
    "password": "SecurePass123!"
  }'
```

### Refresh Tokens

```bash
curl -X POST http://localhost:3000/auth/refresh \
  -H "Content-Type: application/json" \
  -d '{
    "refreshToken": "YOUR_REFRESH_TOKEN"
  }'
```

### Access Protected Route

```bash
curl -X GET http://localhost:3000/protected/profile \
  -H "Authorization: Bearer YOUR_ACCESS_TOKEN"
```

### Logout

```bash
# Logout from current device
curl -X POST http://localhost:3000/auth/logout \
  -H "Authorization: Bearer YOUR_ACCESS_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "refreshToken": "YOUR_REFRESH_TOKEN"
  }'

# Logout from all devices
curl -X POST http://localhost:3000/auth/logout \
  -H "Authorization: Bearer YOUR_ACCESS_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "allDevices": true
  }'
```

## 🔒 Security Features

### Token Rotation

Every time a refresh token is used, it is immediately revoked and a new one is issued. This limits the window of opportunity if a token is compromised.

### Reuse Detection

If a revoked refresh token is used (indicating theft), ALL tokens for that user are immediately invalidated, forcing re-authentication on all devices.

### Rate Limiting

| Endpoint | Limit | Window |
|----------|-------|--------|
| `/auth/register` | 3 requests | 1 hour |
| `/auth/login` | 5 requests | 15 minutes |
| `/auth/refresh` | 10 requests | 15 minutes |
| Protected routes | 100 requests | 15 minutes |

### Brute Force Protection

After repeated failed login attempts, progressive delays are enforced:
- 3 failures: 30 second wait
- 4 failures: 60 second wait
- 5 failures: 120 second wait
- 6+ failures: 300+ second wait

## 📁 Project Structure

```
AuthX/
├── src/
│   ├── controllers/
│   │   └── auth.controller.js      # Request handlers
│   ├── services/
│   │   ├── auth.service.js         # Business logic
│   │   └── token.service.js        # Token management
│   ├── routes/
│   │   ├── auth.routes.js          # Auth endpoints
│   │   └── protected.routes.js     # Protected examples
│   ├── middleware/
│   │   ├── auth.middleware.js      # JWT verification
│   │   ├── rbac.middleware.js      # Role-based access
│   │   ├── rateLimiter.middleware.js # Rate limiting
│   │   ├── errorHandler.middleware.js # Error handling
│   │   └── validator.middleware.js # Input validation
│   ├── utils/
│   │   ├── jwt.util.js             # JWT helpers
│   │   ├── password.util.js        # Bcrypt helpers
│   │   ├── response.util.js        # Response formatting
│   │   └── logger.util.js          # Logging
│   ├── config/
│   │   ├── database.js             # PostgreSQL pool
│   │   ├── redis.js                # Redis client
│   │   └── constants.js            # App constants
│   ├── db/
│   │   ├── schema.sql              # Database schema
│   │   └── init.js                 # Schema runner
│   └── app.js                      # Express app
├── .env.example
├── .gitignore
├── package.json
└── README.md
```

## ⚙️ Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `NODE_ENV` | Environment (development/production) | development |
| `PORT` | Server port | 3000 |
| `DB_HOST` | PostgreSQL host | localhost |
| `DB_PORT` | PostgreSQL port | 5432 |
| `DB_NAME` | Database name | authx |
| `DB_USER` | Database user | postgres |
| `DB_PASSWORD` | Database password | - |
| `REDIS_HOST` | Redis host | localhost |
| `REDIS_PORT` | Redis port | 6379 |
| `ACCESS_TOKEN_SECRET` | JWT secret for access tokens | **CHANGE THIS** |
| `REFRESH_TOKEN_SECRET` | JWT secret for refresh tokens | **CHANGE THIS** |
| `ACCESS_TOKEN_EXPIRY` | Access token lifetime | 15m |
| `REFRESH_TOKEN_EXPIRY_DAYS` | Refresh token lifetime (days) | 7 |
| `BCRYPT_SALT_ROUNDS` | Password hashing rounds | 12 |

## 🔧 Extending the System

### Adding a New Protected Route

```javascript
// In routes/protected.routes.js
const { authenticate } = require('../middleware/auth.middleware');
const { requireRoles } = require('../middleware/rbac.middleware');

router.get(
  '/new-route',
  authenticate,                    // Requires valid access token
  requireRoles('USER', 'ADMIN'),   // Requires USER or ADMIN role
  (req, res) => {
    // Access user info via req.user
    res.json({ userId: req.user.userId });
  }
);
```

### Adding a New Role

1. Add role to `src/config/constants.js`:
```javascript
const ROLES = {
  USER: 'USER',
  ADMIN: 'ADMIN',
  MODERATOR: 'MODERATOR'  // New role
};
```

2. Update database schema constraint:
```sql
ALTER TABLE users DROP CONSTRAINT users_role_check;
ALTER TABLE users ADD CONSTRAINT users_role_check 
  CHECK (role IN ('USER', 'ADMIN', 'MODERATOR'));
```

## 📜 License

MIT

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Commit your changes
4. Push to the branch
5. Open a pull request
