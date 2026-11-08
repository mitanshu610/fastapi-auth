# FastAPI Authentication & Authorization System

A comprehensive authentication and authorization system built with **FastAPI**, featuring local password authentication, token management, and a robust Role-Based Access Control (RBAC) system.

## Features

### 🔐 Authentication
- **Local Authentication** with secure password hashing
- **Multi-token Support**: JWT and PASETO tokens
- **Token Refresh** and revocation mechanisms

### 🏢 Authorization & RBAC
- **Organization-level** access control
- **Team-based** permissions management
- **Role and Permission** assignment system
- **Hierarchical** access control structures

### 🛡️ Security
- Secure password hashing with `bcrypt`
- Token-based authentication with automatic expiration
- Password strength validation
- Session management with Redis
- Comprehensive input validation

### 🚀 Performance & Scalability
- Async/await patterns throughout
- Redis caching for permissions and sessions
- Database connection pooling
- Background task processing

## Tech Stack

- **Framework**: FastAPI
- **Database**: PostgreSQL with SQLAlchemy (async)
- **Cache**: Redis
- **Authentication**: JWT, PASETO
- **Password Hashing**: bcrypt via passlib
- **Testing**: pytest with async support
- **Containerization**: Docker & Docker Compose

## Project Structure

```
├── app/
│   └── server.py              # FastAPI application setup
├── auth/
│   ├── models.py              # User and token models
│   ├── routes.py              # Authentication routes
│   ├── views.py               # Authentication endpoints
│   ├── services.py            # Authentication business logic
│   ├── schemas.py             # Pydantic models
│   ├── dao.py                 # Database access layer
│   ├── dependencies.py        # Auth dependencies
│   └── utils.py               # Auth utilities
├── organizations/
│   ├── models.py              # Organization models
│   ├── routes.py              # Organization routes
│   ├── views.py               # Organization endpoints
│   └── schemas.py             # Organization schemas
├── teams/
│   ├── models.py              # Team models
│   ├── routes.py              # Team routes
│   ├── views.py               # Team endpoints
│   └── schemas.py             # Team schemas
├── roles/
│   ├── models.py              # Role models
│   ├── routes.py              # Role routes
│   ├── views.py               # Role endpoints
│   └── schemas.py             # Role schemas
├── permissions/
│   ├── models.py              # Permission models
│   ├── routes.py              # Permission routes
│   ├── views.py               # Permission endpoints
│   └── schemas.py             # Permission schemas
├── db/
│   ├── pg_connection.py       # PostgreSQL connection
│   └── redis_connection.py    # Redis connection
├── config/
│   └── settings.py            # Application settings
├── utils/
│   ├── exceptions.py          # Custom exceptions
│   ├── utilities.py           # Utility functions
│   └── custom_logger.py       # Logging configuration
├── tests/                     # Comprehensive test suite
├── alembic/                   # Database migrations
├── requirements/              # Dependencies
├── docker-compose.yaml        # Docker services
├── Dockerfile                 # Application container
└── main.py                    # Application entry point
```

## Quick Start

### Prerequisites

- Python 3.8+
- Docker & Docker Compose
- PostgreSQL 12+
- Redis 6+

### Using Docker (Recommended)

1. **Clone the repository**
   ```bash
   git clone <repository-url>
   cd fastapi-auth
   ```

2. **Environment Configuration**
   Create a `.env` file in the root directory:
   ```env
   # Database
   DATABASE_URL=postgresql+asyncpg://postgres:postgres@db:5432/fastapi_auth
   
   # Redis
   REDIS_DATABASE_URL=redis://redis:6379/0
   
   # Security
   SECRET_KEY=your-super-secret-key-here
   ALGORITHM=HS256
   ACCESS_TOKEN_EXPIRE_MINUTES=15
   REFRESH_TOKEN_EXPIRE_DAYS=7
   
   AUTH_MODE=jwt  # or 'paseto'
   ```

3. **Start the services**
   ```bash
   docker compose up --build -d
   ```

   The app waits for PostgreSQL and Redis to become healthy, applies database migrations, and then starts.

4. **Access the application**
   - API Documentation: http://localhost:8000/docs
   - ReDoc Documentation: http://localhost:8000/redoc

### Local Development

1. **Install dependencies**
   ```bash
   pip install -r requirements/requirements.txt
   ```

2. **Set up database**
   ```bash
   # Start PostgreSQL and Redis
   docker compose up -d db redis
   
   # Run migrations
   alembic upgrade head
   ```

3. **Run the application**
   ```bash
   uvicorn app.server:app --reload --host 0.0.0.0 --port 8000
   ```

## API Endpoints

### Authentication

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/auth/register` | POST | Register a new user |
| `/auth/login` | POST | Login with email/password |
| `/auth/refresh` | POST | Refresh access token |
| `/auth/revoke` | POST | Revoke refresh token |

Users register with a local password and can log in immediately. Email verification, email-based password recovery, and email invitations are not available. Organization admins can add users after those users have registered.

### Organizations

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/rbac/organizations/` | POST | Create organization |
| `/rbac/organizations/{id}` | GET | Get organization by ID |
| `/rbac/organizations/{id}` | PUT | Update organization |
| `/rbac/organizations/my-organizations` | GET | Get user's organizations |
| `/rbac/organizations/{id}/members` | GET | Get organization members |
| `/rbac/organizations/{id}/members` | POST | Add user to organization |
| `/rbac/organizations/{id}/members/{user_id}` | DELETE | Remove user from organization |

### Teams

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/rbac/teams/` | POST | Create team |
| `/rbac/teams/{id}` | GET | Get team by ID |
| `/rbac/teams/{id}` | PUT | Update team |
| `/rbac/teams/{id}` | DELETE | Delete team |
| `/rbac/teams/my-teams` | GET | Get user's teams |
| `/rbac/teams/organization/{org_id}` | GET | Get organization teams |
| `/rbac/teams/{id}/members` | GET | Get team members |
| `/rbac/teams/{id}/members` | POST | Add user to team |
| `/rbac/teams/{id}/members/{email}` | DELETE | Remove user from team |

### Roles & Permissions

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/rbac/roles/` | GET/POST | List/Create roles |
| `/rbac/roles/{id}` | GET/PUT/DELETE | Manage role by ID |
| `/rbac/roles/slug/{slug}` | GET | Get role by slug |
| `/rbac/roles/{id}/permissions/{perm_id}` | POST/DELETE | Assign/Remove permissions |
| `/rbac/permissions/` | GET/POST | List/Create permissions |
| `/rbac/permissions/{id}` | GET/PUT/DELETE | Manage permission by ID |
| `/rbac/permissions/cache/refresh` | POST | Refresh permissions cache |

## Example Usage

### Register a New User

```bash
curl -X POST "http://localhost:8000/auth/register" \
     -H "Content-Type: application/json" \
     -d '{
       "email": "user@example.com",
       "first_name": "John",
       "last_name": "Doe",
       "phone_number": "+1234567890",
       "password": "SecurePass123!"
     }'
```

### Login

```bash
curl -X POST "http://localhost:8000/auth/login" \
     -H "Content-Type: application/x-www-form-urlencoded" \
     -d "username=user@example.com&password=SecurePass123!"
```

### Create Organization

```bash
curl -X POST "http://localhost:8000/rbac/organizations/" \
     -H "Content-Type: application/json" \
     -H "Authorization: Bearer YOUR_ACCESS_TOKEN" \
     -d '{"name": "My Organization"}'
```

## Testing

The project includes comprehensive unit tests for all endpoints.

```bash
# Run all tests
pytest

# Run with coverage
pytest --cov=.

# Run specific test file
pytest tests/test_auth_endpoints.py

# Run with verbose output
pytest -v
```

### Test Coverage

- Authentication endpoints (register, login, token refresh and revocation)
- Organizations management
- Teams management
- Roles and permissions
- Error handling and edge cases
- Security validations

## Configuration

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `DATABASE_URL` | PostgreSQL connection string | Required |
| `REDIS_DATABASE_URL` | Redis connection string | Required |
| `SECRET_KEY` | JWT signing secret | Required |
| `ACCESS_TOKEN_EXPIRE_MINUTES` | Access token expiry | 15 |
| `REFRESH_TOKEN_EXPIRE_DAYS` | Refresh token expiry | 7 |
| `AUTH_MODE` | Token type (jwt/paseto) | jwt |

## Security Considerations

- All passwords are hashed using bcrypt
- JWT tokens have configurable expiration times
- Refresh tokens are stored securely and can be revoked
- Input validation on all endpoints
- Rate limiting can be implemented via middleware
- CORS configuration for cross-origin requests
- Comprehensive error handling without information leakage

## Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Support

For support and questions, please:
1. Check the [API documentation](http://localhost:8000/docs)
2. Review the test files for usage examples
3. Open an issue in the repository
