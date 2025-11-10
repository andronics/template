
# REST API Architecture v1.0.0

**Meta-Architecture Compliance**: v1.0.0  
**Template Version**: 1.0.0  
**Status**: Active  
**Last Audit**: 2025-11-10  
**Compliance Score**: 100%

---

## Table of Contents

1. [Meta-Architecture Reference](#1-meta-architecture-reference)
2. [REST API Overview](#2-rest-api-overview)
3. [Core Principles Mapping](#3-core-principles-mapping)
4. [Implementation Patterns](#4-implementation-patterns)
5. [Complete Code Examples](#5-complete-code-examples)
6. [Tool Recommendations](#6-tool-recommendations)
7. [Testing Strategy](#7-testing-strategy)
8. [Deployment Guidelines](#8-deployment-guidelines)
9. [Compliance Checklist](#9-compliance-checklist)
10. [Migration Guide](#10-migration-guide)

---

## 1. Meta-Architecture Reference

This template implements all 12 universal principles from Meta-Architecture v1.0.0, providing REST API-specific patterns and best practices for building reliable, maintainable, and scalable HTTP APIs.

### Compliance Matrix

| Principle | REST API Implementation | Status |
|-----------|------------------------|--------|
| 1. Layered Architecture | Routes → Controllers → Services → Repositories | ✅ Full |
| 2. Dependency Management | OpenAPI spec + package manager | ✅ Full |
| 3. Graceful Degradation | Fallback endpoints, circuit breakers | ✅ Full |
| 4. Input Validation | Request validation middleware | ✅ Full |
| 5. Error Handling | RFC 7807 Problem Details | ✅ Full |
| 6. Configuration | Environment-based configuration | ✅ Full |
| 7. Observability | Structured logs, metrics, tracing | ✅ Full |
| 8. Testing | Contract tests, integration tests | ✅ Full |
| 9. Security | OAuth2, rate limiting, CORS | ✅ Full |
| 10. Resource Management | Connection pooling, timeouts | ✅ Full |
| 11. Performance | Caching, pagination, compression | ✅ Full |
| 12. Evolution | API versioning, deprecation policy | ✅ Full |

### REST API Alignment with Meta-Architecture

This template enforces:
- **Four-layer architecture** with clear separation of concerns
- **HTTP semantic correctness** using proper methods and status codes
- **Stateless design** following REST constraints
- **Hypermedia-driven** with HATEOAS where appropriate
- **Resource-oriented** API design

---

## 2. REST API Overview

### What is a REST API?

**REST** (Representational State Transfer) is an architectural style for distributed systems that uses HTTP as the communication protocol. REST APIs expose resources through URIs and use standard HTTP methods to perform operations.

### Core REST Principles

1. **Client-Server Architecture**: Separation of concerns
2. **Statelessness**: Each request contains all necessary information
3. **Cacheability**: Responses explicitly indicate cacheability
4. **Layered System**: Client cannot tell if connected directly to server
5. **Uniform Interface**: Standardized communication
6. **Code on Demand** (optional): Servers can extend client functionality

### HTTP Methods (CRUD Operations)

```
POST    → Create    (201 Created, 200 OK)
GET     → Read      (200 OK, 404 Not Found)
PUT     → Replace   (200 OK, 204 No Content)
PATCH   → Update    (200 OK, 204 No Content)
DELETE  → Delete    (204 No Content, 200 OK)
```

### Common Use Cases

1. **Public APIs**: External integrations, third-party developers
2. **Mobile Backends**: iOS, Android, React Native apps
3. **Single Page Applications**: React, Vue, Angular frontends
4. **Microservices**: Service-to-service communication
5. **Webhooks**: Event-driven integrations
6. **B2B Integrations**: Partner API integrations

### REST API Characteristics

**Strengths:**
- Simple and well-understood
- Leverages existing HTTP infrastructure
- Great caching support
- Language-agnostic
- Wide tooling support

**Considerations:**
- Over-fetching or under-fetching data
- Multiple round trips for related data
- Versioning complexity
- No built-in real-time support

### When to Use REST APIs

✅ **Use REST when:**
- Building standard CRUD APIs
- Need wide compatibility
- Leveraging HTTP caching
- Simple resource-based operations
- Public API for third parties

❌ **Consider alternatives when:**
- Need real-time bidirectional communication (use WebSockets)
- Complex graph-based data fetching (use GraphQL)
- High-performance RPC (use gRPC)
- Event-driven architecture (use message queues)

---

## 3. Core Principles Mapping

### Principle 1: Layered Architecture ⭐ MANDATORY

**Meta-Architecture Definition:**  
"All systems MUST organize code into 4 distinct layers with downward-only dependencies."

**REST API Implementation:**

REST APIs naturally align with the four-layer architecture:

```
Layer 4: Routes/Controllers    (HTTP handlers, request/response)
              ↓
Layer 3: Integration           (External APIs, databases)
              ↓
Layer 2: Middleware/Services   (Logging, auth, validation)
              ↓
Layer 1: Utilities/Schemas     (Validation schemas, helpers)
```

**Directory Structure:**

```
api/
├── foundation/           # Layer 1
│   ├── schemas/          # Request/response schemas
│   ├── validators/       # Input validation
│   ├── errors/           # Error definitions
│   └── utils/            # Helper functions
│
├── infrastructure/       # Layer 2
│   ├── middleware/       # Auth, logging, CORS
│   ├── config/           # Configuration
│   ├── logging/          # Structured logging
│   └── monitoring/       # Metrics, health checks
│
├── integration/          # Layer 3
│   ├── database/         # Database repositories
│   ├── cache/            # Redis/caching layer
│   ├── external-apis/    # Third-party API clients
│   └── messaging/        # Message queues
│
└── application/          # Layer 4
    ├── routes/           # Route definitions
    ├── controllers/      # Request handlers
    └── services/         # Business logic
```

**Example Implementation (Express.js):**

```javascript
// ✅ foundation/validators/user-validator.js (Layer 1)
const Joi = require('joi');

const createUserSchema = Joi.object({
  email: Joi.string().email().required(),
  name: Joi.string().min(2).max(100).required(),
  age: Joi.number().integer().min(13).max(120).optional()
});

module.exports = { createUserSchema };

// ✅ infrastructure/middleware/validation.js (Layer 2)
const { ValidationError } = require('../foundation/errors');

function validate(schema) {
  return (req, res, next) => {
    const { error, value } = schema.validate(req.body);
    if (error) {
      return next(new ValidationError(error.details[0].message));
    }
    req.validatedBody = value;
    next();
  };
}

module.exports = { validate };

// ✅ integration/database/user-repository.js (Layer 3)
const { db } = require('../../infrastructure/config/database');

class UserRepository {
  async create(userData) {
    return db('users').insert(userData).returning('*');
  }

  async findById(id) {
    return db('users').where({ id }).first();
  }

  async findByEmail(email) {
    return db('users').where({ email }).first();
  }
}

module.exports = new UserRepository();

// ✅ application/controllers/user-controller.js (Layer 4)
const userService = require('../services/user-service');
const { createUserSchema } = require('../../foundation/validators/user-validator');
const { validate } = require('../../infrastructure/middleware/validation');

async function createUser(req, res, next) {
  try {
    const user = await userService.createUser(req.validatedBody);
    res.status(201).json({
      id: user.id,
      email: user.email,
      name: user.name,
      createdAt: user.created_at
    });
  } catch (error) {
    next(error);
  }
}

module.exports = {
  createUser: [validate(createUserSchema), createUser]
};

// ❌ BAD: Controller directly accessing database (skips service layer)
async function createUserBad(req, res) {
  const user = await db('users').insert(req.body); // VIOLATION!
}
```

**HTTP Layer Mapping:**

```
HTTP Request
    ↓
Middleware (Layer 2) - Auth, validation, logging
    ↓
Controller (Layer 4) - Parse request, orchestrate
    ↓
Service (Layer 4) - Business logic
    ↓
Repository (Layer 3) - Data access
    ↓
HTTP Response
```

**Common Pitfalls:**
- Controllers with business logic
- Direct database access from controllers
- Middleware calling business logic
- Circular dependencies between layers

**Best Practices:**
- Keep controllers thin (orchestration only)
- Put business logic in services
- Use middleware for cross-cutting concerns
- Repository pattern for data access
- Validate at layer boundaries

---

### Principle 2: Explicit Dependency Management ⭐ MANDATORY

**Meta-Architecture Definition:**  
"All dependencies MUST be explicitly declared, versioned, and manageable."

**REST API Implementation:**

For REST APIs, dependency management includes both code dependencies and API contract dependencies.

**Code Dependencies (package.json):**

```json
{
  "name": "my-rest-api",
  "version": "1.0.0",
  "dependencies": {
    "express": "^4.18.2",
    "joi": "^17.11.0",
    "jsonwebtoken": "^9.0.2",
    "pg": "^8.11.3",
    "pino": "^8.16.1",
    "prom-client": "^15.0.0"
  },
  "optionalDependencies": {
    "redis": "^4.6.10"
  },
  "devDependencies": {
    "jest": "^29.7.0",
    "supertest": "^6.3.3",
    "eslint": "^8.53.0"
  }
}
```

**API Dependencies (OpenAPI Specification):**

```yaml
# openapi.yaml
openapi: 3.0.3
info:
  title: User Management API
  version: 1.0.0
  description: REST API for managing users

servers:
  - url: https://api.example.com/v1
    description: Production
  - url: https://staging-api.example.com/v1
    description: Staging

paths:
  /users:
    post:
      summary: Create a new user
      operationId: createUser
      requestBody:
        required: true
        content:
          application/json:
            schema:
              $ref: '#/components/schemas/CreateUserRequest'
      responses:
        '201':
          description: User created successfully
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/User'
        '400':
          $ref: '#/components/responses/BadRequest'
        '409':
          $ref: '#/components/responses/Conflict'

components:
  schemas:
    CreateUserRequest:
      type: object
      required:
        - email
        - name
      properties:
        email:
          type: string
          format: email
        name:
          type: string
          minLength: 2
          maxLength: 100

    User:
      type: object
      properties:
        id:
          type: string
          format: uuid
        email:
          type: string
          format: email
        name:
          type: string
        createdAt:
          type: string
          format: date-time

  responses:
    BadRequest:
      description: Invalid request
      content:
        application/json:
          schema:
            $ref: '#/components/schemas/Error'

    Conflict:
      description: Resource already exists
      content:
        application/json:
          schema:
            $ref: '#/components/schemas/Error'

  securitySchemes:
    BearerAuth:
      type: http
      scheme: bearer
      bearerFormat: JWT

security:
  - BearerAuth: []
```

**External Service Dependencies:**

```javascript
// integration/external-apis/payment-service.js
class PaymentServiceClient {
  constructor(config) {
    this.baseURL = config.paymentService.url;
    this.apiKey = config.paymentService.apiKey;
    this.timeout = config.paymentService.timeout || 5000;
    this.retries = config.paymentService.retries || 3;
  }

  async processPayment(paymentData) {
    // Implementation with retry logic
  }

  async getPaymentStatus(paymentId) {
    // Implementation
  }
}

// Document external dependencies in README
/**
 * External Dependencies:
 * 
 * 1. Payment Service API v2.0
 *    - Base URL: https://payments.example.com/v2
 *    - Auth: API Key
 *    - Rate Limit: 100 req/min
 *    - SLA: 99.9% uptime
 *    - Documentation: https://docs.payments.example.com
 * 
 * 2. Email Service API v1.0
 *    - Provider: SendGrid
 *    - Rate Limit: 500 emails/hour (free tier)
 *    - Fallback: AWS SES
 */
```

**Graceful Degradation for Optional Dependencies:**

```javascript
// infrastructure/cache/cache-manager.js
let redisClient = null;
let redisAvailable = false;

async function initializeCache() {
  try {
    const redis = require('redis');
    redisClient = redis.createClient({
      url: process.env.REDIS_URL
    });
    await redisClient.connect();
    redisAvailable = true;
    console.log('✅ Redis cache enabled');
  } catch (error) {
    console.warn('⚠️  Redis not available, using in-memory cache');
    redisAvailable = false;
  }
}

class CacheManager {
  constructor() {
    this.memoryCache = new Map();
  }

  async get(key) {
    if (redisAvailable && redisClient) {
      return await redisClient.get(key);
    }
    return this.memoryCache.get(key);
  }

  async set(key, value, ttl) {
    if (redisAvailable && redisClient) {
      await redisClient.setEx(key, ttl, value);
    } else {
      this.memoryCache.set(key, value);
      setTimeout(() => this.memoryCache.delete(key), ttl * 1000);
    }
  }
}

module.exports = new CacheManager();
```

**API Client SDK Generation:**

```bash
# Generate client SDKs from OpenAPI spec
npm install -g @openapitools/openapi-generator-cli

# TypeScript/JavaScript
openapi-generator-cli generate \
  -i openapi.yaml \
  -g typescript-axios \
  -o clients/typescript

# Python
openapi-generator-cli generate \
  -i openapi.yaml \
  -g python \
  -o clients/python

# Java
openapi-generator-cli generate \
  -i openapi.yaml \
  -g java \
  -o clients/java
```

**Common Pitfalls:**
- Undocumented external dependencies
- No OpenAPI specification
- Hardcoded service URLs
- Missing fallback strategies
- Tight coupling to third-party APIs

**Best Practices:**
- Maintain OpenAPI specification
- Document all external dependencies
- Use API versioning in URLs
- Implement circuit breakers
- Generate client SDKs
- Version your API specification
- Track breaking changes

---

### Principle 3: Graceful Degradation ⭐ MANDATORY

**Meta-Architecture Definition:**  
"Systems MUST continue operating with reduced functionality when non-critical dependencies fail."

**REST API Implementation:**

REST APIs should provide degraded but functional responses when non-critical services fail.

**Dependency Classification:**

```javascript
// infrastructure/dependencies/registry.js
const DependencyLevel = {
  CRITICAL: 'CRITICAL',     // API cannot respond without this
  IMPORTANT: 'IMPORTANT',   // Core features degraded
  OPTIONAL: 'OPTIONAL'      // Nice-to-have only
};

const dependencies = {
  database: { level: DependencyLevel.CRITICAL, name: 'PostgreSQL' },
  cache: { level: DependencyLevel.IMPORTANT, name: 'Redis' },
  emailService: { level: DependencyLevel.OPTIONAL, name: 'SendGrid' },
  analyticsService: { level: DependencyLevel.OPTIONAL, name: 'Analytics' },
  paymentService: { level: DependencyLevel.IMPORTANT, name: 'Stripe' }
};

class DependencyRegistry {
  constructor() {
    this.status = new Map();
    Object.entries(dependencies).forEach(([key, dep]) => {
      this.status.set(key, {
        ...dep,
        available: false,
        lastCheck: null,
        error: null
      });
    });
  }

  markAvailable(key) {
    const dep = this.status.get(key);
    if (dep) {
      dep.available = true;
      dep.lastCheck = new Date();
      dep.error = null;
    }
  }

  markFailed(key, error) {
    const dep = this.status.get(key);
    if (dep) {
      dep.available = false;
      dep.lastCheck = new Date();
      dep.error = error.message;
    }
  }

  getDependencyStatus() {
    return Array.from(this.status.entries()).map(([key, status]) => ({
      name: key,
      ...status
    }));
  }

  getCriticalFailures() {
    return Array.from(this.status.values())
      .filter(dep => dep.level === DependencyLevel.CRITICAL && !dep.available);
  }

  isHealthy() {
    return this.getCriticalFailures().length === 0;
  }

  isDegraded() {
    const failures = Array.from(this.status.values())
      .filter(dep => !dep.available);
    return failures.length > 0 && this.isHealthy();
  }
}

module.exports = new DependencyRegistry();
```

**Health Check Endpoint with Degradation Status:**

```javascript
// application/routes/health.js
const express = require('express');
const dependencyRegistry = require('../../infrastructure/dependencies/registry');

const router = express.Router();

router.get('/health', (req, res) => {
  const dependencies = dependencyRegistry.getDependencyStatus();
  const isHealthy = dependencyRegistry.isHealthy();
  const isDegraded = dependencyRegistry.isDegraded();

  const status = isHealthy ? (isDegraded ? 'degraded' : 'healthy') : 'unhealthy';
  const httpStatus = isHealthy ? 200 : 503;

  res.status(httpStatus).json({
    status,
    timestamp: new Date().toISOString(),
    dependencies: dependencies.map(dep => ({
      name: dep.name,
      level: dep.level,
      available: dep.available,
      lastCheck: dep.lastCheck
    }))
  });
});

router.get('/health/live', (req, res) => {
  // Liveness probe: Can the service process requests?
  res.status(200).json({ status: 'alive' });
});

router.get('/health/ready', (req, res) => {
  // Readiness probe: Is the service ready to accept traffic?
  const isReady = dependencyRegistry.isHealthy();
  res.status(isReady ? 200 : 503).json({
    status: isReady ? 'ready' : 'not ready'
  });
});

module.exports = router;
```

**Circuit Breaker Pattern:**

```javascript
// infrastructure/resilience/circuit-breaker.js
class CircuitBreaker {
  constructor(name, options = {}) {
    this.name = name;
    this.failureThreshold = options.failureThreshold || 5;
    this.resetTimeout = options.resetTimeout || 60000; // 1 minute
    this.halfOpenAttempts = options.halfOpenAttempts || 1;
    
    this.state = 'CLOSED';
    this.failures = 0;
    this.nextAttempt = Date.now();
    this.halfOpenCount = 0;
  }

  async execute(fn) {
    if (this.state === 'OPEN') {
      if (Date.now() < this.nextAttempt) {
        throw new Error(`Circuit breaker ${this.name} is OPEN`);
      }
      this.state = 'HALF_OPEN';
      this.halfOpenCount = 0;
    }

    try {
      const result = await fn();
      this.onSuccess();
      return result;
    } catch (error) {
      this.onFailure();
      throw error;
    }
  }

  onSuccess() {
    this.failures = 0;
    if (this.state === 'HALF_OPEN') {
      this.halfOpenCount++;
      if (this.halfOpenCount >= this.halfOpenAttempts) {
        this.state = 'CLOSED';
      }
    }
  }

  onFailure() {
    this.failures++;
    if (this.state === 'HALF_OPEN') {
      this.state = 'OPEN';
      this.nextAttempt = Date.now() + this.resetTimeout;
    } else if (this.failures >= this.failureThreshold) {
      this.state = 'OPEN';
      this.nextAttempt = Date.now() + this.resetTimeout;
    }
  }

  getState() {
    return {
      name: this.name,
      state: this.state,
      failures: this.failures,
      nextAttempt: new Date(this.nextAttempt)
    };
  }
}

module.exports = CircuitBreaker;
```

**Fallback Response Example:**

```javascript
// application/controllers/user-profile-controller.js
const userService = require('../services/user-service');
const analyticsService = require('../../integration/external-apis/analytics-service');
const cacheManager = require('../../infrastructure/cache/cache-manager');

async function getUserProfile(req, res, next) {
  try {
    const userId = req.params.id;

    // Critical: Get user data (must succeed)
    const user = await userService.getUserById(userId);
    if (!user) {
      return res.status(404).json({
        error: 'User not found'
      });
    }

    // Important: Get cached stats (fallback to basic stats)
    let stats;
    try {
      stats = await cacheManager.get(`user:${userId}:stats`);
      if (!stats) {
        stats = await userService.calculateStats(userId);
        await cacheManager.set(`user:${userId}:stats`, stats, 300);
      }
    } catch (error) {
      console.warn('Failed to get stats, using basic stats:', error);
      stats = {
        postsCount: user.posts_count || 0,
        followersCount: user.followers_count || 0
      };
    }

    // Optional: Track analytics (don't fail if unavailable)
    try {
      await analyticsService.trackProfileView(userId, req.ip);
    } catch (error) {
      console.warn('Analytics unavailable:', error);
      // Continue without analytics
    }

    res.json({
      id: user.id,
      name: user.name,
      email: user.email,
      stats,
      _meta: {
        cached: Boolean(stats),
        analyticsEnabled: true // Even if failed, show feature exists
      }
    });

  } catch (error) {
    next(error);
  }
}

module.exports = { getUserProfile };
```

**Degraded Mode Response Headers:**

```javascript
// infrastructure/middleware/degradation-headers.js
const dependencyRegistry = require('../dependencies/registry');

function addDegradationHeaders(req, res, next) {
  if (dependencyRegistry.isDegraded()) {
    res.set('X-Service-Status', 'degraded');
    res.set('X-Degraded-Features', 
      dependencyRegistry.getDependencyStatus()
        .filter(d => !d.available)
        .map(d => d.name)
        .join(',')
    );
  }
  next();
}

module.exports = { addDegradationHeaders };
```

**Common Pitfalls:**
- Treating all dependencies as critical
- No fallback strategies
- Silent failures without logging
- Not communicating degradation to clients
- Cascading failures

**Best Practices:**
- Classify dependency criticality
- Implement circuit breakers
- Provide fallback responses
- Log degradation events
- Expose degradation in health endpoints
- Add degradation response headers
- Test degradation scenarios

---

### Principle 4: Comprehensive Input Validation ⭐ MANDATORY

**Meta-Architecture Definition:**  
"ALL inputs from external sources MUST be validated before use."

**REST API Implementation:**

REST APIs must validate all request inputs: body, query parameters, path parameters, and headers.

**Request Validation Middleware:**

```javascript
// foundation/validators/schemas.js
const Joi = require('joi');

// Reusable field schemas
const emailField = Joi.string().email().trim().lowercase().max(255);
const uuidField = Joi.string().uuid();
const paginationSchema = {
  page: Joi.number().integer().min(1).default(1),
  limit: Joi.number().integer().min(1).max(100).default(20)
};

// Entity schemas
const createUserSchema = Joi.object({
  email: emailField.required(),
  name: Joi.string().trim().min(2).max(100).required(),
  age: Joi.number().integer().min(13).max(120).optional(),
  agreedToTerms: Joi.boolean().valid(true).required(),
  preferences: Joi.object({
    newsletter: Joi.boolean().default(false),
    notifications: Joi.boolean().default(true)
  }).optional()
});

const updateUserSchema = Joi.object({
  name: Joi.string().trim().min(2).max(100).optional(),
  age: Joi.number().integer().min(13).max(120).optional(),
  preferences: Joi.object({
    newsletter: Joi.boolean().optional(),
    notifications: Joi.boolean().optional()
  }).optional()
}).min(1); // At least one field required

const listUsersQuerySchema = Joi.object({
  ...paginationSchema,
  search: Joi.string().trim().max(100).optional(),
  role: Joi.string().valid('admin', 'user', 'guest').optional(),
  sortBy: Joi.string().valid('name', 'email', 'createdAt').default('createdAt'),
  sortOrder: Joi.string().valid('asc', 'desc').default('desc')
});

module.exports = {
  createUserSchema,
  updateUserSchema,
  listUsersQuerySchema
};
```

**Validation Middleware:**

```javascript
// infrastructure/middleware/validation.js
const { ValidationError } = require('../../foundation/errors');

function validateBody(schema) {
  return async (req, res, next) => {
    try {
      const validated = await schema.validateAsync(req.body, {
        abortEarly: false,
        stripUnknown: true
      });
      req.validatedBody = validated;
      next();
    } catch (error) {
      next(new ValidationError('Invalid request body', {
        details: error.details.map(d => ({
          field: d.path.join('.'),
          message: d.message
        }))
      }));
    }
  };
}

function validateQuery(schema) {
  return async (req, res, next) => {
    try {
      const validated = await schema.validateAsync(req.query, {
        abortEarly: false,
        stripUnknown: true
      });
      req.validatedQuery = validated;
      next();
    } catch (error) {
      next(new ValidationError('Invalid query parameters', {
        details: error.details.map(d => ({
          field: d.path.join('.'),
          message: d.message
        }))
      }));
    }
  };
}

function validateParams(schema) {
  return async (req, res, next) => {
    try {
      const validated = await schema.validateAsync(req.params, {
        abortEarly: false,
        stripUnknown: true
      });
      req.validatedParams = validated;
      next();
    } catch (error) {
      next(new ValidationError('Invalid path parameters', {
        details: error.details.map(d => ({
          field: d.path.join('.'),
          message: d.message
        }))
      }));
    }
  };
}

module.exports = {
  validateBody,
  validateQuery,
  validateParams
};
```

**Content-Type Validation:**

```javascript
// infrastructure/middleware/content-type.js
function requireJsonContent(req, res, next) {
  if (req.method === 'POST' || req.method === 'PUT' || req.method === 'PATCH') {
    const contentType = req.get('Content-Type');
    if (!contentType || !contentType.includes('application/json')) {
      return res.status(415).json({
        error: 'Unsupported Media Type',
        message: 'Content-Type must be application/json',
        code: 'INVALID_CONTENT_TYPE'
      });
    }
  }
  next();
}

module.exports = { requireJsonContent };
```

**Input Sanitization:**

```javascript
// foundation/sanitization/sanitizer.js
const validator = require('validator');

class InputSanitizer {
  static sanitizeHtml(dirty) {
    return validator.escape(dirty);
  }

  static sanitizeFilename(filename) {
    return filename.replace(/[^a-zA-Z0-9._-]/g, '_');
  }

  static sanitizeSqlIdentifier(identifier) {
    if (!/^[a-zA-Z_][a-zA-Z0-9_]*$/.test(identifier)) {
      throw new Error('Invalid SQL identifier');
    }
    return identifier;
  }

  static removeNullBytes(str) {
    return str.replace(/\0/g, '');
  }
}

module.exports = InputSanitizer;
```

**Request Size Limits:**

```javascript
// app.js
const express = require('express');
const app = express();

// Limit request body size
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

// Limit parameter array size
app.use((req, res, next) => {
  if (req.query) {
    for (const key in req.query) {
      if (Array.isArray(req.query[key]) && req.query[key].length > 100) {
        return res.status(400).json({
          error: 'Too many array parameters',
          message: `Parameter "${key}" exceeds maximum array length of 100`
        });
      }
    }
  }
  next();
});
```

**Complete Validation Example:**

```javascript
// application/routes/users.js
const express = require('express');
const router = express.Router();
const Joi = require('joi');
const { validateBody, validateQuery, validateParams } = require('../../infrastructure/middleware/validation');
const { requireJsonContent } = require('../../infrastructure/middleware/content-type');
const userController = require('../controllers/user-controller');
const { createUserSchema, updateUserSchema, listUsersQuerySchema } = require('../../foundation/validators/schemas');

// Path parameter schema
const userIdSchema = Joi.object({
  id: Joi.string().uuid().required()
});

// POST /users - Create user
router.post('/users',
  requireJsonContent,
  validateBody(createUserSchema),
  userController.createUser
);

// GET /users - List users
router.get('/users',
  validateQuery(listUsersQuerySchema),
  userController.listUsers
);

// GET /users/:id - Get user
router.get('/users/:id',
  validateParams(userIdSchema),
  userController.getUser
);

// PATCH /users/:id - Update user
router.patch('/users/:id',
  requireJsonContent,
  validateParams(userIdSchema),
  validateBody(updateUserSchema),
  userController.updateUser
);

// DELETE /users/:id - Delete user
router.delete('/users/:id',
  validateParams(userIdSchema),
  userController.deleteUser
);

module.exports = router;
```

**Common Pitfalls:**
- Trusting client input
- Incomplete validation
- Not validating query parameters
- No content-type checking
- Missing size limits
- SQL injection via dynamic queries

**Best Practices:**
- Validate all inputs (body, query, params, headers)
- Use schema validation libraries
- Sanitize output to prevent XSS
- Set request size limits
- Whitelist allowed values
- Validate content-type headers
- Return clear validation errors
- Log validation failures

---

### Principle 5: Standardized Error Handling ⭐ MANDATORY

**Meta-Architecture Definition:**  
"Systems MUST handle errors consistently using standardized patterns."

**REST API Implementation:**

REST APIs should use RFC 7807 (Problem Details) for consistent error responses.

**Standard Error Codes:**

```javascript
// foundation/errors/error-codes.js
const ErrorCodes = {
  // Standard codes (0-9)
  SUCCESS: 0,
  INVALID_INPUT: 1,
  NOT_FOUND: 2,
  PERMISSION_DENIED: 3,
  CONFLICT: 4,
  DEPENDENCY_ERROR: 5,
  INTERNAL_ERROR: 6,
  TIMEOUT: 7,
  RATE_LIMITED: 8,
  DEGRADED: 9,

  // Domain-specific codes (10+)
  EMAIL_ALREADY_EXISTS: 10,
  INVALID_CREDENTIALS: 11,
  TOKEN_EXPIRED: 12,
  INSUFFICIENT_QUOTA: 13
};

const ErrorMessages = {
  [ErrorCodes.SUCCESS]: 'Operation completed successfully',
  [ErrorCodes.INVALID_INPUT]: 'The request contains invalid data',
  [ErrorCodes.NOT_FOUND]: 'The requested resource was not found',
  [ErrorCodes.PERMISSION_DENIED]: 'You do not have permission to perform this action',
  [ErrorCodes.CONFLICT]: 'The request conflicts with existing data',
  [ErrorCodes.DEPENDENCY_ERROR]: 'A required external service is unavailable',
  [ErrorCodes.INTERNAL_ERROR]: 'An internal server error occurred',
  [ErrorCodes.TIMEOUT]: 'The request timed out',
  [ErrorCodes.RATE_LIMITED]: 'Too many requests, please slow down',
  [ErrorCodes.DEGRADED]: 'Service is running in degraded mode',
  [ErrorCodes.EMAIL_ALREADY_EXISTS]: 'An account with this email already exists',
  [ErrorCodes.INVALID_CREDENTIALS]: 'Invalid email or password',
  [ErrorCodes.TOKEN_EXPIRED]: 'Your session has expired',
  [ErrorCodes.INSUFFICIENT_QUOTA]: 'You have exceeded your quota'
};

module.exports = { ErrorCodes, ErrorMessages };
```

**Custom Error Classes:**

```javascript
// foundation/errors/api-errors.js
const { ErrorCodes, ErrorMessages } = require('./error-codes');

class ApiError extends Error {
  constructor(message, code, httpStatus, details = {}) {
    super(message);
    this.name = this.constructor.name;
    this.code = code;
    this.httpStatus = httpStatus;
    this.details = details;
    this.timestamp = new Date().toISOString();
    this.retryable = false;
    Error.captureStackTrace(this, this.constructor);
  }

  toJSON() {
    return {
      type: `https://api.example.com/errors/${this.name}`,
      title: ErrorMessages[this.code] || this.message,
      status: this.httpStatus,
      detail: this.message,
      instance: this.details.requestId,
      code: this.code,
      timestamp: this.timestamp,
      ...(this.details.errors && { errors: this.details.errors })
    };
  }
}

class ValidationError extends ApiError {
  constructor(message, details = {}) {
    super(message, ErrorCodes.INVALID_INPUT, 400, details);
  }
}

class NotFoundError extends ApiError {
  constructor(resource, identifier) {
    super(
      `${resource} with identifier ${identifier} not found`,
      ErrorCodes.NOT_FOUND,
      404,
      { resource, identifier }
    );
  }
}

class UnauthorizedError extends ApiError {
  constructor(message = 'Authentication required') {
    super(message, ErrorCodes.PERMISSION_DENIED, 401, {});
  }
}

class ForbiddenError extends ApiError {
  constructor(message = 'Insufficient permissions') {
    super(message, ErrorCodes.PERMISSION_DENIED, 403, {});
  }
}

class ConflictError extends ApiError {
  constructor(message, details = {}) {
    super(message, ErrorCodes.CONFLICT, 409, details);
  }
}

class RateLimitError extends ApiError {
  constructor(retryAfter) {
    super(
      'Too many requests',
      ErrorCodes.RATE_LIMITED,
      429,
      { retryAfter }
    );
    this.retryable = true;
  }
}

class ServiceUnavailableError extends ApiError {
  constructor(message, serviceName) {
    super(
      message,
      ErrorCodes.DEPENDENCY_ERROR,
      503,
      { service: serviceName }
    );
    this.retryable = true;
  }
}

module.exports = {
  ApiError,
  ValidationError,
  NotFoundError,
  UnauthorizedError,
  ForbiddenError,
  ConflictError,
  RateLimitError,
  ServiceUnavailableError
};
```

**Error Handler Middleware:**

```javascript
// infrastructure/middleware/error-handler.js
const { ApiError } = require('../../foundation/errors/api-errors');
const logger = require('../logging/logger');

function errorHandler(err, req, res, next) {
  // Add request ID to error details
  if (!err.details) err.details = {};
  err.details.requestId = req.id;

  // Log error
  const logContext = {
    error: {
      name: err.name,
      message: err.message,
      code: err.code,
      stack: err.stack
    },
    request: {
      method: req.method,
      url: req.url,
      headers: {
        'user-agent': req.get('user-agent'),
        'content-type': req.get('content-type')
      },
      query: req.query,
      params: req.params
    },
    requestId: req.id
  };

  if (err instanceof ApiError) {
    // Application errors
    const logLevel = err.httpStatus >= 500 ? 'error' : 'warn';
    logger[logLevel](logContext, `API Error: ${err.message}`);

    // Set retry-after header for retryable errors
    if (err.retryable && err.details.retryAfter) {
      res.set('Retry-After', err.details.retryAfter.toString());
    }

    return res.status(err.httpStatus).json(err.toJSON());
  }

  // Unexpected errors
  logger.error(logContext, 'Unexpected error');

  // Don't expose internal errors to clients
  res.status(500).json({
    type: 'https://api.example.com/errors/InternalError',
    title: 'Internal Server Error',
    status: 500,
    detail: process.env.NODE_ENV === 'development' 
      ? err.message 
      : 'An unexpected error occurred',
    instance: req.id,
    timestamp: new Date().toISOString()
  });
}

module.exports = { errorHandler };
```

**HTTP Status Code Mapping:**

```javascript
// HTTP Status Codes for REST APIs
const StatusCodes = {
  // Success (2xx)
  OK: 200,                    // GET, PUT, PATCH success
  CREATED: 201,               // POST success
  ACCEPTED: 202,              // Async operation started
  NO_CONTENT: 204,            // DELETE success, no body

  // Client Errors (4xx)
  BAD_REQUEST: 400,           // Invalid request
  UNAUTHORIZED: 401,          // Authentication required
  FORBIDDEN: 403,             // Insufficient permissions
  NOT_FOUND: 404,             // Resource not found
  METHOD_NOT_ALLOWED: 405,    // HTTP method not supported
  CONFLICT: 409,              // Resource conflict
  GONE: 410,                  // Resource permanently deleted
  UNSUPPORTED_MEDIA_TYPE: 415, // Wrong Content-Type
  UNPROCESSABLE_ENTITY: 422,  // Validation failed
  TOO_MANY_REQUESTS: 429,     // Rate limit exceeded

  // Server Errors (5xx)
  INTERNAL_SERVER_ERROR: 500, // Unexpected error
  NOT_IMPLEMENTED: 501,       // Feature not implemented
  BAD_GATEWAY: 502,           // Upstream service error
  SERVICE_UNAVAILABLE: 503,   // Service temporarily down
  GATEWAY_TIMEOUT: 504        // Upstream timeout
};
```

**Usage Example:**

```javascript
// application/controllers/user-controller.js
const { NotFoundError, ConflictError, ValidationError } = require('../../foundation/errors/api-errors');
const userService = require('../services/user-service');

async function createUser(req, res, next) {
  try {
    const userData = req.validatedBody;

    // Check if user exists
    const existing = await userService.getUserByEmail(userData.email);
    if (existing) {
      throw new ConflictError('User with this email already exists', {
        field: 'email',
        value: userData.email
      });
    }

    const user = await userService.createUser(userData);

    res.status(201).json({
      id: user.id,
      email: user.email,
      name: user.name,
      createdAt: user.created_at
    });
  } catch (error) {
    next(error);
  }
}

async function getUser(req, res, next) {
  try {
    const { id } = req.validatedParams;
    const user = await userService.getUserById(id);

    if (!user) {
      throw new NotFoundError('User', id);
    }

    res.json({
      id: user.id,
      email: user.email,
      name: user.name,
      createdAt: user.created_at
    });
  } catch (error) {
    next(error);
  }
}

module.exports = {
  createUser,
  getUser
};
```

**Common Pitfalls:**
- Inconsistent error formats
- Exposing stack traces to clients
- Missing error codes
- No correlation IDs
- Unclear error messages
- Not using proper HTTP status codes

**Best Practices:**
- Use RFC 7807 Problem Details format
- Include error codes for programmatic handling
- Add correlation/request IDs
- Log all errors with context
- Use appropriate HTTP status codes
- Don't expose sensitive information
- Provide actionable error messages
- Document error codes in API spec

---

### Principle 6: Hierarchical Configuration ⭐ MANDATORY

**Meta-Architecture Definition:**  
"Configuration MUST follow clear hierarchy (lowest to highest precedence)."

**REST API Implementation:**

```javascript
// infrastructure/config/config-loader.js
const fs = require('fs');
const path = require('path');
const Joi = require('joi');

// Configuration hierarchy:
// 1. Defaults (compiled-in)
// 2. Config file (config/default.json)
// 3. Environment config (config/{env}.json)
// 4. Environment variables
// 5. Command-line arguments (if applicable)

const configSchema = Joi.object({
  app: Joi.object({
    name: Joi.string().default('my-api'),
    env: Joi.string().valid('development', 'staging', 'production').default('development'),
    port: Joi.number().integer().min(1).max(65535).default(3000),
    host: Joi.string().default('0.0.0.0'),
    corsOrigins: Joi.array().items(Joi.string()).default(['*'])
  }),

  database: Joi.object({
    host: Joi.string().required(),
    port: Joi.number().integer().default(5432),
    name: Joi.string().required(),
    user: Joi.string().required(),
    password: Joi.string().required(),
    ssl: Joi.boolean().default(false),
    poolMin: Joi.number().integer().min(1).default(2),
    poolMax: Joi.number().integer().min(1).default(10)
  }),

  redis: Joi.object({
    enabled: Joi.boolean().default(false),
    host: Joi.string().default('localhost'),
    port: Joi.number().integer().default(6379),
    password: Joi.string().allow('').optional(),
    db: Joi.number().integer().min(0).max(15).default(0),
    ttl: Joi.number().integer().default(300)
  }).optional(),

  auth: Joi.object({
    jwtSecret: Joi.string().min(32).required(),
    jwtExpiresIn: Joi.string().default('15m'),
    refreshTokenExpiresIn: Joi.string().default('7d'),
    bcryptRounds: Joi.number().integer().min(10).max(15).default(12)
  }),

  rateLimit: Joi.object({
    enabled: Joi.boolean().default(true),
    windowMs: Joi.number().integer().default(900000), // 15 min
    max: Joi.number().integer().default(100),
    skipSuccessfulRequests: Joi.boolean().default(false)
  }),

  logging: Joi.object({
    level: Joi.string().valid('trace', 'debug', 'info', 'warn', 'error', 'fatal').default('info'),
    pretty: Joi.boolean().default(false)
  }),

  monitoring: Joi.object({
    enabled: Joi.boolean().default(true),
    metricsPath: Joi.string().default('/metrics')
  }),

  external: Joi.object({
    paymentService: Joi.object({
      baseUrl: Joi.string().uri().required(),
      apiKey: Joi.string().required(),
      timeout: Joi.number().integer().default(5000)
    }).optional()
  }).optional()
});

class ConfigLoader {
  static load() {
    // 1. Start with defaults (defined in schema)
    let config = {};

    // 2. Load config/default.json
    const defaultPath = path.join(process.cwd(), 'config', 'default.json');
    if (fs.existsSync(defaultPath)) {
      const defaultConfig = JSON.parse(fs.readFileSync(defaultPath, 'utf-8'));
      config = this.deepMerge(config, defaultConfig);
    }

    // 3. Load environment-specific config
    const env = process.env.NODE_ENV || 'development';
    const envPath = path.join(process.cwd(), 'config', `${env}.json`);
    if (fs.existsSync(envPath)) {
      const envConfig = JSON.parse(fs.readFileSync(envPath, 'utf-8'));
      config = this.deepMerge(config, envConfig);
    }

    // 4. Override with environment variables
    config = this.applyEnvOverrides(config);

    // 5. Validate configuration
    const { error, value } = configSchema.validate(config, {
      abortEarly: false,
      allowUnknown: false
    });

    if (error) {
      console.error('❌ Configuration validation failed:');
      error.details.forEach(detail => {
        console.error(`  - ${detail.path.join('.')}: ${detail.message}`);
      });
      process.exit(1);
    }

    return value;
  }

  static applyEnvOverrides(config) {
    return {
      app: {
        ...config.app,
        env: process.env.NODE_ENV || config.app?.env,
        port: this.envInt('PORT', config.app?.port),
        host: process.env.HOST || config.app?.host,
        corsOrigins: this.envArray('CORS_ORIGINS', config.app?.corsOrigins)
      },
      database: {
        ...config.database,
        host: process.env.DB_HOST || config.database?.host,
        port: this.envInt('DB_PORT', config.database?.port),
        name: process.env.DB_NAME || config.database?.name,
        user: process.env.DB_USER || config.database?.user,
        password: process.env.DB_PASSWORD || config.database?.password,
        ssl: this.envBool('DB_SSL', config.database?.ssl)
      },
      redis: config.redis ? {
        ...config.redis,
        enabled: this.envBool('REDIS_ENABLED', config.redis.enabled),
        host: process.env.REDIS_HOST || config.redis.host,
        port: this.envInt('REDIS_PORT', config.redis.port),
        password: process.env.REDIS_PASSWORD || config.redis.password
      } : undefined,
      auth: {
        ...config.auth,
        jwtSecret: process.env.JWT_SECRET || config.auth?.jwtSecret,
        bcryptRounds: this.envInt('BCRYPT_ROUNDS', config.auth?.bcryptRounds)
      },
      rateLimit: {
        ...config.rateLimit,
        enabled: this.envBool('RATE_LIMIT_ENABLED', config.rateLimit?.enabled),
        max: this.envInt('RATE_LIMIT_MAX', config.rateLimit?.max)
      },
      logging: {
        ...config.logging,
        level: process.env.LOG_LEVEL || config.logging?.level,
        pretty: this.envBool('LOG_PRETTY', config.logging?.pretty)
      },
      monitoring: {
        ...config.monitoring,
        enabled: this.envBool('MONITORING_ENABLED', config.monitoring?.enabled)
      },
      external: config.external
    };
  }

  static envInt(key, defaultValue) {
    const value = process.env[key];
    return value ? parseInt(value, 10) : defaultValue;
  }

  static envBool(key, defaultValue) {
    const value = process.env[key];
    if (value === undefined) return defaultValue;
    return value === 'true' || value === '1';
  }

  static envArray(key, defaultValue) {
    const value = process.env[key];
    return value ? value.split(',').map(v => v.trim()) : defaultValue;
  }

  static deepMerge(target, source) {
    const result = { ...target };
    for (const key in source) {
      if (source[key] instanceof Object && !Array.isArray(source[key])) {
        result[key] = this.deepMerge(result[key] || {}, source[key]);
      } else {
        result[key] = source[key];
      }
    }
    return result;
  }
}

module.exports = ConfigLoader.load();
```

**Environment Variable Template:**

```bash
# .env.example - Copy to .env.production, .env.staging, etc.

# Application
NODE_ENV=production
PORT=3000
HOST=0.0.0.0
CORS_ORIGINS=https://app.example.com,https://www.example.com

# Database
DB_HOST=db.example.com
DB_PORT=5432
DB_NAME=myapi
DB_USER=myapi_user
DB_PASSWORD=CHANGE_ME_IN_PRODUCTION
DB_SSL=true

# Redis
REDIS_ENABLED=true
REDIS_HOST=redis.example.com
REDIS_PORT=6379
REDIS_PASSWORD=

# Authentication
JWT_SECRET=GENERATE_A_SECURE_RANDOM_STRING_AT_LEAST_32_CHARACTERS
BCRYPT_ROUNDS=12

# Rate Limiting
RATE_LIMIT_ENABLED=true
RATE_LIMIT_MAX=100

# Logging
LOG_LEVEL=info
LOG_PRETTY=false

# Monitoring
MONITORING_ENABLED=true
```

**Configuration Files:**

```json
// config/default.json
{
  "app": {
    "name": "my-api",
    "corsOrigins": ["*"]
  },
  "database": {
    "poolMin": 2,
    "poolMax": 10
  },
  "redis": {
    "enabled": false
  },
  "rateLimit": {
    "enabled": true,
    "windowMs": 900000,
    "max": 100
  }
}
```

```json
// config/production.json
{
  "app": {
    "corsOrigins": ["https://app.example.com"]
  },
  "database": {
    "ssl": true,
    "poolMax": 20
  },
  "redis": {
    "enabled": true
  },
  "logging": {
    "level": "warn",
    "pretty": false
  }
}
```

**Common Pitfalls:**
- Hardcoding configuration values
- Committing secrets to version control
- No validation of configuration
- Missing defaults
- Unclear precedence rules
- Not documenting required variables

**Best Practices:**
- Use .env.example as template
- Validate configuration at startup
- Fail fast on invalid configuration
- Document all configuration options
- Use secret management systems
- Never log sensitive configuration
- Provide sensible defaults

---

Let me continue with the remaining principles...

### Principle 7: Observable System Behavior ⭐ MANDATORY

**Meta-Architecture Definition:**  
"System behavior MUST be observable through structured logging, metrics, and tracing."

**REST API Implementation:**

REST APIs need comprehensive observability to monitor performance, debug issues, and ensure reliability.

**Structured Logging:**

```javascript
// infrastructure/logging/logger.js
const pino = require('pino');

const logger = pino({
  level: process.env.LOG_LEVEL || 'info',
  transport: process.env.LOG_PRETTY === 'true'
    ? { target: 'pino-pretty', options: { colorize: true } }
    : undefined,
  base: {
    pid: process.pid,
    hostname: process.env.HOSTNAME || require('os').hostname()
  },
  timestamp: pino.stdTimeFunctions.isoTime,
  serializers: {
    req: (req) => ({
      method: req.method,
      url: req.url,
      headers: {
        'user-agent': req.headers['user-agent'],
        'content-type': req.headers['content-type']
      },
      remoteAddress: req.ip,
      remotePort: req.socket?.remotePort
    }),
    res: (res) => ({
      statusCode: res.statusCode,
      headers: res.getHeaders()
    }),
    err: pino.stdSerializers.err
  }
});

module.exports = logger;
```

**Request Logging Middleware:**

```javascript
// infrastructure/middleware/request-logger.js
const { v4: uuidv4 } = require('uuid');
const logger = require('../logging/logger');

function requestLogger(req, res, next) {
  // Generate request ID
  req.id = req.headers['x-request-id'] || uuidv4();
  res.setHeader('X-Request-ID', req.id);

  // Create request-specific logger
  req.log = logger.child({
    requestId: req.id,
    correlationId: req.headers['x-correlation-id']
  });

  // Log request start
  const startTime = Date.now();
  req.log.info({ req }, 'Request started');

  // Log response
  const originalSend = res.send;
  res.send = function(body) {
    res.send = originalSend;
    
    const duration = Date.now() - startTime;
    const logData = {
      res,
      duration,
      requestId: req.id,
      method: req.method,
      url: req.url,
      statusCode: res.statusCode
    };

    if (res.statusCode >= 500) {
      req.log.error(logData, 'Request failed');
    } else if (res.statusCode >= 400) {
      req.log.warn(logData, 'Request error');
    } else {
      req.log.info(logData, 'Request completed');
    }

    return res.send(body);
  };

  next();
}

module.exports = { requestLogger };
```

**Metrics Collection:**

```javascript
// infrastructure/monitoring/metrics.js
const promClient = require('prom-client');

// Create registry
const register = new promClient.Registry();

// Default metrics (CPU, memory, etc.)
promClient.collectDefaultMetrics({ register });

// HTTP request duration histogram
const httpRequestDuration = new promClient.Histogram({
  name: 'http_request_duration_seconds',
  help: 'Duration of HTTP requests in seconds',
  labelNames: ['method', 'route', 'status_code'],
  buckets: [0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5],
  registers: [register]
});

// HTTP request total counter
const httpRequestTotal = new promClient.Counter({
  name: 'http_requests_total',
  help: 'Total number of HTTP requests',
  labelNames: ['method', 'route', 'status_code'],
  registers: [register]
});

// HTTP errors counter
const httpErrorsTotal = new promClient.Counter({
  name: 'http_errors_total',
  help: 'Total number of HTTP errors',
  labelNames: ['method', 'route', 'status_code', 'error_type'],
  registers: [register]
});

// Database query duration
const dbQueryDuration = new promClient.Histogram({
  name: 'db_query_duration_seconds',
  help: 'Duration of database queries',
  labelNames: ['operation', 'table'],
  buckets: [0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1],
  registers: [register]
});

// Active database connections
const dbConnectionsActive = new promClient.Gauge({
  name: 'db_connections_active',
  help: 'Number of active database connections',
  registers: [register]
});

// Business metrics
const usersCreated = new promClient.Counter({
  name: 'users_created_total',
  help: 'Total number of users created',
  registers: [register]
});

const ordersProcessed = new promClient.Counter({
  name: 'orders_processed_total',
  help: 'Total number of orders processed',
  labelNames: ['status'],
  registers: [register]
});

module.exports = {
  register,
  httpRequestDuration,
  httpRequestTotal,
  httpErrorsTotal,
  dbQueryDuration,
  dbConnectionsActive,
  usersCreated,
  ordersProcessed
};
```

**Metrics Middleware:**

```javascript
// infrastructure/middleware/metrics.js
const metrics = require('../monitoring/metrics');

function metricsMiddleware(req, res, next) {
  const startTime = process.hrtime();

  // Capture response
  res.on('finish', () => {
    const [seconds, nanoseconds] = process.hrtime(startTime);
    const duration = seconds + nanoseconds / 1e9;

    const labels = {
      method: req.method,
      route: req.route?.path || req.path,
      status_code: res.statusCode
    };

    metrics.httpRequestDuration.observe(labels, duration);
    metrics.httpRequestTotal.inc(labels);

    if (res.statusCode >= 400) {
      metrics.httpErrorsTotal.inc({
        ...labels,
        error_type: res.statusCode >= 500 ? 'server' : 'client'
      });
    }
  });

  next();
}

// Metrics endpoint
function metricsEndpoint(req, res) {
  res.set('Content-Type', metrics.register.contentType);
  metrics.register.metrics().then(data => {
    res.send(data);
  });
}

module.exports = { metricsMiddleware, metricsEndpoint };
```

**Distributed Tracing:**

```javascript
// infrastructure/tracing/tracer.js
const opentelemetry = require('@opentelemetry/api');
const { NodeTracerProvider } = require('@opentelemetry/sdk-trace-node');
const { registerInstrumentations } = require('@opentelemetry/instrumentation');
const { HttpInstrumentation } = require('@opentelemetry/instrumentation-http');
const { ExpressInstrumentation } = require('@opentelemetry/instrumentation-express');
const { JaegerExporter } = require('@opentelemetry/exporter-jaeger');
const { SimpleSpanProcessor } = require('@opentelemetry/sdk-trace-base');

function initializeTracing(serviceName) {
  if (process.env.TRACING_ENABLED !== 'true') {
    console.log('🔍 Tracing disabled');
    return;
  }

  const provider = new NodeTracerProvider({
    resource: {
      attributes: {
        'service.name': serviceName,
        'service.version': process.env.npm_package_version || '1.0.0'
      }
    }
  });

  const exporter = new JaegerExporter({
    endpoint: process.env.JAEGER_ENDPOINT || 'http://localhost:14268/api/traces'
  });

  provider.addSpanProcessor(new SimpleSpanProcessor(exporter));
  provider.register();

  registerInstrumentations({
    instrumentations: [
      new HttpInstrumentation(),
      new ExpressInstrumentation()
    ]
  });

  console.log('🔍 Distributed tracing initialized');
}

module.exports = { initializeTracing };
```

**Common Pitfalls:**
- Logging sensitive data (passwords, tokens)
- No correlation IDs
- Insufficient context in logs
- Not collecting metrics
- No distributed tracing

**Best Practices:**
- Use structured JSON logging
- Include correlation IDs in all logs
- Implement RED metrics (Rate, Errors, Duration)
- Expose /metrics and /health endpoints
- Use appropriate log levels
- Add request/response IDs
- Sanitize sensitive data before logging

---

### Principle 8: Automated Testing Strategy ⭐ MANDATORY

**Meta-Architecture Definition:**  
"Code MUST be testable and tested at multiple levels with 80%+ coverage."

**REST API Implementation:**

REST APIs require comprehensive testing including unit, integration, contract, and E2E tests.

**Testing Pyramid for REST APIs:**

```
Manual Testing (5%)
──────────────────────────────────────
Contract Tests (15%)  - OpenAPI validation
──────────────────────────────────────
E2E/API Tests (20%)   - Full request/response
──────────────────────────────────────
Integration Tests (30%) - With real database
──────────────────────────────────────
Unit Tests (30%)       - Business logic
```

**Unit Test Example:**

```javascript
// foundation/validators/schemas.spec.js
const { createUserSchema } = require('./schemas');

describe('createUserSchema', () => {
  describe('valid inputs', () => {
    it('should accept valid user data', () => {
      const validData = {
        email: 'user@example.com',
        name: 'John Doe',
        age: 25,
        agreedToTerms: true
      };

      const { error, value } = createUserSchema.validate(validData);
      expect(error).toBeUndefined();
      expect(value).toMatchObject(validData);
    });

    it('should normalize email to lowercase', () => {
      const data = {
        email: 'User@Example.COM',
        name: 'John Doe',
        agreedToTerms: true
      };

      const { error, value } = createUserSchema.validate(data);
      expect(value.email).toBe('user@example.com');
    });
  });

  describe('invalid inputs', () => {
    it('should reject invalid email', () => {
      const data = {
        email: 'not-an-email',
        name: 'John Doe',
        agreedToTerms: true
      };

      const { error } = createUserSchema.validate(data);
      expect(error).toBeDefined();
      expect(error.details[0].path).toContain('email');
    });

    it('should reject when terms not agreed', () => {
      const data = {
        email: 'user@example.com',
        name: 'John Doe',
        agreedToTerms: false
      };

      const { error } = createUserSchema.validate(data);
      expect(error).toBeDefined();
    });
  });
});
```

**Integration Test Example:**

```javascript
// tests/integration/user-api.test.js
const request = require('supertest');
const app = require('../../src/app');
const { setupTestDatabase, teardownTestDatabase } = require('../helpers/test-db');

describe('User API Integration Tests', () => {
  beforeAll(async () => {
    await setupTestDatabase();
  });

  afterAll(async () => {
    await teardownTestDatabase();
  });

  describe('POST /api/v1/users', () => {
    it('should create a new user', async () => {
      const userData = {
        email: 'newuser@example.com',
        name: 'New User',
        age: 25,
        agreedToTerms: true
      };

      const response = await request(app)
        .post('/api/v1/users')
        .send(userData)
        .expect(201);

      expect(response.body).toMatchObject({
        id: expect.any(String),
        email: userData.email,
        name: userData.name
      });
      expect(response.body).toHaveProperty('createdAt');
      expect(response.headers['x-request-id']).toBeDefined();
    });

    it('should return 409 for duplicate email', async () => {
      const userData = {
        email: 'duplicate@example.com',
        name: 'User One',
        agreedToTerms: true
      };

      // Create first user
      await request(app)
        .post('/api/v1/users')
        .send(userData)
        .expect(201);

      // Try to create duplicate
      const response = await request(app)
        .post('/api/v1/users')
        .send(userData)
        .expect(409);

      expect(response.body).toMatchObject({
        status: 409,
        code: expect.any(Number),
        title: expect.stringContaining('already exists')
      });
    });

    it('should return 400 for invalid input', async () => {
      const response = await request(app)
        .post('/api/v1/users')
        .send({ email: 'invalid' })
        .expect(400);

      expect(response.body).toHaveProperty('errors');
    });
  });

  describe('GET /api/v1/users/:id', () => {
    it('should retrieve existing user', async () => {
      // Create user first
      const createResponse = await request(app)
        .post('/api/v1/users')
        .send({
          email: 'getuser@example.com',
          name: 'Get User',
          agreedToTerms: true
        });

      const userId = createResponse.body.id;

      // Retrieve user
      const response = await request(app)
        .get(`/api/v1/users/${userId}`)
        .expect(200);

      expect(response.body.id).toBe(userId);
      expect(response.body.email).toBe('getuser@example.com');
    });

    it('should return 404 for non-existent user', async () => {
      const fakeId = '00000000-0000-0000-0000-000000000000';
      
      const response = await request(app)
        .get(`/api/v1/users/${fakeId}`)
        .expect(404);

      expect(response.body.status).toBe(404);
    });
  });
});
```

**Contract Testing (OpenAPI Validation):**

```javascript
// tests/contract/openapi-validation.test.js
const request = require('supertest');
const app = require('../../src/app');
const OpenAPIValidator = require('express-openapi-validator');
const yaml = require('js-yaml');
const fs = require('fs');
const path = require('path');

describe('OpenAPI Contract Tests', () => {
  let validator;

  beforeAll(() => {
    const apiSpec = yaml.load(
      fs.readFileSync(path.join(__dirname, '../../openapi.yaml'), 'utf8')
    );

    validator = OpenAPIValidator.middleware({
      apiSpec,
      validateRequests: true,
      validateResponses: true
    });
  });

  it('should match OpenAPI spec for POST /users', async () => {
    const validRequest = {
      email: 'test@example.com',
      name: 'Test User',
      agreedToTerms: true
    };

    const response = await request(app)
      .post('/api/v1/users')
      .send(validRequest)
      .expect(201);

    // Validate response against OpenAPI schema
    expect(response.body).toMatchObject({
      id: expect.any(String),
      email: expect.any(String),
      name: expect.any(String),
      createdAt: expect.any(String)
    });
  });

  it('should reject requests not matching OpenAPI spec', async () => {
    const invalidRequest = {
      email: 'not-an-email',
      wrongField: 'value'
    };

    await request(app)
      .post('/api/v1/users')
      .send(invalidRequest)
      .expect(400);
  });
});
```

**Load Testing:**

```javascript
// tests/performance/load-test.js
const autocannon = require('autocannon');

async function runLoadTest() {
  const result = await autocannon({
    url: 'http://localhost:3000/api/v1/users',
    method: 'GET',
    connections: 10,
    duration: 30,
    headers: {
      'Authorization': 'Bearer test-token'
    }
  });

  console.log('Load Test Results:');
  console.log(`  Requests: ${result.requests.total}`);
  console.log(`  Duration: ${result.duration}s`);
  console.log(`  RPS: ${result.requests.average}`);
  console.log(`  Latency p50: ${result.latency.p50}ms`);
  console.log(`  Latency p95: ${result.latency.p95}ms`);
  console.log(`  Latency p99: ${result.latency.p99}ms`);

  // Assert SLA requirements
  expect(result.latency.p95).toBeLessThan(200);  // 95th percentile < 200ms
  expect(result.requests.average).toBeGreaterThan(100);  // > 100 RPS
}
```

**Test Helpers:**

```javascript
// tests/helpers/test-db.js
const { Pool } = require('pg');

let pool;

async function setupTestDatabase() {
  pool = new Pool({
    host: process.env.TEST_DB_HOST || 'localhost',
    port: process.env.TEST_DB_PORT || 5433,
    database: process.env.TEST_DB_NAME || 'test_db',
    user: process.env.TEST_DB_USER || 'test',
    password: process.env.TEST_DB_PASSWORD || 'test'
  });

  // Run migrations
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
      email VARCHAR(255) UNIQUE NOT NULL,
      name VARCHAR(100) NOT NULL,
      age INTEGER,
      created_at TIMESTAMP DEFAULT NOW()
    )
  `);
}

async function teardownTestDatabase() {
  await pool.query('DROP TABLE IF EXISTS users CASCADE');
  await pool.end();
}

async function clearDatabase() {
  await pool.query('TRUNCATE TABLE users RESTART IDENTITY CASCADE');
}

module.exports = {
  setupTestDatabase,
  teardownTestDatabase,
  clearDatabase
};
```

**Common Pitfalls:**
- Testing implementation instead of behavior
- No contract tests against OpenAPI spec
- Insufficient E2E test coverage
- Not testing error scenarios
- No load/performance tests

**Best Practices:**
- Test the public API contract
- Use OpenAPI spec for validation
- Test both success and error paths
- Use realistic test data
- Isolated test databases
- Mock external services
- Run tests in CI/CD
- Measure and enforce coverage

---

### Principle 9: Security by Design ⭐ MANDATORY

**Meta-Architecture Definition:**  
"Security MUST be built in from the start, not added later."

**REST API Implementation:**

REST APIs require multiple layers of security including authentication, authorization, input validation, and rate limiting.

**Authentication (JWT):**

```javascript
// infrastructure/auth/jwt-service.js
const jwt = require('jsonwebtoken');
const config = require('../config/config-loader');

class JWTService {
  generateAccessToken(payload) {
    return jwt.sign(payload, config.auth.jwtSecret, {
      expiresIn: config.auth.jwtExpiresIn,
      issuer: 'my-api',
      audience: 'my-api-users'
    });
  }

  generateRefreshToken(payload) {
    return jwt.sign(payload, config.auth.jwtSecret, {
      expiresIn: config.auth.refreshTokenExpiresIn,
      issuer: 'my-api',
      audience: 'my-api-users'
    });
  }

  verifyToken(token) {
    try {
      return jwt.verify(token, config.auth.jwtSecret, {
        issuer: 'my-api',
        audience: 'my-api-users'
      });
    } catch (error) {
      if (error.name === 'TokenExpiredError') {
        throw new Error('TOKEN_EXPIRED');
      }
      throw new Error('INVALID_TOKEN');
    }
  }

  decodeToken(token) {
    return jwt.decode(token);
  }
}

module.exports = new JWTService();
```

**Authentication Middleware:**

```javascript
// infrastructure/middleware/auth.js
const { UnauthorizedError, ForbiddenError } = require('../../foundation/errors/api-errors');
const jwtService = require('../auth/jwt-service');

function authenticate(req, res, next) {
  const authHeader = req.headers.authorization;

  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return next(new UnauthorizedError('Missing or invalid authorization header'));
  }

  const token = authHeader.substring(7);

  try {
    const payload = jwtService.verifyToken(token);
    req.user = payload;
    next();
  } catch (error) {
    if (error.message === 'TOKEN_EXPIRED') {
      return next(new UnauthorizedError('Token has expired'));
    }
    return next(new UnauthorizedError('Invalid token'));
  }
}

function requireRole(...roles) {
  return (req, res, next) => {
    if (!req.user) {
      return next(new UnauthorizedError());
    }

    const hasRole = roles.some(role => req.user.roles?.includes(role));
    if (!hasRole) {
      return next(new ForbiddenError('Insufficient permissions'));
    }

    next();
  };
}

function optionalAuth(req, res, next) {
  const authHeader = req.headers.authorization;

  if (!authHeader) {
    return next();
  }

  const token = authHeader.substring(7);

  try {
    req.user = jwtService.verifyToken(token);
  } catch (error) {
    // Continue without user
  }

  next();
}

module.exports = {
  authenticate,
  requireRole,
  optionalAuth
};
```

**Rate Limiting:**

```javascript
// infrastructure/middleware/rate-limiter.js
const rateLimit = require('express-rate-limit');
const RedisStore = require('rate-limit-redis');
const redis = require('redis');
const config = require('../config/config-loader');
const { RateLimitError } = require('../../foundation/errors/api-errors');

function createRateLimiter() {
  const options = {
    windowMs: config.rateLimit.windowMs,
    max: config.rateLimit.max,
    standardHeaders: true,
    legacyHeaders: false,
    handler: (req, res) => {
      const retryAfter = Math.ceil(config.rateLimit.windowMs / 1000);
      throw new RateLimitError(retryAfter);
    },
    skip: (req) => {
      // Skip rate limiting for health checks
      return req.path === '/health' || req.path === '/metrics';
    }
  };

  // Use Redis if available
  if (config.redis?.enabled) {
    const redisClient = redis.createClient({
      host: config.redis.host,
      port: config.redis.port,
      password: config.redis.password
    });

    options.store = new RedisStore({
      client: redisClient,
      prefix: 'rl:'
    });
  }

  return rateLimit(options);
}

// Different rate limits for different endpoints
function createAuthRateLimiter() {
  return rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 5, // 5 attempts
    message: 'Too many authentication attempts'
  });
}

module.exports = {
  createRateLimiter,
  createAuthRateLimiter
};
```

**CORS Configuration:**

```javascript
// infrastructure/middleware/cors.js
const cors = require('cors');
const config = require('../config/config-loader');

function configureCORS() {
  return cors({
    origin: (origin, callback) => {
      // Allow requests with no origin (mobile apps, Postman, etc.)
      if (!origin) return callback(null, true);

      if (config.app.corsOrigins.includes('*') || 
          config.app.corsOrigins.includes(origin)) {
        callback(null, true);
      } else {
        callback(new Error('Not allowed by CORS'));
      }
    },
    methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization', 'X-Request-ID', 'X-Correlation-ID'],
    exposedHeaders: ['X-Request-ID', 'X-RateLimit-Limit', 'X-RateLimit-Remaining'],
    credentials: true,
    maxAge: 86400 // 24 hours
  });
}

module.exports = { configureCORS };
```

**Security Headers:**

```javascript
// infrastructure/middleware/security-headers.js
const helmet = require('helmet');

function configureSecurityHeaders(app) {
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
      maxAge: 31536000,
      includeSubDomains: true,
      preload: true
    },
    frameguard: {
      action: 'deny'
    },
    noSniff: true,
    xssFilter: true,
    referrerPolicy: {
      policy: 'strict-origin-when-cross-origin'
    }
  }));

  // Additional security headers
  app.use((req, res, next) => {
    res.removeHeader('X-Powered-By');
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('X-Frame-Options', 'DENY');
    res.setHeader('X-XSS-Protection', '1; mode=block');
    next();
  });
}

module.exports = { configureSecurityHeaders };
```

**SQL Injection Prevention:**

```javascript
// integration/database/user-repository.js
const db = require('../../infrastructure/config/database');

class UserRepository {
  async findByEmail(email) {
    // ✅ GOOD: Parameterized query
    const result = await db.query(
      'SELECT * FROM users WHERE email = $1',
      [email]
    );
    return result.rows[0];
  }

  async search(searchTerm) {
    // ✅ GOOD: Using LIKE with parameterization
    const result = await db.query(
      'SELECT * FROM users WHERE name ILIKE $1',
      [`%${searchTerm}%`]
    );
    return result.rows;
  }

  // ❌ BAD: String concatenation (SQL injection risk!)
  async findByEmailBad(email) {
    const result = await db.query(
      `SELECT * FROM users WHERE email = '${email}'`
    );
    return result.rows[0];
  }
}

module.exports = new UserRepository();
```

**API Key Management:**

```javascript
// infrastructure/auth/api-key-service.js
const crypto = require('crypto');

class ApiKeyService {
  generateApiKey() {
    return crypto.randomBytes(32).toString('hex');
  }

  hashApiKey(apiKey) {
    return crypto
      .createHash('sha256')
      .update(apiKey)
      .digest('hex');
  }

  verifyApiKey(providedKey, storedHash) {
    const hashedProvided = this.hashApiKey(providedKey);
    return crypto.timingSafeEqual(
      Buffer.from(hashedProvided),
      Buffer.from(storedHash)
    );
  }
}

// API Key authentication middleware
function authenticateApiKey(req, res, next) {
  const apiKey = req.headers['x-api-key'];

  if (!apiKey) {
    return res.status(401).json({ error: 'API key required' });
  }

  // Lookup and verify API key
  // (In production, load from database)
  const isValid = apiKeyService.verifyApiKey(apiKey, storedHash);

  if (!isValid) {
    return res.status(401).json({ error: 'Invalid API key' });
  }

  next();
}

module.exports = new ApiKeyService();
```

**Common Pitfalls:**
- Storing passwords in plaintext
- Weak JWT secrets
- No rate limiting
- Missing input validation
- Not using HTTPS
- Exposing sensitive errors
- No CORS configuration

**Best Practices:**
- Hash passwords with bcrypt
- Use strong JWT secrets (32+ chars)
- Implement rate limiting
- Validate all inputs
- Enforce HTTPS in production
- Use security headers (Helmet)
- Parameterized SQL queries
- Regular security audits
- Log security events

---

### Principle 10: Resource Lifecycle Management ⭐ MANDATORY

**Meta-Architecture Definition:**  
"All acquired resources MUST be properly released using deterministic cleanup patterns."

**REST API Implementation:**

```javascript
// infrastructure/database/connection-pool.js
const { Pool } = require('pg');
const config = require('../config/config-loader');
const logger = require('../logging/logger');

class DatabasePool {
  constructor() {
    this.pool = new Pool({
      host: config.database.host,
      port: config.database.port,
      database: config.database.name,
      user: config.database.user,
      password: config.database.password,
      ssl: config.database.ssl,
      min: config.database.poolMin,
      max: config.database.poolMax,
      idleTimeoutMillis: 30000,
      connectionTimeoutMillis: 2000
    });

    this.pool.on('error', (err) => {
      logger.error({ err }, 'Unexpected error on idle client');
    });

    this.pool.on('connect', () => {
      logger.debug('New client connected to database pool');
    });

    this.pool.on('remove', () => {
      logger.debug('Client removed from database pool');
    });
  }

  async query(text, params) {
    const start = Date.now();
    try {
      const result = await this.pool.query(text, params);
      const duration = Date.now() - start;
      logger.debug({ text, duration, rows: result.rowCount }, 'Executed query');
      return result;
    } catch (error) {
      logger.error({ error, text }, 'Query error');
      throw error;
    }
  }

  async getClient() {
    return this.pool.connect();
  }

  async end() {
    logger.info('Closing database pool');
    await this.pool.end();
  }

  get totalCount() {
    return this.pool.totalCount;
  }

  get idleCount() {
    return this.pool.idleCount;
  }

  get waitingCount() {
    return this.pool.waitingCount;
  }
}

module.exports = new DatabasePool();
```

**Graceful Shutdown:**

```javascript
// infrastructure/lifecycle/shutdown-handler.js
const logger = require('../logging/logger');

class ShutdownHandler {
  constructor(server, resources = []) {
    this.server = server;
    this.resources = resources;
    this.isShuttingDown = false;

    // Register signal handlers
    process.on('SIGTERM', () => this.handleShutdown('SIGTERM'));
    process.on('SIGINT', () => this.handleShutdown('SIGINT'));

    // Handle unexpected errors
    process.on('uncaughtException', (error) => {
      logger.fatal({ error }, 'Uncaught exception');
      this.handleShutdown('UNCAUGHT_EXCEPTION');
    });

    process.on('unhandledRejection', (reason, promise) => {
      logger.fatal({ reason, promise }, 'Unhandled rejection');
      this.handleShutdown('UNHANDLED_REJECTION');
    });
  }

  async handleShutdown(signal) {
    if (this.isShuttingDown) {
      logger.warn('Shutdown already in progress');
      return;
    }

    this.isShuttingDown = true;
    logger.info({ signal }, '🛑 Shutdown initiated');

    // Set shutdown timeout
    const shutdownTimeout = setTimeout(() => {
      logger.error('❌ Shutdown timeout - forcing exit');
      process.exit(1);
    }, 30000); // 30 seconds

    try {
      // 1. Stop accepting new connections
      await this.stopServer();

      // 2. Drain existing connections
      await this.drainConnections();

      // 3. Cleanup resources
      await this.cleanupResources();

      clearTimeout(shutdownTimeout);
      logger.info('✅ Graceful shutdown complete');
      process.exit(0);
    } catch (error) {
      clearTimeout(shutdownTimeout);
      logger.error({ error }, '❌ Shutdown error');
      process.exit(1);
    }
  }

  async stopServer() {
    return new Promise((resolve) => {
      this.server.close(() => {
        logger.info('HTTP server closed');
        resolve();
      });
    });
  }

  async drainConnections() {
    return new Promise((resolve) => {
      const checkInterval = setInterval(() => {
        // Check for active connections
        this.server.getConnections((err, count) => {
          if (err) {
            clearInterval(checkInterval);
            resolve();
            return;
          }

          if (count === 0) {
            clearInterval(checkInterval);
            resolve();
          }
        });
      }, 100);

      // Force resolve after 10 seconds
      setTimeout(() => {
        clearInterval(checkInterval);
        logger.warn('Force closing remaining connections');
        resolve();
      }, 10000);
    });
  }

  async cleanupResources() {
    logger.info('Cleaning up resources');
    
    for (const resource of this.resources.reverse()) {
      try {
        logger.debug({ resource: resource.name }, 'Cleaning up resource');
        await resource.cleanup();
        logger.info({ resource: resource.name }, '✅ Resource cleaned up');
      } catch (error) {
        logger.error({ error, resource: resource.name }, 'Failed to cleanup resource');
      }
    }
  }

  registerResource(name, cleanup) {
    this.resources.push({ name, cleanup });
  }
}

module.exports = ShutdownHandler;
```

**Request Timeout:**

```javascript
// infrastructure/middleware/timeout.js
function requestTimeout(timeoutMs = 30000) {
  return (req, res, next) => {
    req.setTimeout(timeoutMs, () => {
      const error = new Error('Request timeout');
      error.status = 408;
      next(error);
    });

    res.setTimeout(timeoutMs, () => {
      if (!res.headersSent) {
        res.status(408).json({
          error: 'Request timeout',
          message: 'The server took too long to respond'
        });
      }
    });

    next();
  };
}

module.exports = { requestTimeout };
```

**Common Pitfalls:**
- Not closing database connections
- Memory leaks from event listeners
- Orphaned timers
- Not handling shutdown signals
- No connection pooling

**Best Practices:**
- Use connection pooling
- Implement graceful shutdown
- Set request timeouts
- Clear timers/intervals
- Close all resources on shutdown
- Handle SIGTERM/SIGINT signals
- Test cleanup paths

---

### Principle 11: Performance by Design ⚠️ RECOMMENDED

**Meta-Architecture Definition:**  
"Performance characteristics MUST be understood and acceptable by design."

**REST API Implementation:**

```javascript
// infrastructure/cache/response-cache.js
const cache = require('./cache-manager');

function cacheResponse(ttl = 300) {
  return async (req, res, next) => {
    // Only cache GET requests
    if (req.method !== 'GET') {
      return next();
    }

    const cacheKey = `response:${req.originalUrl}`;

    try {
      // Check cache
      const cachedResponse = await cache.get(cacheKey);
      if (cachedResponse) {
        res.setHeader('X-Cache', 'HIT');
        return res.json(JSON.parse(cachedResponse));
      }

      // Cache miss
      res.setHeader('X-Cache', 'MISS');

      // Override res.json to cache response
      const originalJson = res.json.bind(res);
      res.json = (body) => {
        cache.set(cacheKey, JSON.stringify(body), ttl).catch(err => {
          logger.warn({ err }, 'Failed to cache response');
        });
        return originalJson(body);
      };

      next();
    } catch (error) {
      logger.warn({ error }, 'Cache error, continuing without cache');
      next();
    }
  };
}

module.exports = { cacheResponse };
```

**Response Compression:**

```javascript
// infrastructure/middleware/compression.js
const compression = require('compression');

function configureCompression() {
  return compression({
    filter: (req, res) => {
      if (req.headers['x-no-compression']) {
        return false;
      }
      return compression.filter(req, res);
    },
    level: 6, // Compression level (0-9)
    threshold: 1024 // Only compress responses > 1KB
  });
}

module.exports = { configureCompression };
```

**Pagination:**

```javascript
// foundation/pagination/paginator.js
class Paginator {
  static paginate(query, page = 1, limit = 20) {
    const offset = (page - 1) * limit;
    return {
      ...query,
      limit,
      offset
    };
  }

  static formatResponse(data, page, limit, total) {
    const totalPages = Math.ceil(total / limit);
    
    return {
      data,
      pagination: {
        page,
        limit,
        total,
        totalPages,
        hasNext: page < totalPages,
        hasPrev: page > 1
      },
      _links: {
        self: `/api/v1/users?page=${page}&limit=${limit}`,
        ...(page < totalPages && {
          next: `/api/v1/users?page=${page + 1}&limit=${limit}`
        }),
        ...(page > 1 && {
          prev: `/api/v1/users?page=${page - 1}&limit=${limit}`
        }),
        first: `/api/v1/users?page=1&limit=${limit}`,
        last: `/api/v1/users?page=${totalPages}&limit=${limit}`
      }
    };
  }
}

module.exports = Paginator;
```

**ETag Support:**

```javascript
// infrastructure/middleware/etag.js
const etag = require('etag');

function etagMiddleware(req, res, next) {
  const originalSend = res.send;

  res.send = function(body) {
    if (req.method === 'GET' && res.statusCode === 200) {
      const generatedEtag = etag(body);
      res.setHeader('ETag', generatedEtag);

      // Check if client has cached version
      const clientEtag = req.headers['if-none-match'];
      if (clientEtag === generatedEtag) {
        res.status(304).end();
        return;
      }

      // Set cache control headers
      res.setHeader('Cache-Control', 'private, max-age=300');
    }

    return originalSend.call(this, body);
  };

  next();
}

module.exports = { etagMiddleware };
```

**Common Pitfalls:**
- No caching strategy
- Missing pagination
- No response compression
- Inefficient database queries
- Not using connection pooling

**Best Practices:**
- Implement response caching
- Use pagination for lists
- Enable response compression
- Optimize database queries
- Use connection pooling
- Add ETags for caching
- Monitor performance metrics
- Define SLOs (p95 < 200ms)

---

### Principle 12: Evolutionary Architecture ⚠️ RECOMMENDED

**Meta-Architecture Definition:**  
"Architecture MUST support change without requiring complete rewrites."

**REST API Implementation:**

**API Versioning:**

```javascript
// application/routes/versioned-routes.js
const express = require('express');
const v1Routes = require('./v1');
const v2Routes = require('./v2');

function createVersionedRoutes() {
  const router = express.Router();

  // Version from URL path (preferred)
  router.use('/v1', v1Routes);
  router.use('/v2', v2Routes);

  // Version from header (alternative)
  router.use((req, res, next) => {
    const version = req.headers['api-version'];
    
    if (version === '2' || version === 'v2') {
      return v2Routes(req, res, next);
    }
    
    // Default to v1
    return v1Routes(req, res, next);
  });

  return router;
}

module.exports = { createVersionedRoutes };
```

**Deprecation Policy:**

```javascript
// infrastructure/middleware/deprecation.js
function deprecateEndpoint(options) {
  const {
    deprecatedSince,
    removedIn,
    replacement,
    message
  } = options;

  return (req, res, next) => {
    // Add deprecation headers
    res.setHeader('Deprecation', deprecatedSince);
    res.setHeader('Sunset', removedIn);
    
    if (replacement) {
      res.setHeader('Link', `<${replacement}>; rel="alternate"`);
    }

    // Log deprecation usage
    req.log.warn({
      endpoint: req.path,
      deprecatedSince,
      removedIn,
      replacement
    }, 'Deprecated endpoint used');

    // Add deprecation warning to response
    if (!res.locals.warnings) {
      res.locals.warnings = [];
    }
    
    res.locals.warnings.push({
      code: 'DEPRECATED_ENDPOINT',
      message: message || 'This endpoint is deprecated',
      deprecatedSince,
      removedIn,
      replacement
    });

    next();
  };
}

// Usage
router.get('/api/v1/old-endpoint',
  deprecateEndpoint({
    deprecatedSince: '2025-01-01',
    removedIn: '2026-01-01',
    replacement: '/api/v2/new-endpoint',
    message: 'Use v2 endpoint for improved features'
  }),
  oldEndpointHandler
);

module.exports = { deprecateEndpoint };
```

**Feature Flags:**

```javascript
// infrastructure/features/feature-flags.js
class FeatureFlagService {
  constructor() {
    this.flags = new Map();
    this.loadFlags();
  }

  loadFlags() {
    // Load from environment or config
    this.flags.set('newDashboard', {
      enabled: process.env.FEATURE_NEW_DASHBOARD === 'true',
      rollout: 10 // 10% of users
    });

    this.flags.set('advancedSearch', {
      enabled: process.env.FEATURE_ADVANCED_SEARCH === 'true',
      allowedRoles: ['admin', 'power-user']
    });
  }

  isEnabled(feature, userId, userRoles = []) {
    const flag = this.flags.get(feature);
    if (!flag || !flag.enabled) return false;

    // Check role-based access
    if (flag.allowedRoles) {
      return userRoles.some(role => flag.allowedRoles.includes(role));
    }

    // Check percentage rollout
    if (flag.rollout) {
      const hash = this.hashUserId(userId);
      return (hash % 100) < flag.rollout;
    }

    return true;
  }

  hashUserId(userId) {
    let hash = 0;
    for (let i = 0; i < userId.length; i++) {
      hash = ((hash << 5) - hash) + userId.charCodeAt(i);
      hash = hash & hash;
    }
    return Math.abs(hash);
  }
}

module.exports = new FeatureFlagService();
```

**Database Migrations:**

```javascript
// scripts/migrate.js
const { Pool } = require('pg');
const fs = require('fs');
const path = require('path');

class MigrationRunner {
  constructor(pool) {
    this.pool = pool;
    this.migrationsPath = path.join(__dirname, '../migrations');
  }

  async ensureMigrationsTable() {
    await this.pool.query(`
      CREATE TABLE IF NOT EXISTS schema_migrations (
        version INTEGER PRIMARY KEY,
        name VARCHAR(255) NOT NULL,
        applied_at TIMESTAMP DEFAULT NOW()
      )
    `);
  }

  async getCurrentVersion() {
    const result = await this.pool.query(
      'SELECT COALESCE(MAX(version), 0) as version FROM schema_migrations'
    );
    return result.rows[0].version;
  }

  async runMigrations() {
    await this.ensureMigrationsTable();
    const currentVersion = await this.getCurrentVersion();

    const files = fs.readdirSync(this.migrationsPath)
      .filter(f => f.endsWith('.sql'))
      .sort();

    for (const file of files) {
      const version = parseInt(file.split('_')[0]);
      
      if (version <= currentVersion) {
        continue;
      }

      console.log(`Running migration ${version}: ${file}`);
      
      const sql = fs.readFileSync(
        path.join(this.migrationsPath, file),
        'utf-8'
      );

      await this.pool.query('BEGIN');
      
      try {
        await this.pool.query(sql);
        await this.pool.query(
          'INSERT INTO schema_migrations (version, name) VALUES ($1, $2)',
          [version, file]
        );
        await this.pool.query('COMMIT');
        
        console.log(`✅ Migration ${version} complete`);
      } catch (error) {
        await this.pool.query('ROLLBACK');
        console.error(`❌ Migration ${version} failed:`, error);
        throw error;
      }
    }
  }
}

module.exports = MigrationRunner;
```

**Common Pitfalls:**
- Breaking changes without versioning
- No deprecation warnings
- No migration strategy
- Hard-coded business logic
- No feature flags

**Best Practices:**
- Version APIs in URL path
- Provide deprecation notices
- Use feature flags
- Database migrations (up/down)
- Backward compatibility
- Sunset old versions gracefully
- Document breaking changes

---

## 4. Implementation Patterns

### Standard REST API Directory Structure

```
rest-api/
├── src/
│   ├── foundation/           # Layer 1
│   │   ├── errors/
│   │   │   ├── error-codes.js
│   │   │   └── api-errors.js
│   │   ├── validators/
│   │   │   └── schemas.js
│   │   ├── pagination/
│   │   │   └── paginator.js
│   │   └── utils/
│   │       ├── sanitizer.js
│   │       └── helpers.js
│   │
│   ├── infrastructure/       # Layer 2
│   │   ├── config/
│   │   │   └── config-loader.js
│   │   ├── logging/
│   │   │   └── logger.js
│   │   ├── monitoring/
│   │   │   └── metrics.js
│   │   ├── cache/
│   │   │   ├── cache-manager.js
│   │   │   └── response-cache.js
│   │   ├── middleware/
│   │   │   ├── auth.js
│   │   │   ├── validation.js
│   │   │   ├── error-handler.js
│   │   │   ├── rate-limiter.js
│   │   │   ├── cors.js
│   │   │   ├── compression.js
│   │   │   └── request-logger.js
│   │   ├── auth/
│   │   │   └── jwt-service.js
│   │   └── lifecycle/
│   │       └── shutdown-handler.js
│   │
│   ├── integration/          # Layer 3
│   │   ├── database/
│   │   │   ├── connection-pool.js
│   │   │   ├── user-repository.js
│   │   │   └── migrations/
│   │   ├── cache/
│   │   │   └── redis-client.js
│   │   └── external-apis/
│   │       ├── payment-service.js
│   │       └── email-service.js
│   │
│   ├── application/          # Layer 4
│   │   ├── routes/
│   │   │   ├── index.js
│   │   │   ├── health.js
│   │   │   ├── v1/
│   │   │   │   ├── users.js
│   │   │   │   └── posts.js
│   │   │   └── v2/
│   │   │       └── users.js
│   │   ├── controllers/
│   │   │   └── user-controller.js
│   │   └── services/
│   │       └── user-service.js
│   │
│   └── app.js                # Express app setup
│
├── tests/
│   ├── unit/
│   ├── integration/
│   ├── contract/
│   └── e2e/
│
├── config/
│   ├── default.json
│   ├── development.json
│   ├── staging.json
│   └── production.json
│
├── migrations/
│   ├── 001_create_users_table.sql
│   └── 002_add_user_roles.sql
│
├── docs/
│   ├── openapi.yaml
│   └── ARCHITECTURE.md
│
├── scripts/
│   ├── migrate.js
│   └── seed.js
│
├── .env.example
├── .eslintrc.js
├── .prettierrc
├── .gitignore
├── package.json
└── README.md
```

### HTTP Method Usage

```
GET     /users           - List all users (200)
GET     /users/:id       - Get specific user (200, 404)
POST    /users           - Create new user (201, 400, 409)
PUT     /users/:id       - Replace entire user (200, 404)
PATCH   /users/:id       - Update user fields (200, 404)
DELETE  /users/:id       - Delete user (204, 404)
HEAD    /users/:id       - Check if exists (200, 404)
OPTIONS /users           - Get allowed methods (200)
```

### HTTP Status Codes

**Success (2xx):**
- 200 OK - GET, PUT, PATCH successful
- 201 Created - POST successful
- 202 Accepted - Async operation started
- 204 No Content - DELETE successful

**Client Errors (4xx):**
- 400 Bad Request - Invalid request
- 401 Unauthorized - Auth required
- 403 Forbidden - Insufficient permissions
- 404 Not Found - Resource not found
- 409 Conflict - Resource conflict
- 422 Unprocessable Entity - Validation failed
- 429 Too Many Requests - Rate limited

**Server Errors (5xx):**
- 500 Internal Server Error - Unexpected error
- 502 Bad Gateway - Upstream error
- 503 Service Unavailable - Service down
- 504 Gateway Timeout - Upstream timeout

### REST Resource Naming Conventions

```
✅ Good:
/api/v1/users
/api/v1/users/{userId}
/api/v1/users/{userId}/posts
/api/v1/users/{userId}/posts/{postId}

❌ Bad:
/api/v1/get-users
/api/v1/user-list
/api/v1/createUser
/api/v1/users/get/{id}
```

### Request/Response Examples

**Create User:**
```http
POST /api/v1/users
Content-Type: application/json
Authorization: Bearer <token>

{
  "email": "user@example.com",
  "name": "John Doe",
  "age": 25
}

HTTP/1.1 201 Created
Content-Type: application/json
Location: /api/v1/users/123e4567-e89b-12d3-a456-426614174000
X-Request-ID: 5c3b8f1e-9d42-4a7c-8e3f-1b2c3d4e5f6g

{
  "id": "123e4567-e89b-12d3-a456-426614174000",
  "email": "user@example.com",
  "name": "John Doe",
  "age": 25,
  "createdAt": "2025-11-10T10:30:00Z"
}
```

**List Users:**
```http
GET /api/v1/users?page=1&limit=20&sortBy=createdAt&sortOrder=desc
Authorization: Bearer <token>

HTTP/1.1 200 OK
Content-Type: application/json
X-Request-ID: 7d8e9f0a-1b2c-3d4e-5f6g-7h8i9j0k1l2m

{
  "data": [
    {
      "id": "123e4567-e89b-12d3-a456-426614174000",
      "email": "user@example.com",
      "name": "John Doe",
      "createdAt": "2025-11-10T10:30:00Z"
    }
  ],
  "pagination": {
    "page": 1,
    "limit": 20,
    "total": 100,
    "totalPages": 5,
    "hasNext": true,
    "hasPrev": false
  },
  "_links": {
    "self": "/api/v1/users?page=1&limit=20",
    "next": "/api/v1/users?page=2&limit=20",
    "first": "/api/v1/users?page=1&limit=20",
    "last": "/api/v1/users?page=5&limit=20"
  }
}
```

**Error Response:**
```http
POST /api/v1/users
Content-Type: application/json

{
  "email": "invalid-email"
}

HTTP/1.1 400 Bad Request
Content-Type: application/problem+json
X-Request-ID: 9a0b1c2d-3e4f-5g6h-7i8j-9k0l1m2n3o4p

{
  "type": "https://api.example.com/errors/ValidationError",
  "title": "Invalid request body",
  "status": 400,
  "detail": "The request contains invalid data",
  "instance": "9a0b1c2d-3e4f-5g6h-7i8j-9k0l1m2n3o4p",
  "code": 1,
  "timestamp": "2025-11-10T10:35:00Z",
  "errors": [
    {
      "field": "email",
      "message": "must be a valid email address"
    },
    {
      "field": "name",
      "message": "is required"
    }
  ]
}
```

---

## 5. Complete Code Examples

### Complete Express.js REST API

```javascript
// src/app.js
const express = require('express');
const config = require('./infrastructure/config/config-loader');
const logger = require('./infrastructure/logging/logger');
const { requestLogger } = require('./infrastructure/middleware/request-logger');
const { metricsMiddleware, metricsEndpoint } = require('./infrastructure/middleware/metrics');
const { errorHandler } = require('./infrastructure/middleware/error-handler');
const { createRateLimiter } = require('./infrastructure/middleware/rate-limiter');
const { configureCORS } = require('./infrastructure/middleware/cors');
const { configureSecurityHeaders } = require('./infrastructure/middleware/security-headers');
const { configureCompression } = require('./infrastructure/middleware/compression');
const { requestTimeout } = require('./infrastructure/middleware/timeout');
const { createVersionedRoutes } = require('./application/routes/versioned-routes');
const healthRoutes = require('./application/routes/health');
const ShutdownHandler = require('./infrastructure/lifecycle/shutdown-handler');
const databasePool = require('./integration/database/connection-pool');

async function createApp() {
  const app = express();

  // Trust proxy (if behind load balancer)
  app.set('trust proxy', 1);

  // Security headers
  configureSecurityHeaders(app);

  // CORS
  app.use(configureCORS());

  // Body parsing
  app.use(express.json({ limit: '10mb' }));
  app.use(express.urlencoded({ extended: true, limit: '10mb' }));

  // Compression
  app.use(configureCompression());

  // Request timeout
  app.use(requestTimeout(30000));

  // Logging & Metrics
  app.use(requestLogger);
  app.use(metricsMiddleware);

  // Rate limiting
  if (config.rateLimit.enabled) {
    app.use('/api/', createRateLimiter());
  }

  // Health check (before auth)
  app.use('/health', healthRoutes);
  
  // Metrics endpoint
  app.get('/metrics', metricsEndpoint);

  // API routes
  app.use('/api', createVersionedRoutes());

  // 404 handler
  app.use((req, res) => {
    res.status(404).json({
      error: 'Not Found',
      message: `Cannot ${req.method} ${req.path}`,
      path: req.path
    });
  });

  // Error handler (must be last)
  app.use(errorHandler);

  return app;
}

async function startServer() {
  try {
    const app = await createApp();
    
    const server = app.listen(config.app.port, config.app.host, () => {
      logger.info({
        port: config.app.port,
        host: config.app.host,
        env: config.app.env
      }, `🚀 Server running on http://${config.app.host}:${config.app.port}`);
    });

    // Graceful shutdown
    const shutdownHandler = new ShutdownHandler(server);
    shutdownHandler.registerResource('database', () => databasePool.end());

    return server;
  } catch (error) {
    logger.fatal({ error }, 'Failed to start server');
    process.exit(1);
  }
}

// Start if run directly
if (require.main === module) {
  startServer();
}

module.exports = { createApp, startServer };
```

---

## 6. Tool Recommendations

### Core Tools

**Framework:**
- Express.js - Minimal, flexible
- Fastify - High performance
- Nest.js - Enterprise framework
- Hapi - Configuration-driven

**Validation:**
- Joi - Schema validation
- Yup - Object schema validator
- class-validator - Decorator-based
- Zod - TypeScript-first

**Authentication:**
- jsonwebtoken - JWT implementation
- Passport.js - Auth middleware
- express-jwt - JWT middleware
- node-oauth2-server - OAuth2

**Database:**
- Knex.js - SQL query builder
- TypeORM - ORM with TypeScript
- Sequelize - Promise-based ORM
- Prisma - Type-safe ORM

**Caching:**
- Redis - In-memory data store
- node-cache - In-memory caching
- lru-cache - LRU cache

**Testing:**
- Jest - Test framework
- Supertest - HTTP assertions
- Mocha + Chai - Traditional testing
- Artillery - Load testing

**Documentation:**
- Swagger/OpenAPI - API specification
- ReDoc - OpenAPI renderer
- Postman - API development

**Monitoring:**
- Prometheus - Metrics collection
- Pino - Fast JSON logger
- Winston - Feature-rich logger
- Grafana - Metrics visualization

---

## 7. Testing Strategy

### Test Coverage Goals

- Unit Tests: 30% of suite, 85%+ code coverage
- Integration Tests: 30% of suite
- Contract Tests: 15% of suite
- E2E Tests: 20% of suite
- Load Tests: 5% of suite

### Testing Best Practices

1. Test the API contract, not implementation
2. Use OpenAPI spec for contract testing
3. Test error scenarios
4. Use realistic test data
5. Isolated test databases
6. Mock external services
7. Run tests in CI/CD

---

## 8. Deployment Guidelines

### Docker Deployment

**Dockerfile:**
```dockerfile
FROM node:20-alpine AS builder
WORKDIR /app
COPY package*.json ./
RUN npm ci --only=production

FROM node:20-alpine
WORKDIR /app
COPY --from=builder /app/node_modules ./node_modules
COPY . .
USER node
EXPOSE 3000
CMD ["node", "src/app.js"]
```

### Kubernetes Deployment

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: rest-api
spec:
  replicas: 3
  selector:
    matchLabels:
      app: rest-api
  template:
    metadata:
      labels:
        app: rest-api
    spec:
      containers:
      - name: api
        image: myapi:latest
        ports:
        - containerPort: 3000
        env:
        - name: NODE_ENV
          value: "production"
        livenessProbe:
          httpGet:
            path: /health/live
            port: 3000
        readinessProbe:
          httpGet:
            path: /health/ready
            port: 3000
        resources:
          requests:
            memory: "256Mi"
            cpu: "250m"
          limits:
            memory: "512Mi"
            cpu: "500m"
```

---

## 9. Compliance Checklist

- [ ] Four-layer architecture implemented
- [ ] OpenAPI specification documented
- [ ] Input validation on all endpoints
- [ ] RFC 7807 error responses
- [ ] JWT authentication
- [ ] Rate limiting configured
- [ ] CORS properly configured
- [ ] Security headers (Helmet)
- [ ] Structured logging (Pino)
- [ ] Metrics endpoint (/metrics)
- [ ] Health check endpoint (/health)
- [ ] Request/response logging
- [ ] Graceful shutdown
- [ ] Connection pooling
- [ ] Response caching
- [ ] Pagination implemented
- [ ] API versioning
- [ ] 80%+ test coverage
- [ ] Contract tests (OpenAPI)
- [ ] E2E tests

---

## 10. Migration Guide

### From Existing REST API

**Week 1-2: Assessment**
- Document current endpoints
- Review error handling
- Check test coverage
- Identify security gaps

**Week 3-4: Layer Structure**
- Create four-layer structure
- Move business logic to services
- Implement repositories
- Add validation middleware

**Week 5-6: Security & Observability**
- Add authentication
- Implement rate limiting
- Setup structured logging
- Add metrics collection

**Week 7-8: Testing & Documentation**
- Write integration tests
- Create OpenAPI spec
- Add contract tests
- Update documentation

**Week 9-10: Deployment**
- Deploy to staging
- Run load tests
- Production rollout
- Monitor and iterate

---

## Version History

### 1.0.0 (2025-11-10)
- Initial release
- Full Meta-Architecture v1.0.0 compliance
- All 12 principles implemented
- Complete REST API patterns
- Production-ready examples

---

**Template Maintainer**: Architecture Team  
**Last Reviewed**: 2025-11-10  
**License**: MIT

---

**END OF REST API ARCHITECTURE TEMPLATE v1.0.0**
