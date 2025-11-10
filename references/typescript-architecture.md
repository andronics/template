# TypeScript Architecture v1.0.0

**Meta-Architecture Compliance**: v1.0.0  
**Template Version**: 1.0.0  
**Status**: Active  
**Last Audit**: 2025-11-10  
**Compliance Score**: 100%

---

## Table of Contents

1. [Meta-Architecture Reference](#1-meta-architecture-reference)
2. [TypeScript Ecosystem Overview](#2-typescript-ecosystem-overview)
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

This template implements all 12 universal principles from Meta-Architecture v1.0.0, providing TypeScript-specific patterns and best practices for building reliable, maintainable, and scalable systems.

### Compliance Matrix

| Principle | Implementation | Status |
|-----------|----------------|--------|
| 1. Layered Architecture | TypeScript modules with path mapping | ✅ Full |
| 2. Dependency Management | npm/pnpm/yarn with lock files | ✅ Full |
| 3. Graceful Degradation | Optional dependencies & fallbacks | ✅ Full |
| 4. Input Validation | Zod schemas, class-validator | ✅ Full |
| 5. Error Handling | Custom error classes | ✅ Full |
| 6. Configuration | dotenv with env-var | ✅ Full |
| 7. Observability | Pino logger, Prometheus metrics | ✅ Full |
| 8. Testing | Jest/Vitest with high coverage | ✅ Full |
| 9. Security | ESLint security plugins, OWASP | ✅ Full |
| 10. Resource Management | Explicit cleanup, async disposal | ✅ Full |
| 11. Performance | Caching, lazy loading, profiling | ✅ Full |
| 12. Evolution | Semantic versioning, feature flags | ✅ Full |

### Meta-Architecture Alignment

This template enforces:
- **Four-layer architecture** with downward-only dependencies
- **Explicit dependencies** via package.json and TypeScript imports
- **Type safety** leveraging TypeScript's static type system
- **Runtime validation** for all external inputs
- **Observable systems** through structured logging and metrics

---

## 2. TypeScript Ecosystem Overview

### Language Characteristics

**TypeScript** is a statically-typed superset of JavaScript that compiles to plain JavaScript. It provides:

- **Static Type Checking**: Catch errors at compile time
- **Modern ECMAScript Features**: ES2023+ with backward compatibility
- **Rich Tooling**: Excellent IDE support, refactoring, autocomplete
- **Gradual Adoption**: Can be introduced incrementally
- **JavaScript Interop**: Works with existing JavaScript libraries

### Common Use Cases

1. **Backend Services**
   - REST APIs (Express, Fastify, Nest.js)
   - GraphQL servers (Apollo Server)
   - Microservices
   - WebSocket servers

2. **Frontend Applications**
   - React, Vue, Angular applications
   - Single-page applications (SPAs)
   - Progressive web apps (PWAs)

3. **Full-Stack Applications**
   - Next.js, Remix
   - tRPC for end-to-end type safety
   - Monorepos with shared types

4. **CLI Tools**
   - Command-line utilities (Commander, oclif)
   - Build tools and scripts
   - Developer tooling

5. **Real-Time Systems**
   - Chat applications
   - Live dashboards
   - IoT data processing

### Ecosystem Strengths

- **npm Registry**: Largest package ecosystem (2M+ packages)
- **Type Definitions**: @types packages for JavaScript libraries
- **Modern Tooling**: Fast build tools (esbuild, swc)
- **Active Community**: Extensive documentation and support
- **Enterprise Adoption**: Widely used in production systems

---

## 3. Core Principles Mapping

### Principle 1: Layered Architecture ⭐ MANDATORY

**Meta-Architecture Definition:**  
"All systems MUST organize code into 4 distinct layers with downward-only dependencies."

**TypeScript Implementation:**

TypeScript's module system combined with path mapping enables strict layer boundaries. Use TypeScript path aliases in `tsconfig.json` to enforce the four-layer structure.

**Directory Structure:**

```
src/
├── foundation/           # Layer 1: Primitives
│   ├── validation/
│   ├── types/
│   └── utils/
├── infrastructure/       # Layer 2: Core services
│   ├── logging/
│   ├── config/
│   ├── cache/
│   └── metrics/
├── integration/          # Layer 3: External systems
│   ├── database/
│   ├── http/
│   ├── messaging/
│   └── external-apis/
└── application/          # Layer 4: Business logic
    ├── services/
    ├── controllers/
    └── workflows/
```

**tsconfig.json Path Mapping:**

```json
{
  "compilerOptions": {
    "baseUrl": "./src",
    "paths": {
      "@foundation/*": ["foundation/*"],
      "@infrastructure/*": ["infrastructure/*"],
      "@integration/*": ["integration/*"],
      "@application/*": ["application/*"]
    }
  }
}
```

**Layer Enforcement with ESLint:**

```javascript
// .eslintrc.js
module.exports = {
  rules: {
    'import/no-restricted-paths': [
      'error',
      {
        zones: [
          // Foundation cannot import from any other layer
          {
            target: './src/foundation',
            from: './src/infrastructure'
          },
          {
            target: './src/foundation',
            from: './src/integration'
          },
          {
            target: './src/foundation',
            from: './src/application'
          },
          // Infrastructure can only import from foundation
          {
            target: './src/infrastructure',
            from: './src/integration'
          },
          {
            target: './src/infrastructure',
            from: './src/application'
          },
          // Integration can only import from foundation & infrastructure
          {
            target: './src/integration',
            from: './src/application'
          }
        ]
      }
    ]
  }
};
```

**Example - Correct Layering:**

```typescript
// ✅ foundation/validation/email.ts (Layer 1 - No dependencies)
export function isValidEmail(email: string): boolean {
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  return emailRegex.test(email);
}

// ✅ infrastructure/logging/logger.ts (Layer 2 - Depends on Layer 1)
import { isValidEmail } from '@foundation/validation/email';

export class Logger {
  log(message: string, email?: string): void {
    if (email && !isValidEmail(email)) {
      throw new Error('Invalid email for logging context');
    }
    console.log(message, { email });
  }
}

// ✅ integration/database/user-repository.ts (Layer 3 - Depends on Layers 1, 2)
import { Logger } from '@infrastructure/logging/logger';
import { isValidEmail } from '@foundation/validation/email';

export class UserRepository {
  constructor(private logger: Logger) {}

  async findByEmail(email: string): Promise<User | null> {
    if (!isValidEmail(email)) {
      this.logger.log('Invalid email search attempted');
      return null;
    }
    // Database query here
    return null;
  }
}

// ✅ application/services/user-service.ts (Layer 4 - Can depend on any layer)
import { UserRepository } from '@integration/database/user-repository';
import { Logger } from '@infrastructure/logging/logger';

export class UserService {
  constructor(
    private userRepo: UserRepository,
    private logger: Logger
  ) {}

  async registerUser(email: string): Promise<void> {
    this.logger.log('Registering user', email);
    const existing = await this.userRepo.findByEmail(email);
    if (existing) {
      throw new Error('User already exists');
    }
    // Registration logic
  }
}
```

**Example - Layer Violation (FORBIDDEN):**

```typescript
// ❌ foundation/utils/helper.ts trying to import from infrastructure
import { Logger } from '@infrastructure/logging/logger'; // VIOLATION!

// This will be caught by ESLint and fail CI
```

**Common Pitfalls:**
- Circular dependencies between layers
- Business logic in integration layer
- Infrastructure accessing application layer
- Not using TypeScript path aliases

**Best Practices:**
- Use barrel exports (`index.ts`) for clean layer APIs
- Keep layers focused and cohesive
- Document layer purpose in README
- Run `eslint` in pre-commit hooks
- Use `dependency-cruiser` for visualization

---

### Principle 2: Explicit Dependency Management ⭐ MANDATORY

**Meta-Architecture Definition:**  
"All dependencies MUST be explicitly declared, versioned, and manageable."

**TypeScript Implementation:**

Use `package.json` for dependency declaration with exact versioning and lock files for reproducibility.

**package.json Structure:**

```json
{
  "name": "my-typescript-app",
  "version": "1.0.0",
  "engines": {
    "node": ">=20.0.0",
    "npm": ">=10.0.0"
  },
  "dependencies": {
    "express": "4.18.2",
    "zod": "3.22.4",
    "pino": "8.16.1"
  },
  "optionalDependencies": {
    "redis": "4.6.10"
  },
  "devDependencies": {
    "@types/node": "20.9.0",
    "@types/express": "4.17.20",
    "typescript": "5.2.2",
    "vitest": "0.34.6",
    "eslint": "8.53.0"
  },
  "peerDependencies": {
    "react": "^18.0.0"
  }
}
```

**Dependency Categories:**

1. **Required (`dependencies`)**: System cannot run without these
2. **Optional (`optionalDependencies`)**: Graceful degradation if missing
3. **Development (`devDependencies`)**: Build-time only
4. **Peer (`peerDependencies`)**: Expected in consuming projects

**Lock File Management:**

```bash
# npm
npm install  # Creates package-lock.json

# pnpm (recommended for monorepos)
pnpm install  # Creates pnpm-lock.yaml

# yarn
yarn install  # Creates yarn.lock
```

**Graceful Degradation with Optional Dependencies:**

```typescript
// infrastructure/cache/cache-manager.ts
import type { RedisClientType } from 'redis';

let redis: typeof import('redis') | null = null;

try {
  redis = require('redis');
} catch {
  // Redis not installed - will use in-memory fallback
}

export class CacheManager {
  private redisClient?: RedisClientType;
  private memoryCache: Map<string, any> = new Map();

  async connect(): Promise<void> {
    if (redis) {
      try {
        this.redisClient = redis.createClient();
        await this.redisClient.connect();
        console.log('✅ Redis connected');
      } catch (error) {
        console.warn('⚠️  Redis connection failed, using memory cache');
        this.redisClient = undefined;
      }
    } else {
      console.warn('⚠️  Redis not installed, using memory cache');
    }
  }

  async get<T>(key: string): Promise<T | null> {
    if (this.redisClient) {
      const value = await this.redisClient.get(key);
      return value ? JSON.parse(value) : null;
    }
    return this.memoryCache.get(key) ?? null;
  }

  async set<T>(key: string, value: T, ttl?: number): Promise<void> {
    if (this.redisClient) {
      const serialized = JSON.stringify(value);
      if (ttl) {
        await this.redisClient.setEx(key, ttl, serialized);
      } else {
        await this.redisClient.set(key, serialized);
      }
    } else {
      this.memoryCache.set(key, value);
      if (ttl) {
        setTimeout(() => this.memoryCache.delete(key), ttl * 1000);
      }
    }
  }

  async disconnect(): Promise<void> {
    if (this.redisClient) {
      await this.redisClient.quit();
    }
    this.memoryCache.clear();
  }
}
```

**Version Pinning Strategies:**

```json
{
  "dependencies": {
    "express": "4.18.2",           // Exact version (production)
    "zod": "^3.22.4",              // Minor updates OK (^3.22.4 - 3.x.x)
    "lodash": "~4.17.21"           // Patch updates only (~4.17.x)
  }
}
```

**Security Auditing:**

```bash
# Check for vulnerabilities
npm audit

# Fix automatically where possible
npm audit fix

# Check for outdated dependencies
npm outdated
```

**Common Pitfalls:**
- Not committing lock files
- Using wildcards (*) for versions
- Mixing package managers (npm + yarn)
- Not declaring peer dependencies
- Ignoring security advisories

**Best Practices:**
- Always commit lock files
- Use exact versions for production apps
- Use semver ranges for libraries
- Regular dependency updates (weekly/monthly)
- Automated security scanning in CI
- Document why each dependency is needed

---

### Principle 3: Graceful Degradation ⭐ MANDATORY

**Meta-Architecture Definition:**  
"Systems MUST continue operating with reduced functionality when non-critical dependencies fail."

**TypeScript Implementation:**

Classify dependencies and implement fallback strategies for non-critical features.

**Dependency Classification:**

```typescript
// infrastructure/dependencies/classification.ts
export enum DependencyLevel {
  CRITICAL = 'CRITICAL',     // System cannot operate without this
  IMPORTANT = 'IMPORTANT',   // Core functionality degraded
  OPTIONAL = 'OPTIONAL'      // Nice-to-have features only
}

export interface DependencyStatus {
  name: string;
  level: DependencyLevel;
  available: boolean;
  fallbackActive: boolean;
  error?: Error;
}

export class DependencyRegistry {
  private dependencies = new Map<string, DependencyStatus>();

  register(name: string, level: DependencyLevel): void {
    this.dependencies.set(name, {
      name,
      level,
      available: false,
      fallbackActive: false
    });
  }

  markAvailable(name: string): void {
    const dep = this.dependencies.get(name);
    if (dep) {
      dep.available = true;
      dep.fallbackActive = false;
    }
  }

  markFailed(name: string, error: Error, fallbackActive: boolean): void {
    const dep = this.dependencies.get(name);
    if (dep) {
      dep.available = false;
      dep.error = error;
      dep.fallbackActive = fallbackActive;
    }
  }

  getStatus(): DependencyStatus[] {
    return Array.from(this.dependencies.values());
  }

  isCriticalFailed(): boolean {
    return Array.from(this.dependencies.values()).some(
      dep => dep.level === DependencyLevel.CRITICAL && !dep.available
    );
  }
}
```

**Example: Email Service with Graceful Degradation:**

```typescript
// integration/messaging/email-service.ts
import { DependencyLevel, DependencyRegistry } from '@infrastructure/dependencies/classification';

interface EmailProvider {
  send(to: string, subject: string, body: string): Promise<void>;
}

class SendGridProvider implements EmailProvider {
  async send(to: string, subject: string, body: string): Promise<void> {
    // SendGrid API call
    throw new Error('SendGrid API failed');
  }
}

class MailgunProvider implements EmailProvider {
  async send(to: string, subject: string, body: string): Promise<void> {
    // Mailgun API call
    console.log(`📧 Mailgun: Sent email to ${to}`);
  }
}

class LoggingProvider implements EmailProvider {
  async send(to: string, subject: string, body: string): Promise<void> {
    console.log(`📝 [FALLBACK] Email logged: ${to} - ${subject}`);
  }
}

export class EmailService {
  private providers: EmailProvider[];
  private currentProviderIndex = 0;

  constructor(private dependencyRegistry: DependencyRegistry) {
    this.providers = [
      new SendGridProvider(),    // Primary
      new MailgunProvider(),     // Secondary
      new LoggingProvider()      // Fallback (always works)
    ];

    this.dependencyRegistry.register('email-service', DependencyLevel.IMPORTANT);
  }

  async sendEmail(to: string, subject: string, body: string): Promise<boolean> {
    for (let i = this.currentProviderIndex; i < this.providers.length; i++) {
      try {
        await this.providers[i].send(to, subject, body);
        this.dependencyRegistry.markAvailable('email-service');
        return true;
      } catch (error) {
        console.warn(`Email provider ${i} failed:`, error);
        if (i === this.providers.length - 1) {
          // Even fallback failed
          this.dependencyRegistry.markFailed(
            'email-service',
            error as Error,
            false
          );
          return false;
        }
        // Try next provider
        continue;
      }
    }
    return false;
  }
}
```

**Health Check Endpoint:**

```typescript
// application/controllers/health-controller.ts
import { DependencyRegistry } from '@infrastructure/dependencies/classification';

export class HealthController {
  constructor(private dependencyRegistry: DependencyRegistry) {}

  getHealthStatus(): {
    status: 'healthy' | 'degraded' | 'unhealthy';
    dependencies: any[];
  } {
    const dependencies = this.dependencyRegistry.getStatus();
    const isCriticalFailed = this.dependencyRegistry.isCriticalFailed();

    let status: 'healthy' | 'degraded' | 'unhealthy';
    if (isCriticalFailed) {
      status = 'unhealthy';
    } else if (dependencies.some(d => !d.available)) {
      status = 'degraded';
    } else {
      status = 'healthy';
    }

    return { status, dependencies };
  }
}
```

**Common Pitfalls:**
- Treating all dependencies as critical
- No fallback strategies
- Silent failures without logging
- Not exposing degraded state
- Cascading failures

**Best Practices:**
- Document dependency criticality
- Implement circuit breakers
- Log degradation events
- Expose health endpoints
- Test fallback scenarios
- Monitor degradation metrics

---

### Principle 4: Comprehensive Input Validation ⭐ MANDATORY

**Meta-Architecture Definition:**  
"ALL inputs from external sources MUST be validated before use."

**TypeScript Implementation:**

Use runtime validation libraries like Zod or class-validator for type-safe validation.

**Validation with Zod:**

```typescript
// foundation/validation/schemas.ts
import { z } from 'zod';

// Define schemas for all external inputs
export const EmailSchema = z.string().email().min(5).max(255);

export const UserRegistrationSchema = z.object({
  email: EmailSchema,
  password: z.string().min(8).max(100).regex(/^(?=.*[A-Z])(?=.*[a-z])(?=.*\d)/),
  age: z.number().int().min(13).max(120),
  agreedToTerms: z.literal(true),
  metadata: z.record(z.unknown()).optional()
});

export type UserRegistration = z.infer<typeof UserRegistrationSchema>;

// Validate with helpful error messages
export function validateUserRegistration(input: unknown): UserRegistration {
  try {
    return UserRegistrationSchema.parse(input);
  } catch (error) {
    if (error instanceof z.ZodError) {
      const messages = error.errors.map(e => `${e.path.join('.')}: ${e.message}`);
      throw new ValidationError('Invalid user registration data', messages);
    }
    throw error;
  }
}
```

**Four-Layer Validation:**

```typescript
// application/controllers/user-controller.ts
import { validateUserRegistration } from '@foundation/validation/schemas';
import { UserService } from '@application/services/user-service';

export class UserController {
  constructor(private userService: UserService) {}

  async register(rawInput: unknown): Promise<{ id: string }> {
    // Layer 1: Type/Format validation
    const input = validateUserRegistration(rawInput);

    // Layer 2: Range validation (handled by Zod schema)
    // Already enforced: age 13-120, password 8-100 chars

    // Layer 3: Business rule validation
    if (await this.userService.emailExists(input.email)) {
      throw new BusinessRuleError('Email already registered');
    }

    // Layer 4: State validation
    const user = await this.userService.register(input);
    return { id: user.id };
  }
}
```

**API Input Validation Middleware (Express):**

```typescript
// infrastructure/http/validation-middleware.ts
import { Request, Response, NextFunction } from 'express';
import { ZodSchema } from 'zod';

export function validateRequest(schema: ZodSchema) {
  return (req: Request, res: Response, next: NextFunction) => {
    try {
      req.body = schema.parse(req.body);
      next();
    } catch (error) {
      res.status(400).json({
        error: 'INVALID_INPUT',
        message: 'Request validation failed',
        details: error instanceof z.ZodError ? error.errors : []
      });
    }
  };
}

// Usage
app.post('/users', validateRequest(UserRegistrationSchema), async (req, res) => {
  // req.body is now typed and validated
  const user = await userController.register(req.body);
  res.json(user);
});
```

**Sanitization:**

```typescript
// foundation/validation/sanitization.ts
export class Sanitizer {
  static sanitizeHtml(input: string): string {
    return input
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#x27;')
      .replace(/\//g, '&#x2F;');
  }

  static sanitizeFilename(input: string): string {
    return input.replace(/[^a-zA-Z0-9._-]/g, '_');
  }

  static sanitizeSqlIdentifier(input: string): string {
    // Only allow alphanumeric and underscore
    if (!/^[a-zA-Z_][a-zA-Z0-9_]*$/.test(input)) {
      throw new Error('Invalid SQL identifier');
    }
    return input;
  }
}
```

**Common Pitfalls:**
- Trusting client-side validation
- Incomplete type checking
- Not validating third-party API responses
- SQL injection vulnerabilities
- Path traversal attacks

**Best Practices:**
- Validate at system boundaries
- Use schema validation libraries
- Sanitize outputs (prevent XSS)
- Whitelist > Blacklist approaches
- Log validation failures
- Return helpful error messages (non-sensitive)

---

### Principle 5: Standardized Error Handling ⭐ MANDATORY

**Meta-Architecture Definition:**  
"Systems MUST handle errors consistently using standardized patterns."

**TypeScript Implementation:**

Create custom error classes with standardized codes and rich context.

**Standard Error Codes:**

```typescript
// foundation/errors/error-codes.ts
export enum ErrorCode {
  SUCCESS = 0,
  INVALID_INPUT = 1,
  NOT_FOUND = 2,
  PERMISSION_DENIED = 3,
  CONFLICT = 4,
  DEPENDENCY_ERROR = 5,
  INTERNAL_ERROR = 6,
  TIMEOUT = 7,
  RATE_LIMITED = 8,
  DEGRADED = 9,
  
  // Domain-specific codes (10+)
  USER_ALREADY_EXISTS = 10,
  INSUFFICIENT_BALANCE = 11,
  PAYMENT_FAILED = 12
}

export const ErrorCodeDescriptions: Record<ErrorCode, string> = {
  [ErrorCode.SUCCESS]: 'Operation completed successfully',
  [ErrorCode.INVALID_INPUT]: 'The provided input is invalid',
  [ErrorCode.NOT_FOUND]: 'The requested resource was not found',
  [ErrorCode.PERMISSION_DENIED]: 'You do not have permission to perform this action',
  [ErrorCode.CONFLICT]: 'The operation conflicts with existing data',
  [ErrorCode.DEPENDENCY_ERROR]: 'A required dependency is unavailable',
  [ErrorCode.INTERNAL_ERROR]: 'An internal error occurred',
  [ErrorCode.TIMEOUT]: 'The operation timed out',
  [ErrorCode.RATE_LIMITED]: 'Too many requests',
  [ErrorCode.DEGRADED]: 'Service is running in degraded mode',
  [ErrorCode.USER_ALREADY_EXISTS]: 'A user with this email already exists',
  [ErrorCode.INSUFFICIENT_BALANCE]: 'Insufficient account balance',
  [ErrorCode.PAYMENT_FAILED]: 'Payment processing failed'
};
```

**Base Error Class:**

```typescript
// foundation/errors/base-error.ts
export interface ErrorContext {
  [key: string]: unknown;
}

export abstract class BaseError extends Error {
  public readonly code: ErrorCode;
  public readonly context: ErrorContext;
  public readonly timestamp: Date;
  public readonly retryable: boolean;
  public readonly httpStatus: number;

  constructor(
    message: string,
    code: ErrorCode,
    context: ErrorContext = {},
    retryable = false,
    httpStatus = 500
  ) {
    super(message);
    this.name = this.constructor.name;
    this.code = code;
    this.context = context;
    this.timestamp = new Date();
    this.retryable = retryable;
    this.httpStatus = httpStatus;

    // Maintains proper stack trace for where error was thrown
    Error.captureStackTrace(this, this.constructor);
  }

  toJSON(): object {
    return {
      name: this.name,
      message: this.message,
      code: this.code,
      context: this.context,
      timestamp: this.timestamp.toISOString(),
      retryable: this.retryable,
      httpStatus: this.httpStatus
    };
  }
}
```

**Specific Error Classes:**

```typescript
// foundation/errors/domain-errors.ts
export class ValidationError extends BaseError {
  constructor(message: string, context: ErrorContext = {}) {
    super(message, ErrorCode.INVALID_INPUT, context, false, 400);
  }
}

export class NotFoundError extends BaseError {
  constructor(resource: string, identifier: string) {
    super(
      `${resource} not found`,
      ErrorCode.NOT_FOUND,
      { resource, identifier },
      false,
      404
    );
  }
}

export class PermissionError extends BaseError {
  constructor(action: string, resource: string) {
    super(
      `Permission denied: ${action} on ${resource}`,
      ErrorCode.PERMISSION_DENIED,
      { action, resource },
      false,
      403
    );
  }
}

export class BusinessRuleError extends BaseError {
  constructor(message: string, context: ErrorContext = {}) {
    super(message, ErrorCode.CONFLICT, context, false, 409);
  }
}

export class DependencyError extends BaseError {
  constructor(dependency: string, cause?: Error) {
    super(
      `Dependency unavailable: ${dependency}`,
      ErrorCode.DEPENDENCY_ERROR,
      { dependency, cause: cause?.message },
      true,  // Retryable
      503
    );
  }
}

export class TimeoutError extends BaseError {
  constructor(operation: string, timeoutMs: number) {
    super(
      `Operation timed out: ${operation}`,
      ErrorCode.TIMEOUT,
      { operation, timeoutMs },
      true,
      504
    );
  }
}
```

**Error Handler Middleware:**

```typescript
// infrastructure/http/error-handler.ts
import { Request, Response, NextFunction } from 'express';
import { BaseError, ErrorCode } from '@foundation/errors';
import { Logger } from '@infrastructure/logging/logger';

export function errorHandler(logger: Logger) {
  return (err: Error, req: Request, res: Response, next: NextFunction) => {
    if (res.headersSent) {
      return next(err);
    }

    if (err instanceof BaseError) {
      // Log with appropriate level
      const logLevel = err.httpStatus >= 500 ? 'error' : 'warn';
      logger[logLevel]({
        error: err.toJSON(),
        request: {
          method: req.method,
          path: req.path,
          query: req.query
        }
      });

      return res.status(err.httpStatus).json({
        error: {
          code: err.code,
          message: err.message,
          retryable: err.retryable,
          timestamp: err.timestamp
          // Note: context omitted in production for security
        }
      });
    }

    // Unknown error - log as internal error
    logger.error({
      error: {
        name: err.name,
        message: err.message,
        stack: err.stack
      },
      request: {
        method: req.method,
        path: req.path
      }
    });

    res.status(500).json({
      error: {
        code: ErrorCode.INTERNAL_ERROR,
        message: 'An internal error occurred',
        retryable: false
      }
    });
  };
}
```

**Usage Example:**

```typescript
// application/services/user-service.ts
export class UserService {
  async getUser(userId: string): Promise<User> {
    const user = await this.userRepository.findById(userId);
    
    if (!user) {
      throw new NotFoundError('User', userId);
    }

    return user;
  }

  async deleteUser(userId: string, requesterId: string): Promise<void> {
    if (userId !== requesterId) {
      throw new PermissionError('delete', 'user');
    }

    await this.userRepository.delete(userId);
  }
}
```

**Common Pitfalls:**
- Swallowing errors silently
- Exposing sensitive information in error messages
- Inconsistent error responses across endpoints
- Not logging errors properly
- Missing stack traces

**Best Practices:**
- Use typed error classes
- Include correlation IDs for tracing
- Sanitize errors before returning to client
- Log errors with appropriate severity
- Distinguish retryable vs. non-retryable errors
- Document error codes in API documentation

---

### Principle 6: Hierarchical Configuration ⭐ MANDATORY

**Meta-Architecture Definition:**  
"Configuration MUST follow clear hierarchy (lowest to highest precedence)."

**TypeScript Implementation:**

Use environment variables with validation and clear precedence rules.

**Configuration Hierarchy:**

```
1. Compiled-in defaults (lowest precedence)
2. Config file (config/default.json)
3. Environment-specific file (config/production.json)
4. Environment variables
5. Command-line arguments
6. Runtime overrides (highest precedence)
```

**Configuration Schema with Validation:**

```typescript
// infrastructure/config/schema.ts
import { z } from 'zod';

export const ConfigSchema = z.object({
  app: z.object({
    name: z.string().default('my-app'),
    version: z.string().default('1.0.0'),
    env: z.enum(['development', 'staging', 'production']).default('development'),
    port: z.number().int().min(1).max(65535).default(3000)
  }),
  
  database: z.object({
    host: z.string().default('localhost'),
    port: z.number().int().default(5432),
    name: z.string().min(1),
    user: z.string().min(1),
    password: z.string().min(1),
    ssl: z.boolean().default(false),
    maxConnections: z.number().int().min(1).max(100).default(10)
  }),
  
  redis: z.object({
    enabled: z.boolean().default(false),
    host: z.string().default('localhost'),
    port: z.number().int().default(6379),
    password: z.string().optional(),
    db: z.number().int().min(0).max(15).default(0)
  }).optional(),
  
  logging: z.object({
    level: z.enum(['trace', 'debug', 'info', 'warn', 'error', 'fatal']).default('info'),
    pretty: z.boolean().default(false)
  }),
  
  security: z.object({
    jwtSecret: z.string().min(32),
    bcryptRounds: z.number().int().min(10).max(15).default(12),
    rateLimitMax: z.number().int().default(100),
    rateLimitWindowMs: z.number().int().default(900000) // 15 min
  }),
  
  features: z.object({
    emailVerification: z.boolean().default(true),
    socialLogin: z.boolean().default(false),
    analytics: z.boolean().default(true)
  })
});

export type AppConfig = z.infer<typeof ConfigSchema>;
```

**Configuration Loader:**

```typescript
// infrastructure/config/config-loader.ts
import * as fs from 'fs';
import * as path from 'path';
import { parse as parseEnv } from 'dotenv';
import { ConfigSchema, AppConfig } from './schema';

export class ConfigLoader {
  private static instance: AppConfig | null = null;

  static load(): AppConfig {
    if (this.instance) {
      return this.instance;
    }

    // 1. Start with defaults (defined in schema)
    let config: any = {};

    // 2. Load config file if exists
    const configPath = path.join(process.cwd(), 'config', 'default.json');
    if (fs.existsSync(configPath)) {
      const fileConfig = JSON.parse(fs.readFileSync(configPath, 'utf-8'));
      config = this.deepMerge(config, fileConfig);
    }

    // 3. Load environment-specific config
    const env = process.env.NODE_ENV || 'development';
    const envConfigPath = path.join(process.cwd(), 'config', `${env}.json`);
    if (fs.existsSync(envConfigPath)) {
      const envConfig = JSON.parse(fs.readFileSync(envConfigPath, 'utf-8'));
      config = this.deepMerge(config, envConfig);
    }

    // 4. Load .env file
    const envFilePath = path.join(process.cwd(), `.env.${env}`);
    if (fs.existsSync(envFilePath)) {
      const envVars = parseEnv(fs.readFileSync(envFilePath));
      Object.assign(process.env, envVars);
    }

    // 5. Override with environment variables
    config = this.applyEnvOverrides(config);

    // 6. Validate and parse with schema
    try {
      this.instance = ConfigSchema.parse(config);
      return this.instance;
    } catch (error) {
      console.error('❌ Configuration validation failed:');
      console.error(error);
      process.exit(1);
    }
  }

  private static applyEnvOverrides(config: any): any {
    // Map environment variables to config structure
    return {
      app: {
        ...config.app,
        port: this.envInt('PORT', config.app?.port),
        env: process.env.NODE_ENV || config.app?.env
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
      logging: {
        ...config.logging,
        level: process.env.LOG_LEVEL || config.logging?.level,
        pretty: this.envBool('LOG_PRETTY', config.logging?.pretty)
      },
      security: {
        ...config.security,
        jwtSecret: process.env.JWT_SECRET || config.security?.jwtSecret,
        bcryptRounds: this.envInt('BCRYPT_ROUNDS', config.security?.bcryptRounds)
      },
      features: {
        ...config.features,
        emailVerification: this.envBool('FEATURE_EMAIL_VERIFICATION', config.features?.emailVerification),
        socialLogin: this.envBool('FEATURE_SOCIAL_LOGIN', config.features?.socialLogin)
      }
    };
  }

  private static envInt(key: string, defaultValue?: number): number | undefined {
    const value = process.env[key];
    return value ? parseInt(value, 10) : defaultValue;
  }

  private static envBool(key: string, defaultValue?: boolean): boolean | undefined {
    const value = process.env[key];
    if (value === undefined) return defaultValue;
    return value === 'true' || value === '1';
  }

  private static deepMerge(target: any, source: any): any {
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

// Export singleton instance
export const config = ConfigLoader.load();
```

**Environment Variable Template (.env.example):**

```bash
# .env.example - Template for environment-specific configuration
# Copy to .env.production, .env.staging, etc.

# Application
NODE_ENV=production
PORT=3000

# Database
DB_HOST=localhost
DB_PORT=5432
DB_NAME=myapp
DB_USER=myapp_user
DB_PASSWORD=CHANGE_ME_IN_PRODUCTION
DB_SSL=true

# Redis (optional)
REDIS_ENABLED=true
REDIS_HOST=localhost
REDIS_PORT=6379
REDIS_PASSWORD=

# Logging
LOG_LEVEL=info
LOG_PRETTY=false

# Security (NEVER commit these to Git!)
JWT_SECRET=GENERATE_A_SECURE_RANDOM_STRING_AT_LEAST_32_CHARS
BCRYPT_ROUNDS=12

# Features
FEATURE_EMAIL_VERIFICATION=true
FEATURE_SOCIAL_LOGIN=false
```

**Secret Management:**

```typescript
// infrastructure/config/secrets.ts
import * as fs from 'fs';
import * as path from 'path';

/**
 * Load secrets from mounted volumes (Kubernetes secrets, Docker secrets, etc.)
 */
export function loadSecretsFromFiles(secretsDir: string): Record<string, string> {
  const secrets: Record<string, string> = {};

  if (!fs.existsSync(secretsDir)) {
    return secrets;
  }

  const files = fs.readdirSync(secretsDir);
  for (const file of files) {
    const filePath = path.join(secretsDir, file);
    if (fs.statSync(filePath).isFile()) {
      secrets[file] = fs.readFileSync(filePath, 'utf-8').trim();
    }
  }

  return secrets;
}

// Usage: Load from /run/secrets (Docker Swarm) or /etc/secrets (Kubernetes)
const secrets = loadSecretsFromFiles('/run/secrets');
if (secrets.jwt_secret) {
  process.env.JWT_SECRET = secrets.jwt_secret;
}
```

**Common Pitfalls:**
- Hardcoding secrets in source code
- Committing .env files to Git
- No validation of configuration
- Missing defaults
- Complex configuration merging logic

**Best Practices:**
- Use .env.example as a template
- Validate configuration at startup
- Fail fast on invalid configuration
- Document all configuration options
- Use secret management systems (AWS Secrets Manager, Vault)
- Never log sensitive configuration values

---

### Principle 7: Observable System Behavior ⭐ MANDATORY

**Meta-Architecture Definition:**  
"System behavior MUST be observable through structured logging, metrics, and tracing."

**TypeScript Implementation:**

Implement comprehensive observability using Pino for logging and Prometheus for metrics.

**Structured Logging with Pino:**

```typescript
// infrastructure/logging/logger.ts
import pino from 'pino';
import { v4 as uuidv4 } from 'uuid';

export type LogLevel = 'trace' | 'debug' | 'info' | 'warn' | 'error' | 'fatal';

export interface LogContext {
  correlationId?: string;
  userId?: string;
  requestId?: string;
  [key: string]: unknown;
}

export class Logger {
  private logger: pino.Logger;
  private context: LogContext = {};

  constructor(config: { level: LogLevel; pretty: boolean }) {
    this.logger = pino({
      level: config.level,
      transport: config.pretty
        ? { target: 'pino-pretty', options: { colorize: true } }
        : undefined,
      base: {
        pid: process.pid,
        hostname: process.env.HOSTNAME || 'unknown'
      },
      timestamp: pino.stdTimeFunctions.isoTime
    });
  }

  child(context: LogContext): Logger {
    const childLogger = new Logger({ level: this.logger.level as LogLevel, pretty: false });
    childLogger.logger = this.logger.child(context);
    childLogger.context = { ...this.context, ...context };
    return childLogger;
  }

  trace(message: string | object, context?: LogContext): void {
    this.log('trace', message, context);
  }

  debug(message: string | object, context?: LogContext): void {
    this.log('debug', message, context);
  }

  info(message: string | object, context?: LogContext): void {
    this.log('info', message, context);
  }

  warn(message: string | object, context?: LogContext): void {
    this.log('warn', message, context);
  }

  error(message: string | object, context?: LogContext): void {
    this.log('error', message, context);
  }

  fatal(message: string | object, context?: LogContext): void {
    this.log('fatal', message, context);
  }

  private log(level: LogLevel, message: string | object, context?: LogContext): void {
    const fullContext = { ...this.context, ...context };
    
    if (typeof message === 'string') {
      this.logger[level](fullContext, message);
    } else {
      this.logger[level]({ ...fullContext, ...message });
    }
  }
}
```

**Request Correlation Middleware:**

```typescript
// infrastructure/http/correlation-middleware.ts
import { Request, Response, NextFunction } from 'express';
import { v4 as uuidv4 } from 'uuid';

export function correlationMiddleware(req: Request, res: Response, next: NextFunction): void {
  // Get or generate correlation ID
  const correlationId = req.headers['x-correlation-id'] as string || uuidv4();
  
  // Attach to request
  req.correlationId = correlationId;
  
  // Add to response headers
  res.setHeader('x-correlation-id', correlationId);
  
  // Create request-scoped logger
  req.logger = req.app.locals.logger.child({
    correlationId,
    requestId: uuidv4(),
    method: req.method,
    path: req.path
  });
  
  req.logger.info('Request received');
  
  // Log response
  res.on('finish', () => {
    req.logger.info('Request completed', {
      statusCode: res.statusCode,
      duration: Date.now() - req.startTime
    });
  });
  
  next();
}
```

**Metrics Collection with Prometheus:**

```typescript
// infrastructure/metrics/metrics-collector.ts
import { Registry, Counter, Histogram, Gauge } from 'prom-client';

export class MetricsCollector {
  private registry: Registry;

  // RED metrics (Rate, Errors, Duration)
  public httpRequestsTotal: Counter;
  public httpRequestDuration: Histogram;
  public httpErrorsTotal: Counter;

  // USE metrics (Utilization, Saturation, Errors)
  public databaseConnectionsActive: Gauge;
  public databaseConnectionsSaturated: Gauge;
  public databaseErrorsTotal: Counter;

  // Business metrics
  public usersCreatedTotal: Counter;
  public ordersProcessedTotal: Counter;

  constructor() {
    this.registry = new Registry();

    // HTTP metrics
    this.httpRequestsTotal = new Counter({
      name: 'http_requests_total',
      help: 'Total HTTP requests',
      labelNames: ['method', 'path', 'status'],
      registers: [this.registry]
    });

    this.httpRequestDuration = new Histogram({
      name: 'http_request_duration_seconds',
      help: 'HTTP request duration',
      labelNames: ['method', 'path'],
      buckets: [0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10],
      registers: [this.registry]
    });

    this.httpErrorsTotal = new Counter({
      name: 'http_errors_total',
      help: 'Total HTTP errors',
      labelNames: ['method', 'path', 'status'],
      registers: [this.registry]
    });

    // Database metrics
    this.databaseConnectionsActive = new Gauge({
      name: 'database_connections_active',
      help: 'Active database connections',
      registers: [this.registry]
    });

    this.databaseConnectionsSaturated = new Gauge({
      name: 'database_connections_saturated',
      help: 'Database connection pool saturation',
      registers: [this.registry]
    });

    this.databaseErrorsTotal = new Counter({
      name: 'database_errors_total',
      help: 'Total database errors',
      labelNames: ['operation', 'error_type'],
      registers: [this.registry]
    });

    // Business metrics
    this.usersCreatedTotal = new Counter({
      name: 'users_created_total',
      help: 'Total users created',
      registers: [this.registry]
    });

    this.ordersProcessedTotal = new Counter({
      name: 'orders_processed_total',
      help: 'Total orders processed',
      labelNames: ['status'],
      registers: [this.registry]
    });
  }

  getMetrics(): Promise<string> {
    return this.registry.metrics();
  }
}
```

**Metrics Middleware:**

```typescript
// infrastructure/http/metrics-middleware.ts
import { Request, Response, NextFunction } from 'express';
import { MetricsCollector } from '@infrastructure/metrics/metrics-collector';

export function metricsMiddleware(metrics: MetricsCollector) {
  return (req: Request, res: Response, next: NextFunction) => {
    const start = Date.now();

    res.on('finish', () => {
      const duration = (Date.now() - start) / 1000;
      const labels = {
        method: req.method,
        path: req.route?.path || req.path,
        status: res.statusCode.toString()
      };

      metrics.httpRequestsTotal.inc(labels);
      metrics.httpRequestDuration.observe(
        { method: req.method, path: req.route?.path || req.path },
        duration
      );

      if (res.statusCode >= 400) {
        metrics.httpErrorsTotal.inc(labels);
      }
    });

    next();
  };
}

// Metrics endpoint
export function metricsEndpoint(metrics: MetricsCollector) {
  return async (req: Request, res: Response) => {
    res.set('Content-Type', metrics.registry.contentType);
    res.end(await metrics.getMetrics());
  };
}
```

**Distributed Tracing (OpenTelemetry):**

```typescript
// infrastructure/tracing/tracer.ts
import { NodeSDK } from '@opentelemetry/sdk-node';
import { getNodeAutoInstrumentations } from '@opentelemetry/auto-instrumentations-node';
import { JaegerExporter } from '@opentelemetry/exporter-jaeger';

export class TracingService {
  private sdk?: NodeSDK;

  initialize(serviceName: string): void {
    if (process.env.TRACING_ENABLED !== 'true') {
      console.log('🔍 Tracing disabled');
      return;
    }

    const exporter = new JaegerExporter({
      endpoint: process.env.JAEGER_ENDPOINT || 'http://localhost:14268/api/traces'
    });

    this.sdk = new NodeSDK({
      serviceName,
      traceExporter: exporter,
      instrumentations: [getNodeAutoInstrumentations()]
    });

    this.sdk.start();
    console.log('🔍 Tracing initialized');
  }

  async shutdown(): Promise<void> {
    if (this.sdk) {
      await this.sdk.shutdown();
    }
  }
}
```

**Common Pitfalls:**
- Logging sensitive data (passwords, tokens)
- Not using correlation IDs
- Insufficient context in logs
- Missing performance metrics
- No distributed tracing

**Best Practices:**
- Use structured JSON logging
- Include correlation IDs in all logs
- Implement RED and USE metrics
- Expose /metrics and /health endpoints
- Use log levels appropriately
- Sanitize sensitive data before logging

---

### Principle 8: Automated Testing Strategy ⭐ MANDATORY

**Meta-Architecture Definition:**  
"Code MUST be testable and tested at multiple levels with 80%+ coverage."

**TypeScript Implementation:**

Use Jest or Vitest for comprehensive testing across the testing pyramid.

**Testing Pyramid:**

```
Manual Testing (10%)      - Exploratory, UI
────────────────────────────────────────────
E2E Tests (20%)          - Full system flows
────────────────────────────────────────────
Integration Tests (30%)  - Multi-component
────────────────────────────────────────────
Unit Tests (40%)         - Individual functions
```

**Test Configuration (Vitest):**

```typescript
// vitest.config.ts
import { defineConfig } from 'vitest/config';
import path from 'path';

export default defineConfig({
  test: {
    globals: true,
    environment: 'node',
    coverage: {
      provider: 'v8',
      reporter: ['text', 'json', 'html', 'lcov'],
      exclude: [
        'node_modules/',
        'dist/',
        '**/*.spec.ts',
        '**/*.test.ts',
        'src/foundation/types/',
        'vitest.config.ts'
      ],
      thresholds: {
        lines: 80,
        functions: 80,
        branches: 75,
        statements: 80
      }
    },
    setupFiles: ['./tests/setup.ts']
  },
  resolve: {
    alias: {
      '@foundation': path.resolve(__dirname, './src/foundation'),
      '@infrastructure': path.resolve(__dirname, './src/infrastructure'),
      '@integration': path.resolve(__dirname, './src/integration'),
      '@application': path.resolve(__dirname, './src/application')
    }
  }
});
```

**Unit Test Example:**

```typescript
// src/foundation/validation/email.spec.ts
import { describe, it, expect } from 'vitest';
import { isValidEmail } from './email';

describe('isValidEmail', () => {
  describe('valid emails', () => {
    it('should accept standard email', () => {
      expect(isValidEmail('user@example.com')).toBe(true);
    });

    it('should accept email with subdomain', () => {
      expect(isValidEmail('user@mail.example.com')).toBe(true);
    });

    it('should accept email with plus addressing', () => {
      expect(isValidEmail('user+tag@example.com')).toBe(true);
    });
  });

  describe('invalid emails', () => {
    it('should reject email without @', () => {
      expect(isValidEmail('userexample.com')).toBe(false);
    });

    it('should reject email without domain', () => {
      expect(isValidEmail('user@')).toBe(false);
    });

    it('should reject empty string', () => {
      expect(isValidEmail('')).toBe(false);
    });

    it('should reject email with spaces', () => {
      expect(isValidEmail('user @example.com')).toBe(false);
    });
  });
});
```

**Integration Test Example:**

```typescript
// tests/integration/user-service.spec.ts
import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { UserService } from '@application/services/user-service';
import { UserRepository } from '@integration/database/user-repository';
import { TestDatabase } from '../helpers/test-database';

describe('UserService Integration Tests', () => {
  let testDb: TestDatabase;
  let userService: UserService;
  let userRepository: UserRepository;

  beforeAll(async () => {
    testDb = new TestDatabase();
    await testDb.connect();
    await testDb.migrate();

    userRepository = new UserRepository(testDb.getConnection());
    userService = new UserService(userRepository);
  });

  afterAll(async () => {
    await testDb.disconnect();
  });

  it('should create user and retrieve by email', async () => {
    const email = 'test@example.com';
    const user = await userService.createUser({
      email,
      password: 'SecurePass123!',
      name: 'Test User'
    });

    expect(user.id).toBeDefined();
    expect(user.email).toBe(email);

    const retrieved = await userService.getUserByEmail(email);
    expect(retrieved).not.toBeNull();
    expect(retrieved?.id).toBe(user.id);
  });

  it('should not allow duplicate emails', async () => {
    const email = 'duplicate@example.com';
    
    await userService.createUser({
      email,
      password: 'SecurePass123!',
      name: 'User One'
    });

    await expect(
      userService.createUser({
        email,
        password: 'DifferentPass456!',
        name: 'User Two'
      })
    ).rejects.toThrow('User already exists');
  });
});
```

**E2E Test Example (Supertest):**

```typescript
// tests/e2e/user-registration.spec.ts
import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import request from 'supertest';
import { app } from '../../src/app';
import { TestDatabase } from '../helpers/test-database';

describe('User Registration E2E', () => {
  let testDb: TestDatabase;
  let server: any;

  beforeAll(async () => {
    testDb = new TestDatabase();
    await testDb.connect();
    await testDb.migrate();
    server = app.listen(0); // Random port
  });

  afterAll(async () => {
    await server.close();
    await testDb.disconnect();
  });

  it('should register a new user successfully', async () => {
    const response = await request(server)
      .post('/api/users/register')
      .send({
        email: 'newuser@example.com',
        password: 'SecurePass123!',
        name: 'New User',
        agreedToTerms: true
      })
      .expect(201);

    expect(response.body).toHaveProperty('id');
    expect(response.body.email).toBe('newuser@example.com');
  });

  it('should return 400 for invalid input', async () => {
    const response = await request(server)
      .post('/api/users/register')
      .send({
        email: 'invalid-email',
        password: '123'  // Too short
      })
      .expect(400);

    expect(response.body.error).toBe('INVALID_INPUT');
  });

  it('should return 409 for duplicate email', async () => {
    const email = 'duplicate@example.com';

    // First registration
    await request(server)
      .post('/api/users/register')
      .send({
        email,
        password: 'SecurePass123!',
        name: 'First User',
        agreedToTerms: true
      })
      .expect(201);

    // Second registration with same email
    await request(server)
      .post('/api/users/register')
      .send({
        email,
        password: 'DifferentPass456!',
        name: 'Second User',
        agreedToTerms: true
      })
      .expect(409);
  });
});
```

**Test Helpers:**

```typescript
// tests/helpers/test-database.ts
import { DataSource } from 'typeorm';

export class TestDatabase {
  private dataSource?: DataSource;

  async connect(): Promise<void> {
    this.dataSource = new DataSource({
      type: 'postgres',
      host: 'localhost',
      port: 5433,  // Different port for tests
      username: 'test',
      password: 'test',
      database: 'test_db',
      synchronize: false,
      logging: false
    });

    await this.dataSource.initialize();
  }

  async migrate(): Promise<void> {
    if (!this.dataSource) throw new Error('Not connected');
    await this.dataSource.runMigrations();
  }

  async disconnect(): Promise<void> {
    if (this.dataSource) {
      await this.dataSource.destroy();
    }
  }

  getConnection(): DataSource {
    if (!this.dataSource) throw new Error('Not connected');
    return this.dataSource;
  }
}
```

**Mocking with Vitest:**

```typescript
// tests/unit/email-service.spec.ts
import { describe, it, expect, vi } from 'vitest';
import { EmailService } from '@integration/messaging/email-service';

describe('EmailService', () => {
  it('should send email using primary provider', async () => {
    const mockProvider = {
      send: vi.fn().mockResolvedValue(undefined)
    };

    const emailService = new EmailService([mockProvider]);
    await emailService.sendEmail('test@example.com', 'Subject', 'Body');

    expect(mockProvider.send).toHaveBeenCalledWith(
      'test@example.com',
      'Subject',
      'Body'
    );
  });

  it('should fallback to secondary provider on failure', async () => {
    const primaryProvider = {
      send: vi.fn().mockRejectedValue(new Error('Primary failed'))
    };
    
    const secondaryProvider = {
      send: vi.fn().mockResolvedValue(undefined)
    };

    const emailService = new EmailService([primaryProvider, secondaryProvider]);
    await emailService.sendEmail('test@example.com', 'Subject', 'Body');

    expect(primaryProvider.send).toHaveBeenCalled();
    expect(secondaryProvider.send).toHaveBeenCalled();
  });
});
```

**Coverage Reporting:**

```bash
# Run tests with coverage
pnpm test -- --coverage

# View HTML report
open coverage/index.html
```

**Common Pitfalls:**
- Testing implementation instead of behavior
- Insufficient edge case coverage
- Flaky tests (timing issues)
- Not testing error paths
- No integration/e2e tests

**Best Practices:**
- Follow AAA pattern (Arrange, Act, Assert)
- Use descriptive test names
- Test one thing per test
- Mock external dependencies
- Use test databases (Docker)
- Run tests in CI/CD pipeline
- Fail builds on coverage drops

---

### Principle 9: Security by Design ⭐ MANDATORY

**Meta-Architecture Definition:**  
"Security MUST be built in from the start, not added later."

**TypeScript Implementation:**

Implement defense-in-depth with multiple security layers.

**Input Sanitization:**

```typescript
// foundation/security/sanitization.ts
import DOMPurify from 'isomorphic-dompurify';

export class SecuritySanitizer {
  /**
   * Sanitize HTML to prevent XSS
   */
  static sanitizeHtml(dirty: string): string {
    return DOMPurify.sanitize(dirty, {
      ALLOWED_TAGS: ['b', 'i', 'em', 'strong', 'a', 'p', 'br'],
      ALLOWED_ATTR: ['href', 'title']
    });
  }

  /**
   * Escape SQL identifiers (table/column names)
   */
  static escapeSqlIdentifier(identifier: string): string {
    if (!/^[a-zA-Z_][a-zA-Z0-9_]*$/.test(identifier)) {
      throw new Error('Invalid SQL identifier');
    }
    return identifier;
  }

  /**
   * Sanitize file paths to prevent path traversal
   */
  static sanitizeFilePath(filePath: string): string {
    // Remove any parent directory references
    const sanitized = filePath.replace(/\.\./g, '');
    
    // Remove leading slashes
    return sanitized.replace(/^\/+/, '');
  }

  /**
   * Strip potentially dangerous characters from user input
   */
  static stripDangerousChars(input: string): string {
    return input.replace(/[<>&'"]/g, '');
  }
}
```

**Authentication with JWT:**

```typescript
// infrastructure/security/auth-service.ts
import * as jwt from 'jsonwebtoken';
import * as bcrypt from 'bcrypt';
import { config } from '@infrastructure/config/config-loader';

export interface TokenPayload {
  userId: string;
  email: string;
  roles: string[];
}

export class AuthService {
  async hashPassword(password: string): Promise<string> {
    return bcrypt.hash(password, config.security.bcryptRounds);
  }

  async verifyPassword(password: string, hash: string): Promise<boolean> {
    return bcrypt.compare(password, hash);
  }

  generateAccessToken(payload: TokenPayload): string {
    return jwt.sign(payload, config.security.jwtSecret, {
      expiresIn: '15m',
      issuer: 'my-app',
      audience: 'my-app-users'
    });
  }

  generateRefreshToken(payload: TokenPayload): string {
    return jwt.sign(payload, config.security.jwtSecret, {
      expiresIn: '7d',
      issuer: 'my-app',
      audience: 'my-app-users'
    });
  }

  verifyToken(token: string): TokenPayload {
    try {
      const payload = jwt.verify(token, config.security.jwtSecret, {
        issuer: 'my-app',
        audience: 'my-app-users'
      });
      return payload as TokenPayload;
    } catch (error) {
      throw new Error('Invalid token');
    }
  }
}
```

**Authorization Middleware:**

```typescript
// infrastructure/http/auth-middleware.ts
import { Request, Response, NextFunction } from 'express';
import { AuthService } from '@infrastructure/security/auth-service';
import { PermissionError } from '@foundation/errors/domain-errors';

export function authenticateMiddleware(authService: AuthService) {
  return (req: Request, res: Response, next: NextFunction) => {
    const authHeader = req.headers.authorization;

    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return res.status(401).json({ error: 'Missing or invalid authorization header' });
    }

    const token = authHeader.substring(7);

    try {
      const payload = authService.verifyToken(token);
      req.user = payload;
      next();
    } catch (error) {
      return res.status(401).json({ error: 'Invalid or expired token' });
    }
  };
}

export function requireRole(...roles: string[]) {
  return (req: Request, res: Response, next: NextFunction) => {
    if (!req.user) {
      return res.status(401).json({ error: 'Unauthorized' });
    }

    const hasRole = roles.some(role => req.user!.roles.includes(role));
    if (!hasRole) {
      throw new PermissionError('access', 'resource');
    }

    next();
  };
}
```

**Rate Limiting:**

```typescript
// infrastructure/http/rate-limit-middleware.ts
import rateLimit from 'express-rate-limit';
import RedisStore from 'rate-limit-redis';
import { createClient } from 'redis';
import { config } from '@infrastructure/config/config-loader';

export function createRateLimiter() {
  if (config.redis?.enabled) {
    const redisClient = createClient({
      host: config.redis.host,
      port: config.redis.port
    });

    return rateLimit({
      store: new RedisStore({
        client: redisClient,
        prefix: 'rl:'
      }),
      windowMs: config.security.rateLimitWindowMs,
      max: config.security.rateLimitMax,
      message: 'Too many requests, please try again later'
    });
  }

  // Fallback to memory store
  return rateLimit({
    windowMs: config.security.rateLimitWindowMs,
    max: config.security.rateLimitMax,
    message: 'Too many requests, please try again later'
  });
}
```

**Security Headers (Helmet):**

```typescript
// infrastructure/http/security-headers.ts
import helmet from 'helmet';
import { Express } from 'express';

export function configureSecurityHeaders(app: Express): void {
  app.use(helmet({
    contentSecurityPolicy: {
      directives: {
        defaultSrc: ["'self'"],
        styleSrc: ["'self'", "'unsafe-inline'"],
        scriptSrc: ["'self'"],
        imgSrc: ["'self'", 'data:', 'https:'],
        connectSrc: ["'self'"],
        fontSrc: ["'self'"],
        objectSrc: ["'none'"],
        mediaSrc: ["'self'"],
        frameSrc: ["'none'"]
      }
    },
    hsts: {
      maxAge: 31536000,
      includeSubDomains: true,
      preload: true
    },
    referrerPolicy: {
      policy: 'strict-origin-when-cross-origin'
    }
  }));
}
```

**SQL Injection Prevention:**

```typescript
// integration/database/user-repository.ts
import { DataSource } from 'typeorm';

export class UserRepository {
  constructor(private dataSource: DataSource) {}

  async findByEmail(email: string): Promise<User | null> {
    // ✅ GOOD: Using parameterized query
    return this.dataSource
      .getRepository(User)
      .createQueryBuilder('user')
      .where('user.email = :email', { email })
      .getOne();

    // ❌ BAD: String concatenation (SQL injection risk!)
    // return this.dataSource.query(`SELECT * FROM users WHERE email = '${email}'`);
  }
}
```

**Common Pitfalls:**
- Storing passwords in plaintext
- Not validating/sanitizing inputs
- Exposing sensitive errors to clients
- Missing rate limiting
- No HTTPS enforcement
- Hardcoded secrets

**Best Practices:**
- Use parameterized queries (prevent SQL injection)
- Hash passwords with bcrypt/argon2
- Implement JWT with short expiration
- Use HTTPS only in production
- Apply security headers (Helmet)
- Implement rate limiting
- Regular security audits
- Keep dependencies updated

---

### Principle 10: Resource Lifecycle Management ⭐ MANDATORY

**Meta-Architecture Definition:**  
"All acquired resources MUST be properly released using deterministic cleanup patterns."

**TypeScript Implementation:**

Use async cleanup patterns and explicit resource management.

**Database Connection Management:**

```typescript
// integration/database/connection-manager.ts
import { DataSource } from 'typeorm';
import { Logger } from '@infrastructure/logging/logger';

export class DatabaseConnectionManager {
  private dataSource?: DataSource;
  private connected = false;

  constructor(
    private config: DatabaseConfig,
    private logger: Logger
  ) {}

  async connect(): Promise<void> {
    if (this.connected) {
      this.logger.warn('Database already connected');
      return;
    }

    this.dataSource = new DataSource({
      type: 'postgres',
      host: this.config.host,
      port: this.config.port,
      username: this.config.user,
      password: this.config.password,
      database: this.config.name,
      entities: ['src/**/*.entity.ts'],
      logging: false,
      poolSize: this.config.maxConnections
    });

    try {
      await this.dataSource.initialize();
      this.connected = true;
      this.logger.info('✅ Database connected');
    } catch (error) {
      this.logger.error('❌ Database connection failed', { error });
      throw error;
    }
  }

  async disconnect(): Promise<void> {
    if (!this.connected || !this.dataSource) {
      return;
    }

    try {
      await this.dataSource.destroy();
      this.connected = false;
      this.logger.info('Database disconnected');
    } catch (error) {
      this.logger.error('Error disconnecting database', { error });
      throw error;
    }
  }

  getConnection(): DataSource {
    if (!this.connected || !this.dataSource) {
      throw new Error('Database not connected');
    }
    return this.dataSource;
  }

  isConnected(): boolean {
    return this.connected && this.dataSource?.isInitialized === true;
  }
}
```

**Resource Manager Pattern:**

```typescript
// infrastructure/resources/resource-manager.ts
export interface ManagedResource {
  name: string;
  initialize(): Promise<void>;
  cleanup(): Promise<void>;
  healthCheck(): Promise<boolean>;
}

export class ResourceManager {
  private resources: ManagedResource[] = [];
  private initialized = false;

  register(resource: ManagedResource): void {
    this.resources.push(resource);
  }

  async initializeAll(): Promise<void> {
    if (this.initialized) {
      throw new Error('Resources already initialized');
    }

    for (const resource of this.resources) {
      try {
        await resource.initialize();
        console.log(`✅ ${resource.name} initialized`);
      } catch (error) {
        console.error(`❌ ${resource.name} initialization failed`, error);
        // Cleanup already initialized resources
        await this.cleanupAll();
        throw error;
      }
    }

    this.initialized = true;
  }

  async cleanupAll(): Promise<void> {
    // Cleanup in reverse order
    const reversedResources = [...this.resources].reverse();

    for (const resource of reversedResources) {
      try {
        await resource.cleanup();
        console.log(`🧹 ${resource.name} cleaned up`);
      } catch (error) {
        console.error(`❌ ${resource.name} cleanup failed`, error);
        // Continue with other cleanups even if one fails
      }
    }

    this.initialized = false;
  }

  async healthCheckAll(): Promise<Map<string, boolean>> {
    const results = new Map<string, boolean>();

    for (const resource of this.resources) {
      try {
        const healthy = await resource.healthCheck();
        results.set(resource.name, healthy);
      } catch {
        results.set(resource.name, false);
      }
    }

    return results;
  }
}
```

**Graceful Shutdown:**

```typescript
// infrastructure/lifecycle/shutdown-handler.ts
import { Server } from 'http';
import { ResourceManager } from '@infrastructure/resources/resource-manager';
import { Logger } from '@infrastructure/logging/logger';

export class ShutdownHandler {
  private isShuttingDown = false;

  constructor(
    private server: Server,
    private resourceManager: ResourceManager,
    private logger: Logger
  ) {
    this.registerSignalHandlers();
  }

  private registerSignalHandlers(): void {
    // Handle termination signals
    process.on('SIGTERM', () => this.handleShutdown('SIGTERM'));
    process.on('SIGINT', () => this.handleShutdown('SIGINT'));

    // Handle uncaught errors
    process.on('uncaughtException', (error) => {
      this.logger.fatal('Uncaught exception', { error });
      this.handleShutdown('UNCAUGHT_EXCEPTION');
    });

    process.on('unhandledRejection', (reason) => {
      this.logger.fatal('Unhandled promise rejection', { reason });
      this.handleShutdown('UNHANDLED_REJECTION');
    });
  }

  private async handleShutdown(signal: string): Promise<void> {
    if (this.isShuttingDown) {
      this.logger.warn('Shutdown already in progress');
      return;
    }

    this.isShuttingDown = true;
    this.logger.info(`🛑 Shutdown initiated (${signal})`);

    // Set shutdown timeout
    const shutdownTimeout = setTimeout(() => {
      this.logger.error('❌ Shutdown timeout - forcing exit');
      process.exit(1);
    }, 30000); // 30 seconds

    try {
      // 1. Stop accepting new connections
      this.server.close(() => {
        this.logger.info('HTTP server closed');
      });

      // 2. Wait for existing requests to complete (with timeout)
      await this.drainConnections();

      // 3. Cleanup all resources
      await this.resourceManager.cleanupAll();

      clearTimeout(shutdownTimeout);
      this.logger.info('✅ Graceful shutdown complete');
      process.exit(0);
    } catch (error) {
      clearTimeout(shutdownTimeout);
      this.logger.error('❌ Shutdown error', { error });
      process.exit(1);
    }
  }

  private async drainConnections(): Promise<void> {
    return new Promise((resolve) => {
      // Check if there are active connections
      const checkInterval = setInterval(() => {
        // @ts-ignore - accessing internal Node property
        if (this.server._connections === 0) {
          clearInterval(checkInterval);
          resolve();
        }
      }, 100);

      // Force resolve after 10 seconds
      setTimeout(() => {
        clearInterval(checkInterval);
        this.logger.warn('Force closing remaining connections');
        resolve();
      }, 10000);
    });
  }
}
```

**File Handle Management:**

```typescript
// foundation/io/file-manager.ts
import * as fs from 'fs/promises';
import { createReadStream, createWriteStream } from 'fs';
import { pipeline } from 'stream/promises';

export class FileManager {
  /**
   * Read file with automatic cleanup
   */
  static async readFile(path: string): Promise<string> {
    let fileHandle;
    try {
      fileHandle = await fs.open(path, 'r');
      return await fileHandle.readFile('utf-8');
    } finally {
      await fileHandle?.close();
    }
  }

  /**
   * Write file with automatic cleanup
   */
  static async writeFile(path: string, data: string): Promise<void> {
    let fileHandle;
    try {
      fileHandle = await fs.open(path, 'w');
      await fileHandle.writeFile(data);
    } finally {
      await fileHandle?.close();
    }
  }

  /**
   * Stream large file safely
   */
  static async streamFile(source: string, destination: string): Promise<void> {
    const readStream = createReadStream(source);
    const writeStream = createWriteStream(destination);

    try {
      await pipeline(readStream, writeStream);
    } catch (error) {
      // Streams are automatically closed by pipeline on error
      throw error;
    }
  }
}
```

**Memory Leak Prevention:**

```typescript
// infrastructure/cache/cache-with-ttl.ts
export class CacheWithTTL<T> {
  private cache = new Map<string, { value: T; expiresAt: number }>();
  private cleanupInterval: NodeJS.Timeout;

  constructor(private defaultTTL: number = 300000) {
    // Clean up expired entries every minute
    this.cleanupInterval = setInterval(() => {
      this.cleanup();
    }, 60000);
  }

  set(key: string, value: T, ttl?: number): void {
    const expiresAt = Date.now() + (ttl || this.defaultTTL);
    this.cache.set(key, { value, expiresAt });
  }

  get(key: string): T | null {
    const entry = this.cache.get(key);
    if (!entry) return null;

    if (Date.now() > entry.expiresAt) {
      this.cache.delete(key);
      return null;
    }

    return entry.value;
  }

  private cleanup(): void {
    const now = Date.now();
    for (const [key, entry] of this.cache.entries()) {
      if (now > entry.expiresAt) {
        this.cache.delete(key);
      }
    }
  }

  destroy(): void {
    clearInterval(this.cleanupInterval);
    this.cache.clear();
  }
}
```

**Common Pitfalls:**
- Not closing database connections
- Memory leaks from event listeners
- Orphaned timers/intervals
- Unclosed file handles
- Not handling cleanup on errors

**Best Practices:**
- Use try/finally for cleanup
- Implement graceful shutdown
- Clear timers/intervals
- Close file handles
- Use connection pooling
- Monitor resource usage
- Test cleanup paths

---

### Principle 11: Performance by Design ⚠️ RECOMMENDED

**Meta-Architecture Definition:**  
"Performance characteristics MUST be understood and acceptable by design."

**TypeScript Implementation:**

Implement caching, lazy loading, and performance monitoring.

**Caching Strategy:**

```typescript
// infrastructure/cache/cache-decorator.ts
export function Cacheable(ttl: number = 300) {
  return function (
    target: any,
    propertyKey: string,
    descriptor: PropertyDescriptor
  ) {
    const originalMethod = descriptor.value;
    const cache = new Map<string, { value: any; expiresAt: number }>();

    descriptor.value = async function (...args: any[]) {
      const key = JSON.stringify(args);
      const cached = cache.get(key);

      if (cached && Date.now() < cached.expiresAt) {
        return cached.value;
      }

      const result = await originalMethod.apply(this, args);
      cache.set(key, {
        value: result,
        expiresAt: Date.now() + ttl * 1000
      });

      return result;
    };

    return descriptor;
  };
}

// Usage
export class UserService {
  @Cacheable(300) // Cache for 5 minutes
  async getUserById(id: string): Promise<User> {
    return this.userRepository.findById(id);
  }
}
```

**Connection Pooling:**

```typescript
// integration/database/pooled-connection.ts
import { Pool, PoolConfig } from 'pg';

export class DatabasePool {
  private pool: Pool;

  constructor(config: PoolConfig) {
    this.pool = new Pool({
      ...config,
      max: 20,                   // Maximum connections
      idleTimeoutMillis: 30000,  // Close idle connections after 30s
      connectionTimeoutMillis: 2000,
    });

    // Monitor pool health
    this.pool.on('error', (err) => {
      console.error('Unexpected error on idle client', err);
    });
  }

  async query<T>(sql: string, params?: any[]): Promise<T[]> {
    const client = await this.pool.connect();
    try {
      const result = await client.query(sql, params);
      return result.rows;
    } finally {
      client.release(); // Return connection to pool
    }
  }

  async end(): Promise<void> {
    await this.pool.end();
  }
}
```

**Lazy Loading:**

```typescript
// infrastructure/services/lazy-service.ts
export class LazyService<T> {
  private instance?: T;
  private initializing = false;

  constructor(private factory: () => Promise<T>) {}

  async get(): Promise<T> {
    if (this.instance) {
      return this.instance;
    }

    if (this.initializing) {
      // Wait for initialization to complete
      while (this.initializing) {
        await new Promise(resolve => setTimeout(resolve, 10));
      }
      return this.instance!;
    }

    this.initializing = true;
    try {
      this.instance = await this.factory();
      return this.instance;
    } finally {
      this.initializing = false;
    }
  }
}

// Usage
const emailService = new LazyService(async () => {
  const config = await loadEmailConfig();
  return new EmailService(config);
});

// Only initialized when first used
const service = await emailService.get();
```

**Batch Operations:**

```typescript
// infrastructure/batch/batch-processor.ts
export class BatchProcessor<T, R> {
  private queue: T[] = [];
  private timer?: NodeJS.Timeout;

  constructor(
    private batchSize: number,
    private maxWaitMs: number,
    private processor: (items: T[]) => Promise<R[]>
  ) {}

  async add(item: T): Promise<R> {
    return new Promise((resolve, reject) => {
      this.queue.push(item);

      const queueIndex = this.queue.length - 1;

      // Process immediately if batch is full
      if (this.queue.length >= this.batchSize) {
        this.processBatch().then((results) => {
          resolve(results[queueIndex]);
        }).catch(reject);
        return;
      }

      // Schedule batch processing
      if (!this.timer) {
        this.timer = setTimeout(() => {
          this.processBatch().then((results) => {
            resolve(results[queueIndex]);
          }).catch(reject);
        }, this.maxWaitMs);
      }
    });
  }

  private async processBatch(): Promise<R[]> {
    if (this.timer) {
      clearTimeout(this.timer);
      this.timer = undefined;
    }

    const batch = this.queue.splice(0, this.batchSize);
    if (batch.length === 0) return [];

    return this.processor(batch);
  }
}

// Usage: Batch database inserts
const userBatch = new BatchProcessor<User, string>(
  100,    // Batch size
  1000,   // Max wait 1 second
  async (users) => {
    return await userRepository.insertMany(users);
  }
);

// Automatically batched
const userId = await userBatch.add(newUser);
```

**Performance Monitoring:**

```typescript
// infrastructure/monitoring/performance-monitor.ts
export class PerformanceMonitor {
  static measure<T>(
    name: string,
    fn: () => Promise<T>
  ): Promise<T> {
    const start = Date.now();
    return fn().finally(() => {
      const duration = Date.now() - start;
      console.log(`⏱️  ${name}: ${duration}ms`);
    });
  }

  static async profile<T>(
    name: string,
    fn: () => Promise<T>
  ): Promise<T> {
    const start = process.hrtime.bigint();
    const memBefore = process.memoryUsage();

    try {
      return await fn();
    } finally {
      const end = process.hrtime.bigint();
      const memAfter = process.memoryUsage();

      const durationMs = Number(end - start) / 1_000_000;
      const memDelta = {
        heapUsed: memAfter.heapUsed - memBefore.heapUsed,
        external: memAfter.external - memBefore.external
      };

      console.log(`📊 ${name}:`);
      console.log(`  Duration: ${durationMs.toFixed(2)}ms`);
      console.log(`  Heap: ${(memDelta.heapUsed / 1024 / 1024).toFixed(2)}MB`);
    }
  }
}
```

**Common Pitfalls:**
- No caching strategy
- N+1 query problems
- Blocking operations
- Memory leaks in long-running processes
- No performance budgets

**Best Practices:**
- Define performance SLOs
- Use caching strategically
- Implement connection pooling
- Batch database operations
- Use lazy loading
- Profile regularly
- Monitor in production

---

### Principle 12: Evolutionary Architecture ⚠️ RECOMMENDED

**Meta-Architecture Definition:**  
"Architecture MUST support change without requiring complete rewrites."

**TypeScript Implementation:**

Implement versioning, feature flags, and migration strategies.

**API Versioning:**

```typescript
// application/api/versioned-router.ts
import { Router } from 'express';

export class VersionedRouter {
  private routers: Map<string, Router> = new Map();

  registerVersion(version: string, router: Router): void {
    this.routers.set(version, router);
  }

  getRouter(): Router {
    const mainRouter = Router();

    // Version from header (preferred)
    mainRouter.use((req, res, next) => {
      const version = req.headers['api-version'] as string || 'v1';
      const versionRouter = this.routers.get(version);

      if (!versionRouter) {
        return res.status(400).json({
          error: 'Invalid API version',
          supportedVersions: Array.from(this.routers.keys())
        });
      }

      versionRouter(req, res, next);
    });

    return mainRouter;
  }
}

// Usage
const v1Router = Router();
v1Router.get('/users/:id', getUserV1);

const v2Router = Router();
v2Router.get('/users/:id', getUserV2);

const versionedRouter = new VersionedRouter();
versionedRouter.registerVersion('v1', v1Router);
versionedRouter.registerVersion('v2', v2Router);

app.use('/api', versionedRouter.getRouter());
```

**Feature Flags:**

```typescript
// infrastructure/features/feature-flags.ts
export interface FeatureFlag {
  enabled: boolean;
  rolloutPercentage?: number;
  allowedUsers?: string[];
  allowedRoles?: string[];
}

export class FeatureFlagService {
  private flags: Map<string, FeatureFlag> = new Map();

  constructor(private config: Record<string, FeatureFlag>) {
    for (const [name, flag] of Object.entries(config)) {
      this.flags.set(name, flag);
    }
  }

  isEnabled(
    featureName: string,
    userId?: string,
    userRoles?: string[]
  ): boolean {
    const flag = this.flags.get(featureName);
    if (!flag) return false;

    // Always disabled
    if (!flag.enabled) return false;

    // Check user whitelist
    if (flag.allowedUsers && userId) {
      if (flag.allowedUsers.includes(userId)) return true;
    }

    // Check role whitelist
    if (flag.allowedRoles && userRoles) {
      if (userRoles.some(role => flag.allowedRoles!.includes(role))) {
        return true;
      }
    }

    // Percentage rollout
    if (flag.rolloutPercentage !== undefined) {
      if (!userId) return false;
      const hash = this.hashString(userId + featureName);
      return hash % 100 < flag.rolloutPercentage;
    }

    return true;
  }

  private hashString(str: string): number {
    let hash = 0;
    for (let i = 0; i < str.length; i++) {
      hash = ((hash << 5) - hash) + str.charCodeAt(i);
      hash = hash & hash; // Convert to 32-bit integer
    }
    return Math.abs(hash);
  }
}

// Usage
const features = new FeatureFlagService({
  newDashboard: {
    enabled: true,
    rolloutPercentage: 10  // 10% of users
  },
  advancedAnalytics: {
    enabled: true,
    allowedRoles: ['admin', 'analyst']
  },
  betaFeature: {
    enabled: true,
    allowedUsers: ['user123', 'user456']
  }
});

// In controller
if (features.isEnabled('newDashboard', req.user.id)) {
  return renderNewDashboard();
} else {
  return renderOldDashboard();
}
```

**Database Migrations:**

```typescript
// integration/database/migrations/migration-runner.ts
export interface Migration {
  version: number;
  name: string;
  up: (db: Database) => Promise<void>;
  down: (db: Database) => Promise<void>;
}

export class MigrationRunner {
  constructor(
    private db: Database,
    private migrations: Migration[]
  ) {
    this.migrations.sort((a, b) => a.version - b.version);
  }

  async migrate(): Promise<void> {
    await this.ensureMigrationTable();
    const currentVersion = await this.getCurrentVersion();

    for (const migration of this.migrations) {
      if (migration.version > currentVersion) {
        console.log(`🔄 Running migration ${migration.version}: ${migration.name}`);
        await migration.up(this.db);
        await this.setVersion(migration.version);
        console.log(`✅ Migration ${migration.version} complete`);
      }
    }
  }

  async rollback(targetVersion: number): Promise<void> {
    const currentVersion = await this.getCurrentVersion();
    const toRollback = this.migrations
      .filter(m => m.version > targetVersion && m.version <= currentVersion)
      .reverse();

    for (const migration of toRollback) {
      console.log(`⏪ Rolling back migration ${migration.version}: ${migration.name}`);
      await migration.down(this.db);
      await this.setVersion(migration.version - 1);
      console.log(`✅ Rollback ${migration.version} complete`);
    }
  }

  private async ensureMigrationTable(): Promise<void> {
    await this.db.query(`
      CREATE TABLE IF NOT EXISTS schema_migrations (
        version INT PRIMARY KEY,
        applied_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);
  }

  private async getCurrentVersion(): Promise<number> {
    const result = await this.db.query<{ version: number }>(
      'SELECT MAX(version) as version FROM schema_migrations'
    );
    return result[0]?.version || 0;
  }

  private async setVersion(version: number): Promise<void> {
    await this.db.query(
      'INSERT INTO schema_migrations (version) VALUES ($1)',
      [version]
    );
  }
}
```

**Deprecation Strategy:**

```typescript
// infrastructure/deprecation/deprecation-handler.ts
export interface DeprecationNotice {
  feature: string;
  deprecatedSince: string;
  removedIn: string;
  replacement?: string;
  message: string;
}

export class DeprecationHandler {
  private notices: Map<string, DeprecationNotice> = new Map();
  private warnings: Set<string> = new Set();

  registerDeprecation(feature: string, notice: DeprecationNotice): void {
    this.notices.set(feature, notice);
  }

  warnIfDeprecated(feature: string): void {
    const notice = this.notices.get(feature);
    if (!notice) return;

    // Only warn once per feature per process
    if (this.warnings.has(feature)) return;
    this.warnings.add(feature);

    console.warn('⚠️  DEPRECATION WARNING:');
    console.warn(`  Feature: ${notice.feature}`);
    console.warn(`  Deprecated since: ${notice.deprecatedSince}`);
    console.warn(`  Will be removed in: ${notice.removedIn}`);
    if (notice.replacement) {
      console.warn(`  Use instead: ${notice.replacement}`);
    }
    console.warn(`  ${notice.message}`);
  }
}

// Usage
const deprecation = new DeprecationHandler();

deprecation.registerDeprecation('oldUserAPI', {
  feature: 'GET /api/v1/users',
  deprecatedSince: 'v2.0.0',
  removedIn: 'v3.0.0',
  replacement: 'GET /api/v2/users',
  message: 'The v1 users API will be removed in version 3.0.0'
});

// In controller
app.get('/api/v1/users', (req, res) => {
  deprecation.warnIfDeprecated('oldUserAPI');
  res.setHeader('Deprecation', 'version="v2.0.0"');
  res.setHeader('Sunset', new Date('2025-12-31').toUTCString());
  // ... handle request
});
```

**Common Pitfalls:**
- Breaking changes without versioning
- No migration strategy
- Hard-coded business logic
- Tightly coupled components
- No deprecation warnings

**Best Practices:**
- Semantic versioning
- Feature flags for gradual rollouts
- Database migrations (up/down)
- Deprecation notices
- Backward compatibility
- Strangler pattern for rewrites

---

## 4. Implementation Patterns

### Directory Structure

Standard TypeScript project structure following the four-layer architecture:

```
my-typescript-app/
├── src/
│   ├── foundation/              # Layer 1: Primitives
│   │   ├── types/
│   │   │   ├── common.ts
│   │   │   └── index.ts
│   │   ├── validation/
│   │   │   ├── email.ts
│   │   │   ├── schemas.ts
│   │   │   └── sanitization.ts
│   │   ├── errors/
│   │   │   ├── base-error.ts
│   │   │   ├── error-codes.ts
│   │   │   └── domain-errors.ts
│   │   └── utils/
│   │       ├── string.ts
│   │       ├── date.ts
│   │       └── crypto.ts
│   │
│   ├── infrastructure/          # Layer 2: Core services
│   │   ├── config/
│   │   │   ├── config-loader.ts
│   │   │   ├── schema.ts
│   │   │   └── secrets.ts
│   │   ├── logging/
│   │   │   └── logger.ts
│   │   ├── cache/
│   │   │   ├── cache-manager.ts
│   │   │   └── cache-decorator.ts
│   │   ├── metrics/
│   │   │   └── metrics-collector.ts
│   │   ├── security/
│   │   │   └── auth-service.ts
│   │   ├── http/
│   │   │   ├── error-handler.ts
│   │   │   ├── validation-middleware.ts
│   │   │   ├── auth-middleware.ts
│   │   │   └── metrics-middleware.ts
│   │   ├── resources/
│   │   │   └── resource-manager.ts
│   │   └── lifecycle/
│   │       └── shutdown-handler.ts
│   │
│   ├── integration/             # Layer 3: External systems
│   │   ├── database/
│   │   │   ├── connection-manager.ts
│   │   │   ├── user-repository.ts
│   │   │   └── migrations/
│   │   ├── messaging/
│   │   │   └── email-service.ts
│   │   ├── http/
│   │   │   └── external-api-client.ts
│   │   └── cache/
│   │       └── redis-client.ts
│   │
│   └── application/             # Layer 4: Business logic
│       ├── services/
│       │   └── user-service.ts
│       ├── controllers/
│       │   ├── user-controller.ts
│       │   └── health-controller.ts
│       ├── workflows/
│       │   └── user-registration-workflow.ts
│       └── api/
│           └── versioned-router.ts
│
├── tests/
│   ├── unit/
│   │   └── foundation/
│   ├── integration/
│   │   └── services/
│   ├── e2e/
│   │   └── api/
│   └── helpers/
│       ├── test-database.ts
│       └── test-helpers.ts
│
├── config/
│   ├── default.json
│   ├── development.json
│   ├── staging.json
│   └── production.json
│
├── scripts/
│   ├── migrate.ts
│   └── seed.ts
│
├── docs/
│   ├── API.md
│   ├── ARCHITECTURE.md
│   └── DEPLOYMENT.md
│
├── .env.example
├── .eslintrc.js
├── .prettierrc
├── .gitignore
├── tsconfig.json
├── vitest.config.ts
├── package.json
└── README.md
```

### Naming Conventions

**Files and Directories:**
- Use kebab-case for directories: `user-service/`
- Use kebab-case for files: `user-service.ts`
- Test files: `user-service.spec.ts` or `user-service.test.ts`
- Type definition files: `user.types.ts`

**Code:**
- Interfaces: `PascalCase` with descriptive names (e.g., `UserRepository`, `EmailConfig`)
- Classes: `PascalCase` (e.g., `UserService`, `Logger`)
- Functions/Methods: `camelCase` (e.g., `getUserById`, `validateEmail`)
- Constants: `SCREAMING_SNAKE_CASE` (e.g., `MAX_RETRY_ATTEMPTS`, `DEFAULT_TIMEOUT`)
- Private members: prefix with `_` or use `#` for private fields
- Type parameters: Single uppercase letter or `PascalCase` (e.g., `T`, `TUser`, `TResponse`)

### Module Exports

Use barrel exports (`index.ts`) for clean public APIs:

```typescript
// foundation/validation/index.ts
export * from './email';
export * from './schemas';
export { SecuritySanitizer } from './sanitization';
```

### Dependency Injection

```typescript
// application/services/user-service.ts
import { UserRepository } from '@integration/database/user-repository';
import { EmailService } from '@integration/messaging/email-service';
import { Logger } from '@infrastructure/logging/logger';

export class UserService {
  constructor(
    private readonly userRepository: UserRepository,
    private readonly emailService: EmailService,
    private readonly logger: Logger
  ) {}

  async registerUser(data: UserRegistrationData): Promise<User> {
    this.logger.info('Registering user', { email: data.email });
    
    const user = await this.userRepository.create(data);
    await this.emailService.sendWelcomeEmail(user.email);
    
    return user;
  }
}
```

---

## 5. Complete Code Examples

### Example 1: Full REST API Server

```typescript
// src/app.ts
import express, { Express } from 'express';
import { config } from '@infrastructure/config/config-loader';
import { Logger } from '@infrastructure/logging/logger';
import { MetricsCollector } from '@infrastructure/metrics/metrics-collector';
import { ResourceManager } from '@infrastructure/resources/resource-manager';
import { DatabaseConnectionManager } from '@integration/database/connection-manager';
import { errorHandler } from '@infrastructure/http/error-handler';
import { correlationMiddleware } from '@infrastructure/http/correlation-middleware';
import { metricsMiddleware } from '@infrastructure/http/metrics-middleware';
import { createRateLimiter } from '@infrastructure/http/rate-limit-middleware';
import { configureSecurityHeaders } from '@infrastructure/http/security-headers';
import { ShutdownHandler } from '@infrastructure/lifecycle/shutdown-handler';
import { UserRouter } from '@application/api/user-router';

export async function createApp(): Promise<Express> {
  const app = express();

  // Middleware
  app.use(express.json());
  app.use(express.urlencoded({ extended: true }));

  // Infrastructure
  const logger = new Logger({
    level: config.logging.level,
    pretty: config.logging.pretty
  });

  const metrics = new MetricsCollector();
  const resourceManager = new ResourceManager();

  // Database
  const dbManager = new DatabaseConnectionManager(config.database, logger);
  resourceManager.register({
    name: 'database',
    initialize: () => dbManager.connect(),
    cleanup: () => dbManager.disconnect(),
    healthCheck: () => Promise.resolve(dbManager.isConnected())
  });

  // Security headers
  configureSecurityHeaders(app);

  // Rate limiting
  app.use('/api/', createRateLimiter());

  // Correlation & metrics
  app.use(correlationMiddleware);
  app.use(metricsMiddleware(metrics));

  // Health check
  app.get('/health', async (req, res) => {
    const health = await resourceManager.healthCheckAll();
    const allHealthy = Array.from(health.values()).every(v => v);

    res.status(allHealthy ? 200 : 503).json({
      status: allHealthy ? 'healthy' : 'unhealthy',
      dependencies: Object.fromEntries(health)
    });
  });

  // Metrics endpoint
  app.get('/metrics', async (req, res) => {
    res.set('Content-Type', 'text/plain');
    res.send(await metrics.getMetrics());
  });

  // API routes
  const userRouter = new UserRouter(dbManager, logger);
  app.use('/api/v1/users', userRouter.getRouter());

  // Error handler (must be last)
  app.use(errorHandler(logger));

  // Initialize resources
  await resourceManager.initializeAll();

  // Graceful shutdown
  const server = app.listen(config.app.port, () => {
    logger.info(`🚀 Server running on port ${config.app.port}`);
  });

  new ShutdownHandler(server, resourceManager, logger);

  return app;
}

// Start server
if (require.main === module) {
  createApp().catch((error) => {
    console.error('Failed to start server:', error);
    process.exit(1);
  });
}
```

### Example 2: User Registration Workflow

```typescript
// application/workflows/user-registration-workflow.ts
import { UserService } from '@application/services/user-service';
import { EmailService } from '@integration/messaging/email-service';
import { Logger } from '@infrastructure/logging/logger';
import { MetricsCollector } from '@infrastructure/metrics/metrics-collector';
import { ValidationError, BusinessRuleError } from '@foundation/errors/domain-errors';
import { UserRegistrationSchema } from '@foundation/validation/schemas';

export interface RegistrationRequest {
  email: string;
  password: string;
  name: string;
  agreedToTerms: boolean;
}

export class UserRegistrationWorkflow {
  constructor(
    private userService: UserService,
    private emailService: EmailService,
    private metrics: MetricsCollector,
    private logger: Logger
  ) {}

  async execute(request: RegistrationRequest): Promise<{ userId: string; success: boolean }> {
    const correlationId = Math.random().toString(36);
    const workflowLogger = this.logger.child({ correlationId, workflow: 'user-registration' });

    workflowLogger.info('Starting user registration workflow', {
      email: request.email
    });

    try {
      // Step 1: Validate input
      workflowLogger.debug('Step 1: Validating input');
      const validatedData = UserRegistrationSchema.parse(request);

      // Step 2: Check if user exists
      workflowLogger.debug('Step 2: Checking if user exists');
      const existingUser = await this.userService.getUserByEmail(validatedData.email);
      if (existingUser) {
        throw new BusinessRuleError('User with this email already exists');
      }

      // Step 3: Create user
      workflowLogger.debug('Step 3: Creating user');
      const user = await this.userService.createUser(validatedData);

      // Step 4: Send welcome email (non-critical - don't fail workflow)
      workflowLogger.debug('Step 4: Sending welcome email');
      try {
        await this.emailService.sendWelcomeEmail(user.email, user.name);
      } catch (error) {
        workflowLogger.warn('Failed to send welcome email', { error });
        // Continue anyway - email is not critical
      }

      // Step 5: Record metrics
      this.metrics.usersCreatedTotal.inc();

      workflowLogger.info('User registration workflow completed successfully', {
        userId: user.id
      });

      return {
        userId: user.id,
        success: true
      };

    } catch (error) {
      workflowLogger.error('User registration workflow failed', { error });
      throw error;
    }
  }
}
```

---

## 6. Tool Recommendations

### Development Tools

**IDE/Editors:**
- [VS Code](https://code.visualstudio.com/) with extensions:
  - ESLint
  - Prettier
  - TypeScript and JavaScript Language Features
  - Path Intellisense
- [WebStorm](https://www.jetbrains.com/webstorm/) (commercial)

**Linting & Formatting:**
- **ESLint** - Linting and code quality
- **Prettier** - Code formatting
- **TypeScript ESLint** - TypeScript-specific linting
- **eslint-config-airbnb-typescript** - Comprehensive style guide

**Type Checking:**
- **TypeScript** - Static type checking
- **ts-node** - Execute TypeScript directly
- **tsx** - Fast TypeScript execution

### Testing Tools

**Test Frameworks:**
- **Vitest** - Fast unit test runner (recommended)
- **Jest** - Popular test framework
- **Mocha** + **Chai** - Traditional choice

**Testing Utilities:**
- **Supertest** - HTTP assertions
- **@testing-library/react** - React component testing
- **Playwright** / **Cypress** - E2E testing
- **Mock Service Worker (MSW)** - API mocking

**Coverage:**
- **c8** / **istanbul** - Coverage reporting

### Build Tools

**Bundlers:**
- **esbuild** - Fast, minimal configuration
- **swc** - Rust-based compiler
- **Vite** - Modern build tool
- **Webpack** - Mature, feature-rich
- **tsup** - Bundle TypeScript libraries

**Package Managers:**
- **pnpm** - Fast, disk-efficient (recommended for monorepos)
- **npm** - Default Node.js package manager
- **yarn** - Facebook's package manager

### CI/CD

**Platforms:**
- GitHub Actions
- GitLab CI
- CircleCI
- Jenkins

**Docker:**
- Docker for containerization
- Docker Compose for local development
- Multi-stage builds for production

### Monitoring & Observability

**Logging:**
- **Pino** - Fast JSON logger
- **Winston** - Feature-rich logger
- **Bunyan** - Structured logging

**Metrics:**
- **Prometheus** - Time-series metrics
- **prom-client** - Prometheus client for Node.js
- **Grafana** - Metrics visualization

**Tracing:**
- **OpenTelemetry** - Distributed tracing standard
- **Jaeger** - Distributed tracing backend
- **Zipkin** - Alternative tracing solution

**APM:**
- **Datadog** - Full-stack monitoring
- **New Relic** - Application performance monitoring
- **Sentry** - Error tracking

### Security Tools

**Vulnerability Scanning:**
- `npm audit` - Built-in vulnerability checker
- **Snyk** - Security scanning
- **Dependabot** - Automated dependency updates

**Code Security:**
- **ESLint Security Plugin** - Security-focused linting
- **TSLint Security** - TypeScript security rules
- **SonarQube** - Code quality and security

**Runtime Security:**
- **Helmet** - Security headers for Express
- **CORS** - Cross-origin resource sharing
- **express-rate-limit** - Rate limiting

---

## 7. Testing Strategy

### Test Organization

```
tests/
├── unit/                    # 40% of tests
│   ├── foundation/
│   ├── infrastructure/
│   └── application/
├── integration/             # 30% of tests
│   ├── database/
│   └── services/
├── e2e/                     # 20% of tests
│   └── api/
├── performance/             # 5% of tests
│   └── load-tests/
├── security/                # 5% of tests
│   └── penetration-tests/
└── helpers/
    ├── fixtures.ts
    ├── mocks.ts
    └── test-database.ts
```

### Coverage Goals

**Overall:** 80%+ line coverage

**By Layer:**
- Foundation: 95%+ (pure functions, critical utilities)
- Infrastructure: 85%+ (core services)
- Integration: 75%+ (external dependencies, harder to test)
- Application: 80%+ (business logic)

**Critical Paths:** 100% coverage
- Authentication/Authorization
- Payment processing
- Data validation
- Error handling

### Test Naming Convention

```typescript
describe('[Unit/Component Name]', () => {
  describe('[Method/Function Name]', () => {
    describe('[Scenario/Context]', () => {
      it('should [expected behavior]', () => {
        // Test implementation
      });
    });
  });
});
```

Example:

```typescript
describe('UserService', () => {
  describe('createUser', () => {
    describe('when valid data is provided', () => {
      it('should create a user and return the user object', async () => {
        // Test
      });
    });

    describe('when email is already registered', () => {
      it('should throw BusinessRuleError', async () => {
        // Test
      });
    });
  });
});
```

### Testing Best Practices

1. **Use AAA Pattern:**
   - Arrange: Setup test data
   - Act: Execute the behavior
   - Assert: Verify the outcome

2. **Test Isolation:**
   - Each test should be independent
   - Clean up after each test
   - Don't rely on test execution order

3. **Mock External Dependencies:**
   - Database connections
   - External APIs
   - File system operations
   - Time-dependent functions

4. **Test Error Scenarios:**
   - Invalid inputs
   - Network failures
   - Timeout scenarios
   - Edge cases

5. **Performance Tests:**
   - Response time under load
   - Memory usage
   - Concurrent requests
   - Database query performance

---

## 8. Deployment Guidelines

### Build Process

**Production Build:**

```bash
# Install dependencies
pnpm install --frozen-lockfile

# Run linting
pnpm lint

# Run type checking
pnpm type-check

# Run tests
pnpm test

# Build for production
pnpm build

# Output in dist/
```

**package.json scripts:**

```json
{
  "scripts": {
    "dev": "tsx watch src/app.ts",
    "build": "tsup src/app.ts --format esm,cjs --dts",
    "start": "node dist/app.js",
    "test": "vitest run",
    "test:watch": "vitest",
    "test:coverage": "vitest run --coverage",
    "lint": "eslint src/**/*.ts",
    "lint:fix": "eslint src/**/*.ts --fix",
    "type-check": "tsc --noEmit",
    "migrate": "tsx scripts/migrate.ts"
  }
}
```

### Docker Configuration

**Multi-stage Dockerfile:**

```dockerfile
# Stage 1: Dependencies
FROM node:20-alpine AS deps
WORKDIR /app

COPY package.json pnpm-lock.yaml ./
RUN npm install -g pnpm && pnpm install --frozen-lockfile

# Stage 2: Build
FROM node:20-alpine AS builder
WORKDIR /app

COPY --from=deps /app/node_modules ./node_modules
COPY . .

RUN npm run build

# Stage 3: Production
FROM node:20-alpine AS runner
WORKDIR /app

ENV NODE_ENV=production

# Create non-root user
RUN addgroup --system --gid 1001 nodejs
RUN adduser --system --uid 1001 appuser

# Copy built files
COPY --from=builder /app/dist ./dist
COPY --from=builder /app/node_modules ./node_modules
COPY --from=builder /app/package.json ./

USER appuser

EXPOSE 3000

CMD ["node", "dist/app.js"]
```

**docker-compose.yml for development:**

```yaml
version: '3.8'

services:
  app:
    build:
      context: .
      target: deps
    ports:
      - "3000:3000"
    environment:
      NODE_ENV: development
      DB_HOST: postgres
      DB_PORT: 5432
      DB_NAME: myapp
      DB_USER: postgres
      DB_PASSWORD: postgres
      REDIS_HOST: redis
      REDIS_PORT: 6379
    volumes:
      - .:/app
      - /app/node_modules
    depends_on:
      - postgres
      - redis

  postgres:
    image: postgres:16-alpine
    ports:
      - "5432:5432"
    environment:
      POSTGRES_DB: myapp
      POSTGRES_USER: postgres
      POSTGRES_PASSWORD: postgres
    volumes:
      - postgres_data:/var/lib/postgresql/data

  redis:
    image: redis:7-alpine
    ports:
      - "6379:6379"
    volumes:
      - redis_data:/data

volumes:
  postgres_data:
  redis_data:
```

### Environment Configuration

**Production Environment Variables:**

```bash
# Application
NODE_ENV=production
PORT=3000

# Database
DB_HOST=prod-db.example.com
DB_PORT=5432
DB_NAME=myapp_prod
DB_USER=myapp_prod_user
DB_PASSWORD=${DB_PASSWORD_SECRET}  # From secrets manager
DB_SSL=true
DB_MAX_CONNECTIONS=20

# Redis
REDIS_ENABLED=true
REDIS_HOST=prod-redis.example.com
REDIS_PORT=6379
REDIS_PASSWORD=${REDIS_PASSWORD_SECRET}

# Security
JWT_SECRET=${JWT_SECRET}  # From secrets manager
BCRYPT_ROUNDS=12

# Logging
LOG_LEVEL=info
LOG_PRETTY=false

# Monitoring
PROMETHEUS_ENABLED=true
TRACING_ENABLED=true
JAEGER_ENDPOINT=https://jaeger.example.com/api/traces

# Features
FEATURE_EMAIL_VERIFICATION=true
FEATURE_SOCIAL_LOGIN=true
```

### Kubernetes Deployment

**deployment.yaml:**

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: myapp
  labels:
    app: myapp
spec:
  replicas: 3
  selector:
    matchLabels:
      app: myapp
  template:
    metadata:
      labels:
        app: myapp
    spec:
      containers:
      - name: myapp
        image: myapp:latest
        ports:
        - containerPort: 3000
        env:
        - name: NODE_ENV
          value: "production"
        - name: DB_HOST
          valueFrom:
            configMapKeyRef:
              name: myapp-config
              key: db-host
        - name: DB_PASSWORD
          valueFrom:
            secretKeyRef:
              name: myapp-secrets
              key: db-password
        - name: JWT_SECRET
          valueFrom:
            secretKeyRef:
              name: myapp-secrets
              key: jwt-secret
        livenessProbe:
          httpGet:
            path: /health
            port: 3000
          initialDelaySeconds: 30
          periodSeconds: 10
        readinessProbe:
          httpGet:
            path: /health
            port: 3000
          initialDelaySeconds: 5
          periodSeconds: 5
        resources:
          requests:
            memory: "256Mi"
            cpu: "250m"
          limits:
            memory: "512Mi"
            cpu: "500m"
```

### Monitoring Setup

**Prometheus Configuration:**

```yaml
# prometheus.yml
global:
  scrape_interval: 15s

scrape_configs:
  - job_name: 'myapp'
    static_configs:
      - targets: ['myapp:3000']
    metrics_path: '/metrics'
```

**Grafana Dashboard:**
- Import pre-built Node.js dashboard
- Create custom dashboard for business metrics
- Setup alerts for critical thresholds

### CI/CD Pipeline

**GitHub Actions:**

```yaml
# .github/workflows/ci.yml
name: CI/CD

on:
  push:
    branches: [main]
  pull_request:
    branches: [main]

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      
      - uses: pnpm/action-setup@v2
        with:
          version: 8
      
      - uses: actions/setup-node@v3
        with:
          node-version: '20'
          cache: 'pnpm'
      
      - run: pnpm install --frozen-lockfile
      
      - run: pnpm lint
      
      - run: pnpm type-check
      
      - run: pnpm test -- --coverage
      
      - name: Upload coverage
        uses: codecov/codecov-action@v3

  build:
    needs: test
    runs-on: ubuntu-latest
    if: github.ref == 'refs/heads/main'
    steps:
      - uses: actions/checkout@v3
      
      - uses: docker/setup-buildx-action@v2
      
      - uses: docker/login-action@v2
        with:
          registry: ghcr.io
          username: ${{ github.actor }}
          password: ${{ secrets.GITHUB_TOKEN }}
      
      - uses: docker/build-push-action@v4
        with:
          push: true
          tags: ghcr.io/${{ github.repository }}:latest
          cache-from: type=registry,ref=ghcr.io/${{ github.repository }}:buildcache
          cache-to: type=registry,ref=ghcr.io/${{ github.repository }}:buildcache,mode=max
```

---

## 9. Compliance Checklist

Use this checklist to verify compliance with Meta-Architecture v1.0.0:

### Layer Architecture
- [ ] Four layers defined (foundation, infrastructure, integration, application)
- [ ] No upward dependencies (enforced by ESLint)
- [ ] Each layer has clear responsibilities
- [ ] Path mapping configured in tsconfig.json
- [ ] Import linter rules configured
- [ ] Layer violations fail CI build

### Dependency Management
- [ ] package.json with explicit versions
- [ ] Lock file committed (pnpm-lock.yaml/package-lock.json)
- [ ] Optional dependencies marked clearly
- [ ] No circular dependencies
- [ ] Regular security audits (npm audit)
- [ ] Automated dependency updates (Dependabot)

### Graceful Degradation
- [ ] Dependencies classified (CRITICAL/IMPORTANT/OPTIONAL)
- [ ] Fallback strategies implemented
- [ ] Health check endpoint exposes degraded state
- [ ] Graceful degradation tested
- [ ] Dependency registry implemented

### Input Validation
- [ ] Zod schemas for all external inputs
- [ ] Validation at system boundaries
- [ ] Sanitization for outputs (HTML, SQL)
- [ ] Error messages don't expose sensitive data
- [ ] Validation failures logged

### Error Handling
- [ ] Custom error classes with standard codes
- [ ] Error codes documented
- [ ] Errors include context and timestamp
- [ ] Retryable errors identified
- [ ] Error handler middleware configured
- [ ] Errors logged appropriately

### Configuration
- [ ] Hierarchical configuration implemented
- [ ] Default values for all config
- [ ] Secrets not in version control
- [ ] .env.example provided
- [ ] Configuration validated at startup
- [ ] Environment-specific configs

### Observability
- [ ] Structured logging (Pino)
- [ ] Correlation IDs in all logs
- [ ] Metrics endpoint (/metrics)
- [ ] RED metrics implemented (Rate, Errors, Duration)
- [ ] Health check endpoint (/health)
- [ ] Distributed tracing configured (optional)

### Testing
- [ ] Unit tests (40%+ of test suite)
- [ ] Integration tests (30%+ of test suite)
- [ ] E2E tests (20%+ of test suite)
- [ ] 80%+ line coverage overall
- [ ] Critical paths 100% covered
- [ ] Tests run in CI/CD
- [ ] Coverage gates enforced

### Security
- [ ] Input validation comprehensive
- [ ] Passwords hashed (bcrypt/argon2)
- [ ] JWT authentication implemented
- [ ] Security headers configured (Helmet)
- [ ] Rate limiting implemented
- [ ] HTTPS enforced in production
- [ ] SQL injection prevention (parameterized queries)
- [ ] XSS prevention (output encoding)
- [ ] Secrets management (not hardcoded)
- [ ] Regular security audits

### Resource Management
- [ ] Database connections properly closed
- [ ] File handles released
- [ ] Timers/intervals cleared
- [ ] Event listeners removed
- [ ] Graceful shutdown implemented
- [ ] Connection pooling used
- [ ] Memory leaks prevented

### Performance
- [ ] Caching strategy implemented
- [ ] Connection pooling configured
- [ ] Lazy loading for optional features
- [ ] Batch operations for bulk data
- [ ] Performance monitoring in place
- [ ] SLOs defined and tracked
- [ ] Performance tests in CI

### Evolution
- [ ] Semantic versioning used
- [ ] API versioning strategy
- [ ] Feature flags implemented
- [ ] Database migrations (up/down)
- [ ] Deprecation policy defined
- [ ] Breaking changes documented
- [ ] Backward compatibility maintained

---

## 10. Migration Guide

### From Existing TypeScript Project

Follow this step-by-step guide to migrate an existing TypeScript project to this architecture.

#### Phase 1: Assessment (Week 1)

**1. Audit Current State:**

```bash
# Analyze project structure
tree -L 3 src/

# Check dependencies
npm list --depth=0

# Check test coverage
npm test -- --coverage

# Check for security issues
npm audit
```

**2. Document Current Architecture:**
- Draw current directory structure
- Identify major components
- List external dependencies
- Document configuration approach
- Note testing strategy

**3. Identify Gaps:**
- Which principles are missing?
- What needs refactoring?
- What can be kept as-is?

#### Phase 2: Setup (Week 2)

**1. Create New Layer Structure:**

```bash
mkdir -p src/{foundation,infrastructure,integration,application}
mkdir -p src/foundation/{types,validation,errors,utils}
mkdir -p src/infrastructure/{config,logging,cache,metrics,http}
mkdir -p src/integration/{database,messaging,http}
mkdir -p src/application/{services,controllers,workflows}
```

**2. Configure Path Mapping:**

```json
// tsconfig.json
{
  "compilerOptions": {
    "baseUrl": "./src",
    "paths": {
      "@foundation/*": ["foundation/*"],
      "@infrastructure/*": ["infrastructure/*"],
      "@integration/*": ["integration/*"],
      "@application/*": ["application/*"]
    }
  }
}
```

**3. Setup ESLint Layer Rules:**

```javascript
// .eslintrc.js
module.exports = {
  // ... existing config
  rules: {
    'import/no-restricted-paths': [
      'error',
      {
        zones: [
          { target: './src/foundation', from: './src/infrastructure' },
          { target: './src/foundation', from: './src/integration' },
          { target: './src/foundation', from: './src/application' },
          { target: './src/infrastructure', from: './src/integration' },
          { target: './src/infrastructure', from: './src/application' },
          { target: './src/integration', from: './src/application' }
        ]
      }
    ]
  }
};
```

#### Phase 3: Incremental Migration (Weeks 3-8)

**Week 3-4: Foundation Layer**

1. Move utility functions to `foundation/utils/`
2. Create error classes in `foundation/errors/`
3. Add validation in `foundation/validation/`
4. Define types in `foundation/types/`

```bash
# Example migration
mv src/utils/string-helpers.ts src/foundation/utils/string.ts
mv src/utils/date-helpers.ts src/foundation/utils/date.ts
```

**Week 5: Infrastructure Layer**

1. Implement configuration system
2. Setup structured logging
3. Add metrics collection
4. Create HTTP middleware

**Week 6: Integration Layer**

1. Refactor database access
2. Migrate external API clients
3. Setup message queues
4. Implement caching

**Week 7: Application Layer**

1. Move business logic to services
2. Create controllers
3. Implement workflows
4. Setup API routes

**Week 8: Testing & Documentation**

1. Write tests for migrated code
2. Update documentation
3. Add compliance checklist
4. Train team

#### Phase 4: Validation (Week 9)

**1. Run Compliance Checklist:**
- Verify all 12 principles implemented
- Check test coverage meets goals
- Validate security measures
- Review error handling

**2. Performance Testing:**
- Load testing
- Memory profiling
- Database query optimization

**3. Security Audit:**
- Run npm audit
- Check for common vulnerabilities
- Review authentication/authorization

#### Phase 5: Deployment (Week 10)

**1. Staging Deployment:**
- Deploy to staging environment
- Run smoke tests
- Monitor logs and metrics

**2. Production Rollout:**
- Deploy to production
- Monitor closely
- Have rollback plan ready

**3. Post-Migration:**
- Gather feedback
- Address issues
- Document lessons learned

### Tips for Successful Migration

1. **Incremental Approach:**
   - Don't try to migrate everything at once
   - Start with foundation layer
   - Migrate one layer at a time

2. **Maintain Functionality:**
   - Keep old code working during migration
   - Use feature flags for gradual rollout
   - Test thoroughly before removing old code

3. **Team Collaboration:**
   - Regular sync meetings
   - Code reviews for migrated code
   - Share knowledge and learnings

4. **Documentation:**
   - Update docs as you migrate
   - Document new patterns
   - Create migration runbook

5. **Testing:**
   - Write tests before refactoring
   - Maintain or improve coverage
   - Test both old and new code paths

---

## Version History

### 1.0.0 (2025-11-10)
- Initial release
- Full compliance with Meta-Architecture v1.0.0
- All 12 principles implemented
- Complete code examples
- Comprehensive testing strategy
- Production-ready deployment guide

---

## References

- **Meta-Architecture v1.0.0**: Universal principles governing software architecture
- **TypeScript Documentation**: https://www.typescriptlang.org/docs/
- **Node.js Best Practices**: https://github.com/goldbergyoni/nodebestpractices
- **OWASP Top 10**: https://owasp.org/www-project-top-ten/
- **The Twelve-Factor App**: https://12factor.net/

---

**Template Maintainer**: Architecture Team  
**Last Reviewed**: 2025-11-10  
**License**: MIT  
**Contact**: See governance documentation for questions and proposals

---

**END OF TYPESCRIPT ARCHITECTURE TEMPLATE v1.0.0**
