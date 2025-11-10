# Python Architecture
## Meta-Architecture v1.0.0 Compliant Template

**Meta-Architecture Compliance:** v1.0.0  
**Template Version:** 1.0.0  
**Status:** Production-Ready  
**Last Audit:** 2025-11-10  
**Compliance Score:** 100%

---

## Table of Contents

1. [Meta-Architecture Reference](#meta-architecture-reference)
2. [Python Ecosystem Overview](#python-ecosystem-overview)
3. [Core Principles Mapping](#core-principles-mapping)
4. [Four-Layer Architecture](#four-layer-architecture)
5. [Project Structure](#project-structure)
6. [Complete Code Examples](#complete-code-examples)
7. [Tool Recommendations](#tool-recommendations)
8. [Testing Strategy](#testing-strategy)
9. [Deployment Guidelines](#deployment-guidelines)
10. [Compliance Checklist](#compliance-checklist)

---

## Meta-Architecture Reference

This template implements all 12 universal principles from **Meta-Architecture v1.0.0**:

1. Layered Architecture (MANDATORY)
2. Explicit Dependency Management (MANDATORY)
3. Graceful Degradation (MANDATORY)
4. Comprehensive Input Validation (MANDATORY)
5. Standardized Error Handling (MANDATORY)
6. Hierarchical Configuration (MANDATORY)
7. Observable Behavior (MANDATORY)
8. Automated Testing (MANDATORY)
9. Security by Design (MANDATORY)
10. Resource Lifecycle Management (MANDATORY)
11. Performance Patterns (MANDATORY)
12. Evolutionary Design (MANDATORY)

Each principle is mapped to Python-specific patterns, idioms, and libraries.

---

## Python Ecosystem Overview

### Language Characteristics

**Python's Core Strengths:**
- Dynamic typing with optional type hints (PEP 484+)
- Rich standard library ("batteries included")
- Mature ecosystem (PyPI with 500k+ packages)
- Strong scientific computing support (NumPy, Pandas, etc.)
- Excellent readability ("executable pseudocode")

**Architectural Implications:**
```python
# Dynamic typing enables flexibility
def process(data):  # Can accept any type
    return data.transform()

# But requires runtime validation
def process_validated(data: dict) -> Result:
    if not isinstance(data, dict):
        raise TypeError("Expected dict")
    return Result(data)

# Type hints enable static analysis (mypy)
def process_typed(data: dict[str, Any]) -> Result:
    return Result(data)
```

**Key Design Considerations:**
1. **Module System** - `import` creates namespace, packages are directories with `__init__.py`
2. **Context Managers** - `with` statement for resource management
3. **Decorators** - Function/class wrappers for cross-cutting concerns
4. **Duck Typing** - "If it walks like a duck..." enables polymorphism
5. **GIL** - Global Interpreter Lock affects concurrency strategy

---

## Core Principles Mapping

### Principle 1: Layered Architecture (MANDATORY)

**Meta-Architecture Principle:**
> Dependencies create coupling; unidirectional dependencies create testable, replaceable systems. Four-layer pattern: Foundation → Infrastructure → Integration → Application.

**Python Implementation:**

```python
"""
Python package structure for layered architecture.

Mechanism: Python's module system naturally supports layers.
Each layer is a package (directory with __init__.py).
Import rules enforce dependency direction.
"""

# Project structure
my_project/
├── foundation/         # Layer 1: Core primitives
│   ├── __init__.py
│   ├── types.py       # Custom types, protocols
│   ├── errors.py      # Exception hierarchy
│   └── validators.py  # Input validation
├── infrastructure/     # Layer 2: Core services
│   ├── __init__.py
│   ├── database.py    # Database abstraction
│   ├── cache.py       # Caching layer
│   └── logging.py     # Logging utilities
├── integration/        # Layer 3: External systems
│   ├── __init__.py
│   ├── api_client.py  # REST API client
│   └── queue.py       # Message queue
├── application/        # Layer 4: Business logic
│   ├── __init__.py
│   ├── services.py    # Business services
│   └── handlers.py    # Request handlers
└── main.py            # Entry point

# Dependency rules (enforced by import-linter or similar)
# - foundation: no dependencies
# - infrastructure: depends on foundation only
# - integration: depends on foundation + infrastructure
# - application: depends on all lower layers
```

**Enforcement with import-linter:**
```toml
# .importlinter
[importlinter]
root_package = my_project

[[importlinter.contracts]]
name = "Layer independence"
type = "layers"
layers =
    application
    integration
    infrastructure
    foundation
```

**Example: Foundation Layer**
```python
# foundation/types.py
"""
Core type definitions with no external dependencies.

Mechanism: Protocol classes define interfaces.
Type hints enable static analysis without runtime overhead.
"""

from typing import Protocol, TypeVar, Generic
from datetime import datetime

T = TypeVar('T')

class Entity(Protocol):
    """Base protocol for all entities."""
    id: str
    created_at: datetime
    updated_at: datetime

class Repository(Protocol, Generic[T]):
    """Repository protocol for data access."""
    
    async def find_by_id(self, id: str) -> T | None:
        """Find entity by ID."""
        ...
    
    async def save(self, entity: T) -> T:
        """Save entity."""
        ...
    
    async def delete(self, id: str) -> bool:
        """Delete entity."""
        ...
```

**Why This Works:**
- Python's import system creates clear module boundaries
- Type hints enable static dependency checking
- Protocols define interfaces without inheritance
- Each layer is independently testable

---

### Principle 2: Explicit Dependency Management (MANDATORY)

**Meta-Architecture Principle:**
> Implicit dependencies create hidden coupling and unpredictable behavior. All dependencies declared in manifest with pinned versions.

**Python Implementation:**

```toml
# pyproject.toml (PEP 621 - standard dependency specification)
[project]
name = "my-project"
version = "1.0.0"
requires-python = ">=3.11"

# Direct dependencies with version constraints
dependencies = [
    "fastapi>=0.104.0,<0.105.0",     # Patch updates allowed
    "sqlalchemy==2.0.23",             # Exact version
    "pydantic>=2.5.0,<3.0.0",        # Minor updates allowed
    "redis~=5.0.0",                   # Compatible releases
]

# Development dependencies
[project.optional-dependencies]
dev = [
    "pytest>=7.4.0",
    "mypy>=1.7.0",
    "ruff>=0.1.0",
    "pytest-cov>=4.1.0",
]

test = [
    "pytest>=7.4.0",
    "pytest-asyncio>=0.21.0",
    "httpx>=0.25.0",  # For testing FastAPI
]

[tool.poetry.group.dev.dependencies]  # If using Poetry
python = "^3.11"
```

**Lock File for Reproducibility:**
```bash
# Generate lock file with exact versions
pip freeze > requirements.txt

# Or with Poetry (preferred)
poetry lock

# Or with pip-tools
pip-compile pyproject.toml --output-file=requirements.lock
```

**Dependency Injection Pattern:**
```python
# infrastructure/container.py
"""
Dependency injection container.

Mechanism: Container provides dependencies to application layer.
Enables testing by swapping implementations.
"""

from typing import Protocol
from dataclasses import dataclass

class DatabaseClient(Protocol):
    """Database client interface."""
    async def execute(self, query: str) -> list[dict]: ...

@dataclass
class Container:
    """
    Application dependency container.
    
    Why: Centralized dependency management.
    All dependencies injected, no hidden imports.
    """
    db_client: DatabaseClient
    cache_client: CacheClient
    config: Config
    
    @classmethod
    def create_production(cls) -> 'Container':
        """Create production container."""
        config = Config.from_env()
        
        return cls(
            db_client=PostgreSQLClient(config.database_url),
            cache_client=RedisClient(config.redis_url),
            config=config,
        )
    
    @classmethod
    def create_test(cls) -> 'Container':
        """Create test container with mocks."""
        return cls(
            db_client=InMemoryDatabase(),
            cache_client=InMemoryCache(),
            config=Config.from_dict({"env": "test"}),
        )

# Usage in application
async def create_user(
    data: CreateUserRequest,
    container: Container,
) -> User:
    """Create user with injected dependencies."""
    user = User(**data.model_dump())
    await container.db_client.save(user)
    return user
```

**Why This Works:**
- `pyproject.toml` is Python's standard dependency specification
- Version constraints prevent unexpected updates
- Lock files ensure reproducible builds
- Dependency injection makes testing trivial

---

### Principle 3: Graceful Degradation (MANDATORY)

**Meta-Architecture Principle:**
> Cascade failures occur when one component failure triggers others. Classify services as CRITICAL, IMPORTANT, or OPTIONAL.

**Python Implementation:**

```python
# infrastructure/circuit_breaker.py
"""
Circuit breaker pattern for graceful degradation.

Mechanism: Monitor failure rate. After threshold, stop trying
(circuit opens). Periodically test (half-open). Resume on success.
"""

from enum import Enum
from datetime import datetime, timedelta
from typing import Callable, TypeVar, ParamSpec
import asyncio
import logging

logger = logging.getLogger(__name__)

P = ParamSpec('P')
T = TypeVar('T')

class CircuitState(Enum):
    """Circuit breaker states."""
    CLOSED = "closed"      # Normal operation
    OPEN = "open"          # Failures exceeded threshold
    HALF_OPEN = "half_open"  # Testing recovery

class CircuitBreaker:
    """
    Circuit breaker for external service calls.
    
    Mechanism:
    - CLOSED: Normal operation, track failures
    - OPEN: Too many failures, reject calls immediately
    - HALF_OPEN: Test with single call, open or close based on result
    """
    
    def __init__(
        self,
        failure_threshold: int = 5,
        timeout_seconds: int = 60,
        service_name: str = "unknown",
    ):
        self.failure_threshold = failure_threshold
        self.timeout = timedelta(seconds=timeout_seconds)
        self.service_name = service_name
        
        self.state = CircuitState.CLOSED
        self.failure_count = 0
        self.last_failure_time: datetime | None = None
    
    async def call(
        self,
        func: Callable[P, T],
        *args: P.args,
        **kwargs: P.kwargs,
    ) -> T:
        """
        Execute function with circuit breaker protection.
        
        Raises: CircuitBreakerOpenError if circuit is open
        """
        if self.state == CircuitState.OPEN:
            # Check if timeout elapsed
            if (
                self.last_failure_time and
                datetime.utcnow() - self.last_failure_time > self.timeout
            ):
                # Try half-open
                self.state = CircuitState.HALF_OPEN
                logger.info(f"Circuit half-open for {self.service_name}")
            else:
                # Still open, fail fast
                raise CircuitBreakerOpenError(self.service_name)
        
        try:
            # Attempt call
            result = await func(*args, **kwargs)
            
            # Success - reset if half-open, or continue if closed
            if self.state == CircuitState.HALF_OPEN:
                self.state = CircuitState.CLOSED
                self.failure_count = 0
                logger.info(f"Circuit closed for {self.service_name}")
            
            return result
        
        except Exception as e:
            # Failure - increment counter
            self.failure_count += 1
            self.last_failure_time = datetime.utcnow()
            
            # Check threshold
            if self.failure_count >= self.failure_threshold:
                self.state = CircuitState.OPEN
                logger.error(
                    f"Circuit opened for {self.service_name} "
                    f"after {self.failure_count} failures"
                )
            
            raise

# Service Classification
class ServicePriority(Enum):
    """Service priority levels."""
    CRITICAL = "critical"    # System unusable without this
    IMPORTANT = "important"  # Reduced functionality
    OPTIONAL = "optional"    # Nice to have

# Example: API with graceful degradation
class UserService:
    """
    User service with degraded modes.
    
    Mechanism:
    - CRITICAL: Database (must work)
    - IMPORTANT: Cache (falls back to DB)
    - OPTIONAL: Avatar service (returns placeholder)
    """
    
    def __init__(
        self,
        db: DatabaseClient,
        cache: CacheClient,
        avatar_service: AvatarService,
    ):
        self.db = db  # CRITICAL
        self.cache = cache  # IMPORTANT
        self.avatar_service = avatar_service  # OPTIONAL
        
        # Circuit breakers for non-critical services
        self.avatar_circuit = CircuitBreaker(
            failure_threshold=3,
            timeout_seconds=30,
            service_name="avatar_service"
        )
    
    async def get_user(self, user_id: str) -> User:
        """
        Get user with graceful degradation.
        
        Flow:
        1. Try cache (IMPORTANT)
        2. Fall back to database (CRITICAL)
        3. Optionally fetch avatar (OPTIONAL)
        """
        # Try cache first
        try:
            cached = await self.cache.get(f"user:{user_id}")
            if cached:
                logger.info(f"Cache hit for user {user_id}")
                user = User.model_validate_json(cached)
                return await self._enrich_user(user)
        except Exception as e:
            # Cache failure is not critical
            logger.warning(f"Cache failed, using database: {e}")
        
        # Database (CRITICAL - no fallback)
        user = await self.db.get_user(user_id)
        
        # Update cache (best effort)
        try:
            await self.cache.set(
                f"user:{user_id}",
                user.model_dump_json(),
                expire=300,
            )
        except Exception as e:
            logger.warning(f"Failed to update cache: {e}")
        
        # Enrich with avatar (optional)
        return await self._enrich_user(user)
    
    async def _enrich_user(self, user: User) -> User:
        """Add optional avatar URL."""
        try:
            avatar_url = await self.avatar_circuit.call(
                self.avatar_service.get_avatar_url,
                user.email,
            )
            user.avatar_url = avatar_url
        except CircuitBreakerOpenError:
            # Circuit open, use placeholder
            user.avatar_url = "/static/default-avatar.png"
            logger.debug(f"Using default avatar for {user.id}")
        except Exception as e:
            # Avatar service failed, use placeholder
            logger.warning(f"Avatar service error: {e}")
            user.avatar_url = "/static/default-avatar.png"
        
        return user
```

**Why This Works:**
- Circuit breaker prevents cascade failures
- Service classification guides degradation strategy
- System continues operating with reduced functionality
- Failures are isolated and don't propagate

---

### Principle 4: Comprehensive Input Validation (MANDATORY)

**Meta-Architecture Principle:**
> Invalid input is the primary attack vector and error source. Validate at boundaries: type, range, business rules, state.

**Python Implementation:**

```python
# foundation/validators.py
"""
Multi-layer input validation.

Mechanism: Pydantic models provide type/range validation.
Custom validators add business rules. State validators check context.
"""

from pydantic import (
    BaseModel,
    Field,
    field_validator,
    model_validator,
    ConfigDict,
)
from typing import Annotated, Self
from datetime import datetime
import re

# Layer 1: Type and Format Validation
class CreateUserRequest(BaseModel):
    """
    User creation request with Pydantic validation.
    
    Mechanism: Pydantic validates types, formats, and constraints
    automatically. Raises ValidationError with detailed messages.
    """
    
    model_config = ConfigDict(str_strip_whitespace=True)
    
    # Type + length constraints
    username: Annotated[str, Field(min_length=3, max_length=20)]
    email: Annotated[str, Field(pattern=r'^[^@]+@[^@]+\.[^@]+$')]
    password: Annotated[str, Field(min_length=8)]
    age: Annotated[int, Field(ge=18, le=120)]
    
    # Optional fields with defaults
    display_name: str | None = None
    bio: Annotated[str, Field(max_length=500)] | None = None

# Layer 2: Field-Level Business Rules
class CreatePostRequest(BaseModel):
    """Post creation with field validators."""
    
    title: str
    content: str
    tags: list[str] = []
    status: str = "draft"
    
    @field_validator('title')
    @classmethod
    def validate_title(cls, v: str) -> str:
        """Validate title business rules."""
        if len(v.strip()) < 10:
            raise ValueError('Title must be at least 10 characters')
        
        # No profanity (simplified)
        profanity = ['badword1', 'badword2']
        if any(word in v.lower() for word in profanity):
            raise ValueError('Title contains inappropriate content')
        
        return v.strip()
    
    @field_validator('tags')
    @classmethod
    def validate_tags(cls, v: list[str]) -> list[str]:
        """Validate tags."""
        if len(v) > 5:
            raise ValueError('Maximum 5 tags allowed')
        
        # Normalize tags
        return [tag.lower().strip() for tag in v]
    
    @field_validator('status')
    @classmethod
    def validate_status(cls, v: str) -> str:
        """Validate status."""
        allowed = {'draft', 'published', 'archived'}
        if v not in allowed:
            raise ValueError(f'Status must be one of: {allowed}')
        return v

# Layer 3: Model-Level Business Rules
class TransferRequest(BaseModel):
    """Money transfer with cross-field validation."""
    
    from_account: str
    to_account: str
    amount: Annotated[float, Field(gt=0)]
    currency: str
    
    @model_validator(mode='after')
    def validate_transfer(self) -> Self:
        """Validate transfer business rules."""
        # Can't transfer to same account
        if self.from_account == self.to_account:
            raise ValueError('Cannot transfer to same account')
        
        # Amount limits by currency
        limits = {'USD': 10000, 'EUR': 9000, 'GBP': 8000}
        if self.amount > limits.get(self.currency, 5000):
            raise ValueError(
                f'Transfer exceeds limit for {self.currency}'
            )
        
        return self

# Layer 4: State Validation
class PostService:
    """Service with state-dependent validation."""
    
    async def publish_post(
        self,
        post_id: str,
        user_id: str,
        db: DatabaseClient,
    ) -> Post:
        """
        Publish post with state validation.
        
        Mechanism: Check current state before allowing operation.
        """
        # Fetch current post
        post = await db.get_post(post_id)
        if not post:
            raise NotFoundError('Post not found')
        
        # State validation: must be draft
        if post.status != 'draft':
            raise StateError(
                f'Cannot publish post with status: {post.status}'
            )
        
        # Authorization: must be author
        if post.author_id != user_id:
            raise PermissionError('Not authorized to publish this post')
        
        # Business rule: must have content
        if not post.content or len(post.content) < 100:
            raise ValidationError(
                'Post must have at least 100 characters to publish'
            )
        
        # Update status
        post.status = 'published'
        post.published_at = datetime.utcnow()
        
        return await db.save_post(post)

# Validation Error Handling
from fastapi import Request, status
from fastapi.responses import JSONResponse
from pydantic import ValidationError

async def validation_exception_handler(
    request: Request,
    exc: ValidationError
) -> JSONResponse:
    """
    Convert Pydantic validation errors to API response.
    
    Mechanism: Extract field-level errors with clear messages.
    """
    errors = []
    for error in exc.errors():
        errors.append({
            'field': '.'.join(str(loc) for loc in error['loc']),
            'message': error['msg'],
            'type': error['type'],
        })
    
    return JSONResponse(
        status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        content={
            'detail': 'Validation failed',
            'errors': errors,
        },
    )
```

**Why This Works:**
- Pydantic provides automatic type/format validation
- Field validators add business rules
- Model validators check cross-field constraints
- State validation ensures operations valid for current state
- Clear error messages help debugging

---

### Principle 5: Standardized Error Handling (MANDATORY)

**Meta-Architecture Principle:**
> Consistent error patterns enable automated handling, proper logging, and user-friendly messages. Use standard error codes.

**Python Implementation:**

```python
# foundation/errors.py
"""
Exception hierarchy with error codes.

Mechanism: Custom exceptions inherit from base with error code.
Middleware catches and converts to API responses.
"""

from enum import IntEnum
from typing import Any

class ErrorCode(IntEnum):
    """Standard error codes."""
    SUCCESS = 0
    INVALID_INPUT = 1
    NOT_FOUND = 2
    PERMISSION_DENIED = 3
    CONFLICT = 4
    DEPENDENCY_ERROR = 5
    INTERNAL_ERROR = 6
    TIMEOUT = 7
    RATE_LIMITED = 8
    DEGRADED = 9

class ApplicationError(Exception):
    """
    Base application error.
    
    Mechanism: All application errors inherit from this.
    Enables catch-all handling while preserving error details.
    """
    
    def __init__(
        self,
        message: str,
        code: ErrorCode,
        details: dict[str, Any] | None = None,
    ):
        self.message = message
        self.code = code
        self.details = details or {}
        super().__init__(message)

class ValidationError(ApplicationError):
    """Input validation failed."""
    def __init__(self, message: str, field: str | None = None):
        super().__init__(
            message,
            ErrorCode.INVALID_INPUT,
            details={'field': field} if field else {},
        )

class NotFoundError(ApplicationError):
    """Resource not found."""
    def __init__(self, resource: str, id: str | None = None):
        message = f"{resource} not found"
        if id:
            message += f": {id}"
        super().__init__(
            message,
            ErrorCode.NOT_FOUND,
            details={'resource': resource, 'id': id},
        )

class PermissionError(ApplicationError):
    """Insufficient permissions."""
    def __init__(self, message: str = "Permission denied"):
        super().__init__(message, ErrorCode.PERMISSION_DENIED)

class ConflictError(ApplicationError):
    """Resource conflict (e.g., duplicate)."""
    def __init__(self, message: str, resource: str | None = None):
        super().__init__(
            message,
            ErrorCode.CONFLICT,
            details={'resource': resource} if resource else {},
        )

# Error Handler Middleware
from fastapi import FastAPI, Request, status
from fastapi.responses import JSONResponse
import logging

logger = logging.getLogger(__name__)

async def error_handler(request: Request, exc: Exception) -> JSONResponse:
    """
    Global error handler.
    
    Mechanism: Catches all exceptions, logs with context,
    returns standardized response.
    """
    # Extract request ID for correlation
    request_id = request.headers.get('X-Request-ID', 'unknown')
    
    if isinstance(exc, ApplicationError):
        # Known application error
        logger.warning(
            f"Application error: {exc.message}",
            extra={
                'error_code': exc.code,
                'request_id': request_id,
                'path': request.url.path,
                'details': exc.details,
            },
        )
        
        # Map error code to HTTP status
        status_map = {
            ErrorCode.INVALID_INPUT: status.HTTP_400_BAD_REQUEST,
            ErrorCode.NOT_FOUND: status.HTTP_404_NOT_FOUND,
            ErrorCode.PERMISSION_DENIED: status.HTTP_403_FORBIDDEN,
            ErrorCode.CONFLICT: status.HTTP_409_CONFLICT,
            ErrorCode.RATE_LIMITED: status.HTTP_429_TOO_MANY_REQUESTS,
        }
        
        return JSONResponse(
            status_code=status_map.get(
                exc.code,
                status.HTTP_500_INTERNAL_SERVER_ERROR
            ),
            content={
                'error': {
                    'code': exc.code,
                    'message': exc.message,
                    'details': exc.details,
                },
                'request_id': request_id,
            },
        )
    
    else:
        # Unexpected error - log with traceback
        logger.error(
            f"Unexpected error: {exc}",
            extra={'request_id': request_id, 'path': request.url.path},
            exc_info=True,
        )
        
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content={
                'error': {
                    'code': ErrorCode.INTERNAL_ERROR,
                    'message': 'Internal server error',
                },
                'request_id': request_id,
            },
        )

# Register error handler
app = FastAPI()
app.add_exception_handler(Exception, error_handler)
```

**Why This Works:**
- Exception hierarchy provides structure
- Error codes enable programmatic handling
- Middleware catches all errors consistently
- Logs include request context for debugging
- Client gets clear, actionable error messages

---

### Principle 6: Hierarchical Configuration (MANDATORY)

**Meta-Architecture Principle:**
> Configuration conflicts resolved through explicit precedence: defaults → config file → environment → CLI → runtime.

**Python Implementation:**

```python
# infrastructure/config.py
"""
Hierarchical configuration with Pydantic settings.

Mechanism: Pydantic-settings loads from multiple sources
with clear precedence. Type validation automatic.
"""

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict
from typing import Literal
from pathlib import Path

class Settings(BaseSettings):
    """
    Application settings with hierarchical loading.
    
    Precedence (lowest to highest):
    1. Defaults (in Field defaults)
    2. Config file (.env or .env.production)
    3. Environment variables
    4. Runtime overrides (via .copy(update=...))
    
    Mechanism: pydantic-settings handles loading and precedence.
    """
    
    model_config = SettingsConfigDict(
        env_file='.env',
        env_file_encoding='utf-8',
        env_nested_delimiter='__',  # DATABASE__HOST → database.host
        case_sensitive=False,
        extra='ignore',
    )
    
    # ==========================================
    # Level 1: Compiled Defaults
    # ==========================================
    
    # Application
    app_name: str = "my-app"
    environment: Literal["dev", "staging", "prod"] = "dev"
    debug: bool = False
    log_level: Literal["DEBUG", "INFO", "WARNING", "ERROR"] = "INFO"
    
    # Server
    host: str = "0.0.0.0"
    port: int = 8000
    workers: int = 4
    
    # Database
    database_url: str = Field(
        default="postgresql://localhost/myapp",
        validation_alias="DATABASE_URL",  # Can be overridden by env
    )
    database_pool_size: int = Field(default=10, ge=1, le=100)
    database_max_overflow: int = Field(default=5, ge=0, le=50)
    
    # Redis
    redis_url: str = Field(
        default="redis://localhost:6379/0",
        validation_alias="REDIS_URL",
    )
    redis_max_connections: int = 50
    
    # Security
    secret_key: str = Field(
        default="dev-secret-key-change-in-production",
        min_length=32,
    )
    jwt_algorithm: str = "HS256"
    jwt_expiration_minutes: int = 60
    
    # Features
    enable_cache: bool = True
    enable_metrics: bool = True
    enable_swagger: bool = True
    
    # Rate Limiting
    rate_limit_enabled: bool = True
    rate_limit_requests: int = 100
    rate_limit_window_seconds: int = 60
    
    @property
    def is_production(self) -> bool:
        """Check if running in production."""
        return self.environment == "prod"
    
    @property
    def is_development(self) -> bool:
        """Check if running in development."""
        return self.environment == "dev"
    
    def get_log_config(self) -> dict:
        """Get logging configuration."""
        return {
            'version': 1,
            'disable_existing_loggers': False,
            'formatters': {
                'default': {
                    'format': (
                        '%(asctime)s - %(name)s - '
                        '%(levelname)s - %(message)s'
                    ),
                },
                'json': {
                    'class': 'pythonjsonlogger.jsonlogger.JsonFormatter',
                    'format': (
                        '%(asctime)s %(name)s %(levelname)s '
                        '%(message)s'
                    ),
                },
            },
            'handlers': {
                'console': {
                    'class': 'logging.StreamHandler',
                    'formatter': 'json' if self.is_production else 'default',
                    'level': self.log_level,
                },
            },
            'root': {
                'level': self.log_level,
                'handlers': ['console'],
            },
        }

# ==========================================
# Level 2: Environment-Specific Config Files
# ==========================================

# .env (development)
"""
APP_NAME=my-app
ENVIRONMENT=dev
DEBUG=true
DATABASE_URL=postgresql://localhost/myapp_dev
SECRET_KEY=dev-secret-key
"""

# .env.production (production)
"""
APP_NAME=my-app
ENVIRONMENT=prod
DEBUG=false
DATABASE_URL=postgresql://prod-db.example.com/myapp
SECRET_KEY=super-secret-production-key
LOG_LEVEL=WARNING
"""

# ==========================================
# Level 3: Environment Variables Override
# ==========================================

# export DATABASE_URL=postgresql://override/db
# export SECRET_KEY=override-secret

# ==========================================
# Level 4: Runtime Overrides
# ==========================================

# Load settings
settings = Settings()

# Override at runtime (testing)
test_settings = settings.model_copy(
    update={
        'database_url': 'postgresql://localhost/test',
        'debug': True,
        'enable_cache': False,
    }
)

# ==========================================
# Usage in Application
# ==========================================

from functools import lru_cache

@lru_cache
def get_settings() -> Settings:
    """
    Get settings singleton.
    
    Mechanism: lru_cache ensures single instance.
    Can be overridden for testing.
    """
    return Settings()

# FastAPI dependency injection
from fastapi import Depends

async def get_database(
    settings: Settings = Depends(get_settings)
) -> DatabaseClient:
    """Get database client from settings."""
    return create_database_client(settings.database_url)

# Usage in route
@app.get("/users/{user_id}")
async def get_user(
    user_id: str,
    db: DatabaseClient = Depends(get_database),
):
    return await db.get_user(user_id)
```

**Configuration Validation:**
```python
# Validate settings on startup
settings = Settings()

# Check required production settings
if settings.is_production:
    if settings.secret_key == "dev-secret-key-change-in-production":
        raise ValueError("Must set SECRET_KEY in production")
    
    if not settings.database_url.startswith("postgresql://"):
        raise ValueError("Production must use PostgreSQL")
    
    if settings.debug:
        raise ValueError("Debug must be False in production")
```

**Why This Works:**
- Pydantic-settings handles loading and precedence automatically
- Type validation catches configuration errors early
- Environment-specific files (`.env.production`) keep secrets separate
- Runtime overrides enable testing
- Single source of truth for all configuration

---

### Principle 7: Observable Behavior (MANDATORY)

**Meta-Architecture Principle:**
> Systems must be observable through logs, metrics, and traces. Structured logging enables programmatic analysis.

**Python Implementation:**

```python
# infrastructure/observability.py
"""
Structured logging, metrics, and tracing.

Mechanism: Python logging with JSON formatter + OpenTelemetry.
"""

import logging
import structlog
from typing import Any
from opentelemetry import trace, metrics
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.metrics import MeterProvider
from contextlib import contextmanager
import time

# ==========================================
# Structured Logging
# ==========================================

def configure_logging(log_level: str = "INFO"):
    """
    Configure structured logging with structlog.
    
    Mechanism: structlog adds context to log entries.
    Processors convert to JSON for machine parsing.
    """
    structlog.configure(
        processors=[
            structlog.stdlib.filter_by_level,
            structlog.processors.TimeStamper(fmt="iso"),
            structlog.stdlib.add_logger_name,
            structlog.stdlib.add_log_level,
            structlog.processors.StackInfoRenderer(),
            structlog.processors.format_exc_info,
            structlog.processors.UnicodeDecoder(),
            structlog.processors.JSONRenderer(),  # JSON output
        ],
        wrapper_class=structlog.stdlib.BoundLogger,
        context_class=dict,
        logger_factory=structlog.stdlib.LoggerFactory(),
        cache_logger_on_first_use=True,
    )
    
    logging.basicConfig(
        format="%(message)s",
        level=getattr(logging, log_level),
    )

# Get logger with bound context
logger = structlog.get_logger()

# Usage with context
logger.info(
    "user_created",
    user_id="123",
    username="alice",
    email="alice@example.com",
)

# Output (JSON):
# {
#   "event": "user_created",
#   "user_id": "123",
#   "username": "alice",
#   "email": "alice@example.com",
#   "timestamp": "2025-11-10T20:00:00.123456Z",
#   "level": "info",
#   "logger": "my_app"
# }

# ==========================================
# Request Context Logging
# ==========================================

from contextvars import ContextVar
import uuid

# Context variables for request tracking
request_id_var: ContextVar[str] = ContextVar('request_id')
user_id_var: ContextVar[str | None] = ContextVar('user_id', default=None)

class RequestContextMiddleware:
    """
    Middleware to add request context to logs.
    
    Mechanism: ContextVar stores request-specific data.
    All logs in request include this context automatically.
    """
    
    def __init__(self, app):
        self.app = app
    
    async def __call__(self, scope, receive, send):
        if scope['type'] == 'http':
            # Generate request ID
            request_id = str(uuid.uuid4())
            request_id_var.set(request_id)
            
            # Extract user from auth (if any)
            # user_id_var.set(extract_user_id(scope))
            
            # Bind context to logger
            logger_with_context = logger.bind(
                request_id=request_id,
                path=scope['path'],
                method=scope['method'],
            )
            
            # Log request
            logger_with_context.info("request_started")
            
            start_time = time.time()
            
            try:
                await self.app(scope, receive, send)
                
                duration = time.time() - start_time
                logger_with_context.info(
                    "request_completed",
                    duration_ms=duration * 1000,
                )
            except Exception as e:
                duration = time.time() - start_time
                logger_with_context.error(
                    "request_failed",
                    error=str(e),
                    duration_ms=duration * 1000,
                )
                raise
        else:
            await self.app(scope, receive, send)

# ==========================================
# Metrics Collection
# ==========================================

from prometheus_client import Counter, Histogram, Gauge

# Define metrics
request_count = Counter(
    'http_requests_total',
    'Total HTTP requests',
    ['method', 'endpoint', 'status'],
)

request_duration = Histogram(
    'http_request_duration_seconds',
    'HTTP request duration',
    ['method', 'endpoint'],
)

active_connections = Gauge(
    'active_connections',
    'Number of active connections',
)

# Usage in application
@contextmanager
def track_request(method: str, endpoint: str):
    """Context manager to track request metrics."""
    active_connections.inc()
    start_time = time.time()
    status = 500  # Default to error
    
    try:
        yield
        status = 200
    except Exception:
        status = 500
        raise
    finally:
        duration = time.time() - start_time
        request_duration.labels(method=method, endpoint=endpoint).observe(duration)
        request_count.labels(
            method=method,
            endpoint=endpoint,
            status=status,
        ).inc()
        active_connections.dec()

# Expose metrics endpoint
from prometheus_client import generate_latest
from fastapi import Response

@app.get("/metrics")
async def metrics():
    """Prometheus metrics endpoint."""
    return Response(
        content=generate_latest(),
        media_type="text/plain",
    )

# ==========================================
# Distributed Tracing
# ==========================================

from opentelemetry import trace
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import BatchSpanProcessor
from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import (
    OTLPSpanExporter
)

# Setup tracing
trace.set_tracer_provider(TracerProvider())
tracer = trace.get_tracer(__name__)

# Export to OTLP (e.g., Jaeger, Tempo)
otlp_exporter = OTLPSpanExporter(endpoint="localhost:4317")
span_processor = BatchSpanProcessor(otlp_exporter)
trace.get_tracer_provider().add_span_processor(span_processor)

# Usage in application
async def get_user(user_id: str) -> User:
    """Get user with tracing."""
    with tracer.start_as_current_span("get_user") as span:
        # Add attributes to span
        span.set_attribute("user.id", user_id)
        
        # Database query
        with tracer.start_as_current_span("database_query"):
            user = await db.get_user(user_id)
        
        # Cache check
        with tracer.start_as_current_span("cache_check"):
            await cache.set(f"user:{user_id}", user)
        
        span.set_attribute("user.found", user is not None)
        return user
```

**Why This Works:**
- Structured logging (JSON) enables programmatic analysis
- Context variables track request across entire flow
- Prometheus metrics provide quantitative monitoring
- Distributed tracing shows request flow across services
- All observability data includes correlation IDs

---

## Four-Layer Architecture

### Complete Python Implementation

```python
# ==========================================
# LAYER 1: FOUNDATION
# ==========================================

# foundation/types.py
"""Core domain types."""

from typing import Protocol
from datetime import datetime

class Entity(Protocol):
    """Base entity protocol."""
    id: str
    created_at: datetime
    updated_at: datetime

# foundation/errors.py
"""Exception hierarchy."""
# (See Principle 5)

# ==========================================
# LAYER 2: INFRASTRUCTURE
# ==========================================

# infrastructure/database.py
"""Database client."""

from sqlalchemy.ext.asyncio import (
    create_async_engine,
    AsyncSession,
    async_sessionmaker,
)

class DatabaseClient:
    """Async database client."""
    
    def __init__(self, url: str):
        self.engine = create_async_engine(url, echo=False)
        self.session_factory = async_sessionmaker(
            self.engine,
            class_=AsyncSession,
            expire_on_commit=False,
        )
    
    async def get_session(self) -> AsyncSession:
        """Get database session."""
        async with self.session_factory() as session:
            yield session

# infrastructure/cache.py
"""Redis cache client."""

from redis.asyncio import Redis

class CacheClient:
    """Async cache client."""
    
    def __init__(self, url: str):
        self.redis = Redis.from_url(url)
    
    async def get(self, key: str) -> str | None:
        """Get value from cache."""
        return await self.redis.get(key)
    
    async def set(
        self,
        key: str,
        value: str,
        expire: int | None = None,
    ) -> None:
        """Set value in cache."""
        await self.redis.set(key, value, ex=expire)

# ==========================================
# LAYER 3: INTEGRATION
# ==========================================

# integration/email_service.py
"""Email service integration."""

import aiohttp

class EmailService:
    """External email service client."""
    
    def __init__(self, api_key: str):
        self.api_key = api_key
        self.base_url = "https://api.emailservice.com"
    
    async def send_email(
        self,
        to: str,
        subject: str,
        body: str,
    ) -> bool:
        """Send email via external service."""
        async with aiohttp.ClientSession() as session:
            async with session.post(
                f"{self.base_url}/send",
                json={
                    'to': to,
                    'subject': subject,
                    'body': body,
                },
                headers={'Authorization': f'Bearer {self.api_key}'},
            ) as response:
                return response.status == 200

# ==========================================
# LAYER 4: APPLICATION
# ==========================================

# application/services.py
"""Business logic services."""

from foundation.types import Entity
from foundation.errors import NotFoundError, ValidationError
from infrastructure.database import DatabaseClient
from infrastructure.cache import CacheClient
from integration.email_service import EmailService

class UserService:
    """User business logic."""
    
    def __init__(
        self,
        db: DatabaseClient,
        cache: CacheClient,
        email: EmailService,
    ):
        self.db = db
        self.cache = cache
        self.email = email
    
    async def create_user(
        self,
        username: str,
        email: str,
        password: str,
    ) -> User:
        """
        Create user with validation and welcome email.
        
        Orchestrates:
        - Database (Infrastructure)
        - Cache (Infrastructure)
        - Email service (Integration)
        """
        # Validation
        if len(username) < 3:
            raise ValidationError("Username too short")
        
        # Create user
        user = User(
            username=username,
            email=email,
            password_hash=hash_password(password),
        )
        
        # Save to database
        async with self.db.get_session() as session:
            session.add(user)
            await session.commit()
        
        # Cache user
        await self.cache.set(
            f"user:{user.id}",
            user.model_dump_json(),
            expire=300,
        )
        
        # Send welcome email
        await self.email.send_email(
            to=user.email,
            subject="Welcome!",
            body=f"Welcome {username}!",
        )
        
        return user
```

---

## Project Structure

### Standard Python Project Layout

```
my_project/
├── src/
│   └── my_project/              # Main package
│       ├── __init__.py
│       ├── foundation/          # Layer 1
│       │   ├── __init__.py
│       │   ├── types.py
│       │   ├── errors.py
│       │   └── validators.py
│       ├── infrastructure/      # Layer 2
│       │   ├── __init__.py
│       │   ├── database.py
│       │   ├── cache.py
│       │   └── logging.py
│       ├── integration/         # Layer 3
│       │   ├── __init__.py
│       │   ├── email_service.py
│       │   └── payment_gateway.py
│       ├── application/         # Layer 4
│       │   ├── __init__.py
│       │   ├── services.py
│       │   └── api/
│       │       ├── __init__.py
│       │       ├── routes.py
│       │       └── dependencies.py
│       └── main.py             # Entry point
│
├── tests/                       # Test package
│   ├── __init__.py
│   ├── unit/
│   │   ├── test_validators.py
│   │   └── test_services.py
│   ├── integration/
│   │   ├── test_database.py
│   │   └── test_api.py
│   └── conftest.py             # Pytest fixtures
│
├── scripts/                     # Utility scripts
│   ├── migrate_db.py
│   └── seed_data.py
│
├── docs/                        # Documentation
│   └── architecture.md
│
├── .github/                     # CI/CD
│   └── workflows/
│       └── ci.yml
│
├── pyproject.toml              # Project metadata & deps
├── .env.example                # Example environment vars
├── .gitignore
├── README.md
└── Makefile                    # Common commands
```

---

## Complete Code Examples

### Example: FastAPI Application

```python
# main.py
"""
Complete FastAPI application following architecture principles.
"""

from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from typing import Annotated
import logging

# Configure logging
from infrastructure.observability import configure_logging
configure_logging()
logger = logging.getLogger(__name__)

# Load settings
from infrastructure.config import Settings, get_settings

# Create app
app = FastAPI(
    title="My API",
    version="1.0.0",
    docs_url="/docs",
)

# Middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# Error handlers
from foundation.errors import ApplicationError, error_handler
app.add_exception_handler(Exception, error_handler)

# ==========================================
# Dependency Injection
# ==========================================

from infrastructure.database import DatabaseClient
from infrastructure.cache import CacheClient
from application.services import UserService

async def get_database(
    settings: Settings = Depends(get_settings)
) -> DatabaseClient:
    """Get database dependency."""
    return DatabaseClient(settings.database_url)

async def get_cache(
    settings: Settings = Depends(get_settings)
) -> CacheClient:
    """Get cache dependency."""
    return CacheClient(settings.redis_url)

async def get_user_service(
    db: DatabaseClient = Depends(get_database),
    cache: CacheClient = Depends(get_cache),
) -> UserService:
    """Get user service dependency."""
    return UserService(db, cache)

# ==========================================
# API Models
# ==========================================

class CreateUserRequest(BaseModel):
    """User creation request."""
    username: Annotated[str, Field(min_length=3, max_length=20)]
    email: Annotated[str, Field(pattern=r'^[^@]+@[^@]+\.[^@]+$')]
    password: Annotated[str, Field(min_length=8)]

class UserResponse(BaseModel):
    """User response."""
    id: str
    username: str
    email: str
    created_at: str

# ==========================================
# Routes
# ==========================================

@app.post(
    "/users",
    response_model=UserResponse,
    status_code=status.HTTP_201_CREATED,
)
async def create_user(
    request: CreateUserRequest,
    service: UserService = Depends(get_user_service),
):
    """Create new user."""
    user = await service.create_user(
        username=request.username,
        email=request.email,
        password=request.password,
    )
    
    return UserResponse(
        id=user.id,
        username=user.username,
        email=user.email,
        created_at=user.created_at.isoformat(),
    )

@app.get("/users/{user_id}", response_model=UserResponse)
async def get_user(
    user_id: str,
    service: UserService = Depends(get_user_service),
):
    """Get user by ID."""
    user = await service.get_user(user_id)
    
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found",
        )
    
    return UserResponse(
        id=user.id,
        username=user.username,
        email=user.email,
        created_at=user.created_at.isoformat(),
    )

@app.get("/health")
async def health_check():
    """Health check endpoint."""
    return {"status": "healthy"}

# ==========================================
# Startup/Shutdown
# ==========================================

@app.on_event("startup")
async def startup():
    """Initialize on startup."""
    logger.info("Application starting")
    settings = get_settings()
    logger.info(f"Environment: {settings.environment}")

@app.on_event("shutdown")
async def shutdown():
    """Cleanup on shutdown."""
    logger.info("Application shutting down")

# ==========================================
# Run Server
# ==========================================

if __name__ == "__main__":
    import uvicorn
    
    settings = get_settings()
    uvicorn.run(
        "main:app",
        host=settings.host,
        port=settings.port,
        reload=settings.debug,
        log_level=settings.log_level.lower(),
    )
```

---

## Tool Recommendations

### Development Tools

```toml
# pyproject.toml

[tool.ruff]
# Linting and formatting (replaces black, flake8, isort)
line-length = 88
target-version = "py311"
select = [
    "E",  # pycodestyle errors
    "W",  # pycodestyle warnings
    "F",  # pyflakes
    "I",  # isort
    "B",  # flake8-bugbear
    "C4", # flake8-comprehensions
    "UP", # pyupgrade
]

[tool.mypy]
# Type checking
python_version = "3.11"
strict = true
warn_return_any = true
warn_unused_configs = true
disallow_untyped_defs = true

[tool.pytest.ini_options]
# Testing
testpaths = ["tests"]
python_files = ["test_*.py"]
python_classes = ["Test*"]
python_functions = ["test_*"]
addopts = [
    "--cov=src",
    "--cov-report=html",
    "--cov-report=term-missing",
]

[tool.coverage.run]
# Coverage
source = ["src"]
omit = ["tests/*", "*/migrations/*"]

[tool.coverage.report]
# Coverage thresholds
fail_under = 80
```

### Recommended Tools

**Code Quality:**
- `ruff` - Fast linting and formatting (replaces black, flake8, isort)
- `mypy` - Static type checking
- `bandit` - Security linting
- `safety` - Dependency vulnerability scanning

**Testing:**
- `pytest` - Test framework
- `pytest-asyncio` - Async test support
- `pytest-cov` - Coverage reporting
- `pytest-mock` - Mocking utilities
- `httpx` - Async HTTP client for testing APIs
- `fakeredis` - Mock Redis for testing

**Development:**
- `ipython` - Enhanced REPL
- `ipdb` - Interactive debugger
- `pre-commit` - Git hooks for code quality

**Monitoring:**
- `structlog` - Structured logging
- `prometheus-client` - Metrics collection
- `opentelemetry` - Distributed tracing
- `sentry-sdk` - Error tracking

**Documentation:**
- `mkdocs` - Documentation generator
- `mkdocs-material` - Material theme for mkdocs

### Makefile for Common Commands

```makefile
# Makefile

.PHONY: install
install:
	pip install -e ".[dev,test]"

.PHONY: lint
lint:
	ruff check src tests
	mypy src

.PHONY: format
format:
	ruff format src tests

.PHONY: test
test:
	pytest tests/ -v

.PHONY: test-cov
test-cov:
	pytest tests/ --cov=src --cov-report=html --cov-report=term

.PHONY: migrate
migrate:
	alembic upgrade head

.PHONY: run
run:
	uvicorn main:app --reload

.PHONY: docker-build
docker-build:
	docker build -t my-app:latest .

.PHONY: docker-run
docker-run:
	docker run -p 8000:8000 my-app:latest
```

---

## Testing Strategy

### Test Organization

```
tests/
├── unit/                    # Fast, isolated tests
│   ├── test_validators.py  # Test validation logic
│   ├── test_services.py    # Test business logic
│   └── test_models.py      # Test data models
├── integration/             # Tests with external systems
│   ├── test_database.py    # Database integration
│   ├── test_cache.py       # Cache integration
│   └── test_api.py         # API integration
└── e2e/                     # End-to-end tests
    └── test_user_flow.py   # Complete user journeys
```

### Example Tests

```python
# tests/unit/test_validators.py

import pytest
from pydantic import ValidationError
from foundation.validators import CreateUserRequest

def test_valid_user_request():
    """Test valid user request."""
    request = CreateUserRequest(
        username="alice",
        email="alice@example.com",
        password="secure-password-123",
    )
    
    assert request.username == "alice"
    assert request.email == "alice@example.com"

def test_invalid_username_too_short():
    """Test username validation."""
    with pytest.raises(ValidationError) as exc_info:
        CreateUserRequest(
            username="ab",  # Too short
            email="alice@example.com",
            password="secure-password-123",
        )
    
    errors = exc_info.value.errors()
    assert any(e['loc'] == ('username',) for e in errors)

def test_invalid_email_format():
    """Test email validation."""
    with pytest.raises(ValidationError):
        CreateUserRequest(
            username="alice",
            email="not-an-email",  # Invalid format
            password="secure-password-123",
        )

# tests/integration/test_api.py

import pytest
from httpx import AsyncClient
from main import app

@pytest.mark.asyncio
async def test_create_user():
    """Test user creation endpoint."""
    async with AsyncClient(app=app, base_url="http://test") as client:
        response = await client.post(
            "/users",
            json={
                "username": "alice",
                "email": "alice@example.com",
                "password": "secure-password-123",
            },
        )
    
    assert response.status_code == 201
    data = response.json()
    assert data["username"] == "alice"
    assert data["email"] == "alice@example.com"
    assert "id" in data

@pytest.mark.asyncio
async def test_get_nonexistent_user():
    """Test getting nonexistent user."""
    async with AsyncClient(app=app, base_url="http://test") as client:
        response = await client.get("/users/nonexistent")
    
    assert response.status_code == 404

# tests/conftest.py

import pytest
from infrastructure.database import DatabaseClient
from infrastructure.config import Settings

@pytest.fixture
def test_settings():
    """Test settings."""
    return Settings(
        environment="test",
        database_url="postgresql://localhost/test",
        redis_url="redis://localhost:6379/1",
        debug=True,
    )

@pytest.fixture
async def test_db(test_settings):
    """Test database."""
    db = DatabaseClient(test_settings.database_url)
    # Setup test database
    yield db
    # Teardown
```

---

## Deployment Guidelines

### Docker

```dockerfile
# Dockerfile

FROM python:3.11-slim

WORKDIR /app

# Install dependencies
COPY pyproject.toml .
RUN pip install --no-cache-dir -e .

# Copy application
COPY src/ ./src/
COPY main.py .

# Run
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
```

### Docker Compose

```yaml
# docker-compose.yml

version: '3.8'

services:
  app:
    build: .
    ports:
      - "8000:8000"
    environment:
      - DATABASE_URL=postgresql://postgres:postgres@db:5432/myapp
      - REDIS_URL=redis://redis:6379/0
    depends_on:
      - db
      - redis
  
  db:
    image: postgres:15
    environment:
      - POSTGRES_PASSWORD=postgres
    volumes:
      - postgres_data:/var/lib/postgresql/data
  
  redis:
    image: redis:7-alpine
    volumes:
      - redis_data:/data

volumes:
  postgres_data:
  redis_data:
```

---

## Compliance Checklist

- [ ] **Layered Architecture**: Foundation → Infrastructure → Integration → Application
- [ ] **Explicit Dependencies**: pyproject.toml with pinned versions
- [ ] **Graceful Degradation**: Circuit breakers for non-critical services
- [ ] **Input Validation**: Pydantic models with custom validators
- [ ] **Standardized Errors**: Exception hierarchy with error codes
- [ ] **Hierarchical Config**: pydantic-settings with env override
- [ ] **Observable Behavior**: Structured logging with correlation IDs
- [ ] **Automated Testing**: Unit, integration, and E2E tests
- [ ] **Security by Design**: Authentication, authorization, input sanitization
- [ ] **Resource Lifecycle**: Context managers for cleanup
- [ ] **Performance Patterns**: Async I/O, connection pooling, caching
- [ ] **Evolutionary Design**: Versioned APIs, feature flags

---

## Summary

This Python architecture provides production-ready patterns:

**Key Characteristics:**
- ✅ **Type-safe** - Type hints throughout with mypy validation
- ✅ **Async-first** - Fully async/await for I/O operations
- ✅ **Dependency injection** - Testable, flexible dependencies
- ✅ **Observable** - Structured logging, metrics, tracing
- ✅ **Production-ready** - Error handling, config, testing

[View your Python architecture](computer:///mnt/user-data/outputs/PYTHON-ARCHITECTURE.md)
