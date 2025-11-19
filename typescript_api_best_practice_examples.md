# TypeScript API Security Examples

This document provides practical TypeScript examples demonstrating secure API consumption patterns with type safety.

## Table of Contents

- [Secure Authentication](#secure-authentication)
- [HTTPS Communication with Certificate Validation](#https-communication-with-certificate-validation)
- [Retry Logic with Exponential Backoff](#retry-logic-with-exponential-backoff)
- [Proper Error Handling](#proper-error-handling)
- [Input Validation and Sanitization](#input-validation-and-sanitization)
- [Secure Logging with Redaction](#secure-logging-with-redaction)

---

## Secure Authentication

Always store API credentials securely using environment variables or secret management systems, never hardcode them.

```typescript
import axios, { AxiosInstance, AxiosRequestConfig } from 'axios';

class SecureAPIClient {
  private client: AxiosInstance;
  private apiKey: string;
  private baseURL: string;

  constructor(baseURL: string) {
    // Retrieve API key from environment variable
    this.apiKey = process.env.API_KEY || '';
    if (!this.apiKey) {
      throw new Error('API_KEY environment variable not set');
    }

    this.baseURL = baseURL;
    this.client = axios.create({
      baseURL: this.baseURL,
      timeout: 10000,
      headers: {
        'Authorization': `Bearer ${this.apiKey}`,
        'Content-Type': 'application/json',
      },
    });
  }

  async fetchData(): Promise<string> {
    try {
      const response = await this.client.get('/data');
      return response.data;
    } catch (error) {
      console.error('API request failed:', error);
      throw error;
    }
  }
}

// Usage
async function main() {
  try {
    const client = new SecureAPIClient('https://api.example.com');
    const data = await client.fetchData();
    console.log(data);
  } catch (error) {
    console.error('Error:', (error as Error).message);
  }
}

main();
```

**Why this is secure**: Credentials are retrieved from environment variables and never hardcoded. TypeScript's type system ensures proper error handling. The application throws an error immediately if credentials are missing. Axios is configured with appropriate timeouts.

---

## HTTPS Communication with Certificate Validation

Always use HTTPS and verify SSL certificates to prevent man-in-the-middle attacks.

```typescript
import axios, { AxiosInstance } from 'axios';
import https from 'https';
import fs from 'fs';

class SecureHTTPClient {
  // Create client with default secure settings
  static createSecureClient(): AxiosInstance {
    return axios.create({
      timeout: 10000,
      httpsAgent: new https.Agent({
        rejectUnauthorized: true, // Enforce certificate validation (default)
        minVersion: 'TLSv1.2', // Enforce minimum TLS version
        maxVersion: 'TLSv1.3',
      }),
    });
  }

  // Create client with custom CA certificate
  static createClientWithCustomCA(caFilePath: string): AxiosInstance {
    const ca = fs.readFileSync(caFilePath);

    return axios.create({
      timeout: 10000,
      httpsAgent: new https.Agent({
        ca: ca,
        rejectUnauthorized: true,
        minVersion: 'TLSv1.2',
      }),
    });
  }

  static async makeRequest(url: string): Promise<string> {
    const client = this.createSecureClient();
    const response = await client.get(url);
    return response.data;
  }
}

// Usage
async function main() {
  try {
    const response = await SecureHTTPClient.makeRequest('https://api.example.com/data');
    console.log('Response:', response);
  } catch (error) {
    console.error('Error:', (error as Error).message);
  }
}

main();
```

**Why this is secure**: Certificate validation is explicitly enabled through rejectUnauthorized. Minimum TLS version is enforced. Custom CA certificates can be loaded for internal APIs while maintaining validation. TypeScript's type system prevents configuration errors at compile time.

---

## Retry Logic with Exponential Backoff

Implement intelligent retry logic for transient failures with exponential backoff and jitter.

```typescript
import axios, { AxiosInstance, AxiosRequestConfig, AxiosResponse } from 'axios';

const MAX_RETRIES = 3;

async function apiCallWithRetry(
  client: AxiosInstance,
  config: AxiosRequestConfig,
  maxRetries: number = MAX_RETRIES
): Promise<AxiosResponse> {
  for (let attempt = 0; attempt < maxRetries; attempt++) {
    try {
      const response = await client.request(config);

      // Success
      return response;
    } catch (error: any) {
      const status = error.response?.status;

      // Rate limited - respect Retry-After header
      if (status === 429) {
        if (attempt < maxRetries - 1) {
          const retryAfter = parseInt(error.response.headers['retry-after'] || '60');
          await sleep(retryAfter * 1000);
          continue;
        }
      }

      // Server error - retry with exponential backoff
      if (status >= 500 || error.code === 'ECONNRESET' || error.code === 'ETIMEDOUT') {
        if (attempt < maxRetries - 1) {
          const waitTime = calculateBackoff(attempt);
          await sleep(waitTime);
          continue;
        }
      }

      // Client error or final attempt - throw error
      throw error;
    }
  }

  throw new Error('Max retries exceeded');
}

function calculateBackoff(attempt: number): number {
  // Exponential backoff with jitter
  const exponential = Math.pow(2, attempt) * 1000;
  const jitter = Math.random() * 1000;
  return exponential + jitter;
}

function sleep(ms: number): Promise<void> {
  return new Promise(resolve => setTimeout(resolve, ms));
}

// Usage
async function fetchUserData(): Promise<any> {
  const client = axios.create({ timeout: 10000 });
  const apiKey = process.env.API_KEY || '';

  try {
    const response = await apiCallWithRetry(client, {
      method: 'GET',
      url: 'https://api.example.com/users/123',
      headers: {
        'Authorization': `Bearer ${apiKey}`,
      },
    });
    return response.data;
  } catch (error) {
    console.error('All retry attempts failed:', (error as Error).message);
    throw error;
  }
}
```

**Why this is secure**: Exponential backoff with jitter prevents overwhelming struggling services. Retry-After headers are respected for rate limits. Network errors and server errors trigger retries while client errors do not. TypeScript ensures proper typing of error responses.

---

## Proper Error Handling

Handle errors gracefully and avoid exposing sensitive information in error messages.

```typescript
import axios, { AxiosInstance, AxiosError } from 'axios';

// Custom error classes
class APIError extends Error {
  constructor(
    message: string,
    public statusCode?: number,
    public originalError?: Error
  ) {
    super(message);
    this.name = 'APIError';
    Object.setPrototypeOf(this, APIError.prototype);
  }
}

class AuthenticationError extends APIError {
  constructor(message: string = 'Invalid credentials') {
    super(message, 401);
    this.name = 'AuthenticationError';
    Object.setPrototypeOf(this, AuthenticationError.prototype);
  }
}

class ServiceUnavailableError extends APIError {
  constructor(message: string, statusCode: number) {
    super(message, statusCode);
    this.name = 'ServiceUnavailableError';
    Object.setPrototypeOf(this, ServiceUnavailableError.prototype);
  }
}

async function fetchUserData(
  client: AxiosInstance,
  userId: string,
  apiKey: string
): Promise<any> {
  try {
    const response = await client.get(`https://api.example.com/users/${userId}`, {
      headers: { 'Authorization': `Bearer ${apiKey}` },
      timeout: 10000,
    });

    return response.data;
  } catch (error) {
    // Log detailed error for debugging
    console.error('API request failed:', {
      userId,
      status: (error as AxiosError).response?.status,
      message: (error as Error).message,
      code: (error as any).code,
    });

    // Throw user-friendly errors without sensitive details
    if (axios.isAxiosError(error)) {
      const status = error.response?.status;

      if (status === 404) {
        throw new APIError('User not found', 404, error);
      } else if (status === 401) {
        throw new AuthenticationError();
      } else if (status === 403) {
        throw new APIError('Access denied', 403, error);
      } else if (status && status >= 500) {
        throw new ServiceUnavailableError('Service temporarily unavailable', status);
      } else {
        throw new APIError('Request failed', status, error);
      }
    } else if ((error as any).code === 'ETIMEDOUT') {
      throw new APIError('Request timed out', undefined, error as Error);
    } else if ((error as any).code === 'ECONNREFUSED') {
      throw new APIError('Service unavailable', undefined, error as Error);
    } else {
      throw new APIError('Request failed', undefined, error as Error);
    }
  }
}

// Usage with error handling
async function handleUserRequest(userId: string): Promise<void> {
  const client = axios.create();
  const apiKey = process.env.API_KEY || '';

  try {
    const userData = await fetchUserData(client, userId, apiKey);
    console.log('Success:', userData);
  } catch (error) {
    if (error instanceof AuthenticationError) {
      console.error('Authentication error:', error.message);
    } else if (error instanceof ServiceUnavailableError) {
      console.error('Service error:', error.message, 'Status:', error.statusCode);
    } else if (error instanceof APIError) {
      console.error('API error:', error.message, 'Status:', error.statusCode);
    } else {
      console.error('Unexpected error:', (error as Error).message);
    }
  }
}
```

**Why this is secure**: Detailed errors are logged for debugging but generic messages are thrown to callers. Custom error classes with proper prototypes enable type-safe error handling. TypeScript's type guards (instanceof) ensure appropriate handling of different error types.

---

## Input Validation and Sanitization

Validate and sanitize all inputs before including them in API requests.

```typescript
import axios, { AxiosInstance } from 'axios';

const EMAIL_REGEX = /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/;

function validateEmail(email: string): boolean {
  return EMAIL_REGEX.test(email);
}

function sanitizeInput(input: string, maxLength: number = 100): string {
  if (typeof input !== 'string') {
    throw new Error('Input must be a string');
  }

  if (input.length > maxLength) {
    throw new Error(`Input exceeds maximum length of ${maxLength}`);
  }

  // Remove null bytes and trim whitespace
  return input.replace(/\0/g, '').trim();
}

async function searchUsers(
  client: AxiosInstance,
  searchTerm: string,
  apiKey: string
): Promise<any> {
  // Validate and sanitize input
  const sanitized = sanitizeInput(searchTerm, 50);

  // Axios automatically handles URL encoding for params
  const response = await client.get('https://api.example.com/users/search', {
    params: { q: sanitized },
    headers: { 'Authorization': `Bearer ${apiKey}` },
  });

  return response.data;
}

interface CreateUserRequest {
  email: string;
  name: string;
}

async function createUser(
  client: AxiosInstance,
  email: string,
  name: string,
  apiKey: string
): Promise<any> {
  // Validate email format
  if (!validateEmail(email)) {
    throw new Error('Invalid email format');
  }

  // Sanitize name
  const sanitizedName = sanitizeInput(name, 100);

  // Axios automatically handles JSON encoding
  const payload: CreateUserRequest = {
    email: email,
    name: sanitizedName,
  };

  const response = await client.post('https://api.example.com/users', payload, {
    headers: { 'Authorization': `Bearer ${apiKey}` },
  });

  return response.data;
}

// Usage
async function main() {
  const client = axios.create();
  const apiKey = process.env.API_KEY || '';

  try {
    // Search with validated input
    const results = await searchUsers(client, 'John', apiKey);
    console.log('Search results:', results);

    // Create user with validated input
    const newUser = await createUser(client, 'john@example.com', 'John Doe', apiKey);
    console.log('Created user:', newUser);
  } catch (error) {
    console.error('Validation error:', (error as Error).message);
  }
}
```

**Why this is secure**: Input validation prevents injection attacks and malformed requests. TypeScript interfaces ensure type safety for request payloads. Axios automatically handles URL encoding and JSON serialization, preventing manual string concatenation vulnerabilities.

---

## Secure Logging with Redaction

Log API interactions for troubleshooting while protecting sensitive information.

```typescript
import winston from 'winston';

interface LogData {
  [key: string]: any;
}

const SENSITIVE_FIELDS = [
  'password', 'api_key', 'apiKey', 'token', 'secret',
  'authorization', 'ssn', 'creditCard', 'cvv', 'pin'
];

// Configure winston logger
const logger = winston.createLogger({
  level: 'info',
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.json()
  ),
  transports: [
    new winston.transports.File({ filename: 'error.log', level: 'error' }),
    new winston.transports.File({ filename: 'combined.log' }),
  ],
});

if (process.env.NODE_ENV !== 'production') {
  logger.add(new winston.transports.Console({
    format: winston.format.simple(),
  }));
}

function redactSensitiveData(data: LogData): LogData {
  if (typeof data !== 'object' || data === null) {
    return data;
  }

  const redacted: LogData = {};

  for (const [key, value] of Object.entries(data)) {
    const lowerKey = key.toLowerCase();
    const isSensitive = SENSITIVE_FIELDS.some(field => lowerKey.includes(field));

    if (isSensitive) {
      redacted[key] = '[REDACTED]';
    } else if (typeof value === 'object' && value !== null && !Array.isArray(value)) {
      redacted[key] = redactSensitiveData(value);
    } else {
      redacted[key] = value;
    }
  }

  return redacted;
}

function maskEmail(email: string): string {
  if (!email || !email.includes('@')) {
    return '[INVALID_EMAIL]';
  }

  const [local, domain] = email.split('@');
  const maskedLocal = local.length <= 2
    ? '*'.repeat(local.length)
    : local.substring(0, 2) + '*'.repeat(local.length - 2);

  return `${maskedLocal}@${domain}`;
}

function logAPIRequest(
  method: string,
  url: string,
  headers: Record<string, string> = {},
  payload: LogData | null = null
): void {
  const safeHeaders = { ...headers };
  if (safeHeaders.Authorization) {
    safeHeaders.Authorization = '[REDACTED]';
  }

  const safePayload = payload ? redactSensitiveData(payload) : null;

  logger.info('API Request', {
    method,
    url,
    headers: safeHeaders,
    payload: safePayload,
  });
}

function logAPIResponse(
  statusCode: number,
  responseTime: number,
  payload: LogData | null = null
): void {
  const safePayload = payload ? redactSensitiveData(payload) : null;

  logger.info('API Response', {
    statusCode,
    responseTime: `${responseTime}ms`,
    payload: safePayload,
  });
}

// Axios interceptors for automatic logging
import axios, { AxiosInstance, AxiosRequestConfig } from 'axios';

// Extend AxiosRequestConfig to include metadata
interface RequestConfigWithMetadata extends AxiosRequestConfig {
  metadata?: {
    startTime: number;
  };
}

function setupLoggingInterceptors(axiosInstance: AxiosInstance): void {
  // Request interceptor
  axiosInstance.interceptors.request.use(
    (config: RequestConfigWithMetadata) => {
      config.metadata = { startTime: Date.now() };
      logAPIRequest(
        config.method?.toUpperCase() || 'GET',
        config.url || '',
        config.headers as Record<string, string>,
        config.data
      );
      return config;
    },
    error => {
      logger.error('Request interceptor error', { error: error.message });
      return Promise.reject(error);
    }
  );

  // Response interceptor
  axiosInstance.interceptors.response.use(
    response => {
      const config = response.config as RequestConfigWithMetadata;
      const responseTime = Date.now() - (config.metadata?.startTime || Date.now());
      logAPIResponse(response.status, responseTime, response.data);
      return response;
    },
    error => {
      const config = error.config as RequestConfigWithMetadata;
      if (config?.metadata) {
        const responseTime = Date.now() - config.metadata.startTime;
        const status = error.response?.status || 'N/A';
        logAPIResponse(status, responseTime, error.response?.data);
      }
      logger.error('API Error', {
        message: error.message,
        status: error.response?.status,
        url: error.config?.url,
      });
      return Promise.reject(error);
    }
  );
}

// Usage
const apiClient = axios.create({
  baseURL: 'https://api.example.com',
  headers: { 'Authorization': `Bearer ${process.env.API_KEY}` },
});

setupLoggingInterceptors(apiClient);
```

**Why this approach is secure**: Sensitive fields are automatically redacted before logging. Winston provides structured logging with appropriate log levels. TypeScript interfaces ensure type-safe logging without bypassing type checks with 'as any'. Axios interceptors enable automatic request/response logging without modifying individual API calls.

---

## Complete Example: Secure API Client

Here's a complete example combining all best practices:

```typescript
import axios, { AxiosInstance, AxiosRequestConfig } from 'axios';
import https from 'https';
import winston from 'winston';

const MAX_RETRIES = 3;

// Extend AxiosRequestConfig for metadata
interface RequestConfigWithMetadata extends AxiosRequestConfig {
  metadata?: {
    startTime: number;
  };
}

class CompleteSecureAPIClient {
  private client: AxiosInstance;
  private baseURL: string;
  private apiKey: string;
  private logger: winston.Logger;

  constructor(baseURL: string) {
    this.apiKey = process.env.API_KEY || '';
    if (!this.apiKey) {
      throw new Error('API_KEY environment variable not set');
    }

    this.baseURL = baseURL;
    this.logger = winston.createLogger({
      level: 'info',
      format: winston.format.json(),
      transports: [new winston.transports.Console()],
    });

    this.client = axios.create({
      baseURL: this.baseURL,
      timeout: 10000,
      headers: {
        'Authorization': `Bearer ${this.apiKey}`,
        'Content-Type': 'application/json',
      },
      httpsAgent: new https.Agent({
        rejectUnauthorized: true,
        minVersion: 'TLSv1.2',
      }),
    });

    this.setupInterceptors();
  }

  private setupInterceptors(): void {
    this.client.interceptors.request.use(
      (config: RequestConfigWithMetadata) => {
        config.metadata = { startTime: Date.now() };
        this.logger.info('API Request', {
          method: config.method,
          url: config.url,
        });
        return config;
      }
    );

    this.client.interceptors.response.use(
      response => {
        const config = response.config as RequestConfigWithMetadata;
        const duration = Date.now() - (config.metadata?.startTime || Date.now());
        this.logger.info('API Response', {
          status: response.status,
          duration: `${duration}ms`,
        });
        return response;
      },
      error => {
        this.logger.error('API Error', {
          message: error.message,
          status: error.response?.status,
        });
        return Promise.reject(error);
      }
    );
  }

  private async request(
    method: string,
    endpoint: string,
    options: AxiosRequestConfig = {}
  ): Promise<any> {
    for (let attempt = 0; attempt < MAX_RETRIES; attempt++) {
      try {
        const response = await this.client.request({
          method,
          url: endpoint,
          ...options,
        });
        return response.data;
      } catch (error: any) {
        const status = error.response?.status;

        if (status === 429 && attempt < MAX_RETRIES - 1) {
          const retryAfter = parseInt(error.response.headers['retry-after'] || '60');
          await this.sleep(retryAfter * 1000);
          continue;
        }

        if ((status >= 500 || error.code === 'ETIMEDOUT') && attempt < MAX_RETRIES - 1) {
          const waitTime = this.calculateBackoff(attempt);
          await this.sleep(waitTime);
          continue;
        }

        throw error;
      }
    }
  }

  private calculateBackoff(attempt: number): number {
    const exponential = Math.pow(2, attempt) * 1000;
    const jitter = Math.random() * 1000;
    return exponential + jitter;
  }

  private sleep(ms: number): Promise<void> {
    return new Promise(resolve => setTimeout(resolve, ms));
  }

  async get(endpoint: string, params?: any): Promise<any> {
    return this.request('GET', endpoint, { params });
  }

  async post(endpoint: string, data?: any): Promise<any> {
    return this.request('POST', endpoint, { data });
  }

  async put(endpoint: string, data?: any): Promise<any> {
    return this.request('PUT', endpoint, { data });
  }

  async delete(endpoint: string): Promise<any> {
    return this.request('DELETE', endpoint);
  }
}

// Usage
async function main() {
  try {
    const client = new CompleteSecureAPIClient('https://api.example.com');

    // Example GET request
    const user = await client.get('/users/123');
    console.log('User data:', user);

    // Example POST request
    const newUser = await client.post('/users', {
      name: 'John Doe',
      email: 'john@example.com',
    });
    console.log('Created user:', newUser);
  } catch (error) {
    console.error('Operation failed:', (error as Error).message);
  }
}

main();
```

**Why this is secure**: This client combines all security best practices: environment-based credential management, certificate validation with minimum TLS version enforcement, automatic retry logic with exponential backoff, comprehensive logging through interceptors, and proper error handling. TypeScript's type system ensures compile-time safety and prevents many common security mistakes.