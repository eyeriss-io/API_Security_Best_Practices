# JavaScript/Node.js API Security Examples

This document provides practical JavaScript/Node.js examples demonstrating secure API consumption patterns.

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

```javascript
const https = require('https');
const axios = require('axios');

// Retrieve API key from environment variable
const API_KEY = process.env.API_KEY;
if (!API_KEY) {
  throw new Error('API_KEY environment variable not set');
}

// Configure axios with secure defaults
const apiClient = axios.create({
  baseURL: 'https://api.example.com',
  headers: {
    'Authorization': `Bearer ${API_KEY}`,
    'Content-Type': 'application/json'
  },
  timeout: 10000
});

// Make authenticated request
async function fetchData() {
  try {
    const response = await apiClient.get('/data');
    return response.data;
  } catch (error) {
    console.error('API request failed:', error.message);
    throw error;
  }
}
```

**Why this approach is secure**: Credentials are retrieved from environment variables and never hardcoded. The application fails immediately if credentials are missing. Axios is configured with sensible timeout defaults to prevent hanging requests.

---

## HTTPS Communication with Certificate Validation

Always use HTTPS and verify SSL certificates to prevent man-in-the-middle attacks.

```javascript
const axios = require('axios');
const https = require('https');
const tls = require('tls');

// Certificate verification is enabled by default in Node.js
const secureClient = axios.create({
  baseURL: 'https://api.example.com',
  httpsAgent: new https.Agent({
    rejectUnauthorized: true, // Enforce certificate validation (default)
    minVersion: 'TLSv1.2', // Enforce minimum TLS version
    maxVersion: 'TLSv1.3'
  })
});

// For custom CA certificates
const fs = require('fs');
const customCAClient = axios.create({
  baseURL: 'https://api.example.com',
  httpsAgent: new https.Agent({
    ca: fs.readFileSync('/path/to/ca-bundle.crt'),
    rejectUnauthorized: true
  })
});

// Make secure request
async function secureRequest() {
  const response = await secureClient.get('/data');
  return response.data;
}
```

**Why this is secure**: Certificate validation is explicitly enabled (though it's the default). Minimum TLS version is enforced to prevent use of deprecated protocols. Custom CA certificates can be loaded when needed for internal APIs.

---

## Retry Logic with Exponential Backoff

Implement intelligent retry logic for transient failures with exponential backoff and jitter.

```javascript
const axios = require('axios');

async function apiCallWithRetry(url, options = {}, maxRetries = 3) {
  const { headers, ...axiosOptions } = options;
  
  for (let attempt = 0; attempt < maxRetries; attempt++) {
    try {
      const response = await axios.get(url, {
        ...axiosOptions,
        headers,
        timeout: 10000
      });
      
      // Success
      return response;
      
    } catch (error) {
      const status = error.response?.status;
      
      // Rate limited - respect Retry-After header
      if (status === 429) {
        const retryAfter = parseInt(error.response.headers['retry-after'] || '60');
        if (attempt < maxRetries - 1) {
          await sleep(retryAfter * 1000);
          continue;
        }
      }
      
      // Server error - retry with exponential backoff
      if (status >= 500 || error.code === 'ECONNRESET' || error.code === 'ETIMEDOUT') {
        if (attempt < maxRetries - 1) {
          const waitTime = Math.pow(2, attempt) * 1000 + Math.random() * 1000;
          await sleep(waitTime);
          continue;
        }
      }
      
      // Client error or final attempt - throw error
      throw error;
    }
  }
}

function sleep(ms) {
  return new Promise(resolve => setTimeout(resolve, ms));
}

// Usage
async function fetchUserData() {
  try {
    const response = await apiCallWithRetry(
      'https://api.example.com/users/123',
      { headers: { 'Authorization': `Bearer ${API_KEY}` } }
    );
    return response.data;
  } catch (error) {
    console.error('All retry attempts failed:', error.message);
    throw error;
  }
}
```

**Why this is secure**: Exponential backoff with jitter prevents overwhelming struggling services. Retry-After headers are respected for rate limits. Network errors and server errors trigger retries while client errors do not. The random jitter prevents synchronized retry attempts across multiple clients.

---

## Proper Error Handling

Handle errors gracefully and avoid exposing sensitive information in error messages.

```javascript
const axios = require('axios');

class APIError extends Error {
  constructor(message, statusCode, originalError) {
    super(message);
    this.name = 'APIError';
    this.statusCode = statusCode;
    this.originalError = originalError;
  }
}

class AuthenticationError extends APIError {
  constructor(message) {
    super(message, 401);
    this.name = 'AuthenticationError';
  }
}

async function fetchUserData(userId) {
  try {
    const response = await axios.get(
      `https://api.example.com/users/${userId}`,
      {
        headers: { 'Authorization': `Bearer ${API_KEY}` },
        timeout: 10000
      }
    );
    
    return response.data;
    
  } catch (error) {
    // Log detailed error for debugging (with sensitive data redacted)
    console.error('API request failed:', {
      userId,
      status: error.response?.status,
      message: error.message,
      code: error.code
    });
    
    // Throw user-friendly errors without sensitive details
    if (error.response) {
      const status = error.response.status;
      
      if (status === 404) {
        throw new APIError('User not found', 404, error);
      } else if (status === 401) {
        throw new AuthenticationError('Invalid credentials');
      } else if (status === 403) {
        throw new APIError('Access denied', 403, error);
      } else if (status >= 500) {
        throw new APIError('Service temporarily unavailable', status, error);
      } else {
        throw new APIError('Request failed', status, error);
      }
    } else if (error.code === 'ETIMEDOUT') {
      throw new APIError('Request timed out', null, error);
    } else if (error.code === 'ECONNREFUSED') {
      throw new APIError('Service unavailable', null, error);
    } else {
      throw new APIError('Request failed', null, error);
    }
  }
}

// Usage with error handling
async function handleUserRequest(userId) {
  try {
    const userData = await fetchUserData(userId);
    return { success: true, data: userData };
  } catch (error) {
    if (error instanceof AuthenticationError) {
      // Handle authentication errors
      return { success: false, error: 'Please check your credentials' };
    } else if (error instanceof APIError) {
      // Handle other API errors
      return { success: false, error: error.message };
    } else {
      // Handle unexpected errors
      return { success: false, error: 'An unexpected error occurred' };
    }
  }
}
```

**Why this is secure**: Detailed errors are logged for debugging but generic messages are returned to callers. Custom error classes allow application-level error handling without exposing sensitive information. Network errors are handled separately from HTTP errors.

---

## Input Validation and Sanitization

Validate and sanitize all inputs before including them in API requests.

```javascript
const validator = require('validator');

function validateEmail(email) {
  return validator.isEmail(email);
}

function sanitizeInput(input, maxLength = 100) {
  // Validate type
  if (typeof input !== 'string') {
    throw new Error('Input must be a string');
  }
  
  // Enforce length limit
  if (input.length > maxLength) {
    throw new Error(`Input exceeds maximum length of ${maxLength}`);
  }
  
  // Remove null bytes and trim whitespace
  return input.replace(/\0/g, '').trim();
}

async function searchUsers(searchTerm) {
  // Validate and sanitize input
  const sanitized = sanitizeInput(searchTerm, 50);
  
  // URL encoding is handled automatically by axios params
  const response = await axios.get('https://api.example.com/users/search', {
    params: { q: sanitized },
    headers: { 'Authorization': `Bearer ${API_KEY}` }
  });
  
  return response.data;
}

async function createUser(email, name) {
  // Validate email format
  if (!validateEmail(email)) {
    throw new Error('Invalid email format');
  }
  
  // Sanitize name
  const sanitizedName = sanitizeInput(name, 100);
  
  // Axios automatically handles JSON encoding
  const response = await axios.post(
    'https://api.example.com/users',
    {
      email: email,
      name: sanitizedName
    },
    {
      headers: { 'Authorization': `Bearer ${API_KEY}` }
    }
  );
  
  return response.data;
}

// Input validation middleware for Express applications
function validateUserInput(req, res, next) {
  const { email, name } = req.body;
  
  try {
    if (!email || !validateEmail(email)) {
      return res.status(400).json({ error: 'Invalid email address' });
    }
    
    if (!name) {
      return res.status(400).json({ error: 'Name is required' });
    }
    
    req.body.name = sanitizeInput(name, 100);
    next();
  } catch (error) {
    return res.status(400).json({ error: error.message });
  }
}
```

**Why this is secure**: Input validation prevents injection attacks and malformed requests. The validator library provides battle-tested validation functions. Axios automatically handles URL encoding for query parameters and JSON encoding for request bodies, preventing manual string concatenation vulnerabilities.

---

## Secure Logging with Redaction

Log API interactions for troubleshooting while protecting sensitive information.

```javascript
const winston = require('winston');

// Configure winston logger
const logger = winston.createLogger({
  level: 'info',
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.json()
  ),
  transports: [
    new winston.transports.File({ filename: 'error.log', level: 'error' }),
    new winston.transports.File({ filename: 'combined.log' })
  ]
});

// Add console transport in development
if (process.env.NODE_ENV !== 'production') {
  logger.add(new winston.transports.Console({
    format: winston.format.simple()
  }));
}

function redactSensitiveData(data) {
  if (typeof data !== 'object' || data === null) {
    return data;
  }
  
  // Create a deep copy
  const redacted = JSON.parse(JSON.stringify(data));
  
  const sensitiveFields = [
    'password', 'api_key', 'apiKey', 'token', 'secret', 
    'authorization', 'ssn', 'creditCard', 'cvv', 'pin'
  ];
  
  function redactObject(obj) {
    for (const key in obj) {
      // Check if field name contains sensitive keywords
      const lowerKey = key.toLowerCase();
      if (sensitiveFields.some(field => lowerKey.includes(field))) {
        obj[key] = '[REDACTED]';
      } else if (typeof obj[key] === 'object' && obj[key] !== null) {
        redactObject(obj[key]);
      }
    }
  }
  
  redactObject(redacted);
  return redacted;
}

function maskEmail(email) {
  if (!email || !email.includes('@')) {
    return '[INVALID_EMAIL]';
  }
  
  const [local, domain] = email.split('@');
  const maskedLocal = local.length <= 2 
    ? '*'.repeat(local.length)
    : local.substring(0, 2) + '*'.repeat(local.length - 2);
  
  return `${maskedLocal}@${domain}`;
}

function logAPIRequest(method, url, headers = {}, payload = null) {
  const safeHeaders = { ...headers };
  if (safeHeaders.Authorization) {
    safeHeaders.Authorization = '[REDACTED]';
  }
  
  const safePayload = payload ? redactSensitiveData(payload) : null;
  
  logger.info('API Request', {
    method,
    url,
    headers: safeHeaders,
    payload: safePayload
  });
}

function logAPIResponse(statusCode, responseTime, payload = null) {
  const safePayload = payload ? redactSensitiveData(payload) : null;
  
  logger.info('API Response', {
    statusCode,
    responseTime: `${responseTime}ms`,
    payload: safePayload
  });
}

// Axios interceptors for automatic logging
function setupLoggingInterceptors(axiosInstance) {
  // Request interceptor
  axiosInstance.interceptors.request.use(
    config => {
      config.metadata = { startTime: Date.now() };
      logAPIRequest(
        config.method.toUpperCase(),
        config.url,
        config.headers,
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
      const responseTime = Date.now() - response.config.metadata.startTime;
      logAPIResponse(response.status, responseTime, response.data);
      return response;
    },
    error => {
      if (error.config && error.config.metadata) {
        const responseTime = Date.now() - error.config.metadata.startTime;
        const status = error.response?.status || 'N/A';
        logAPIResponse(status, responseTime, error.response?.data);
      }
      logger.error('API Error', {
        message: error.message,
        status: error.response?.status,
        url: error.config?.url
      });
      return Promise.reject(error);
    }
  );
}

// Usage
const apiClient = axios.create({
  baseURL: 'https://api.example.com',
  headers: { 'Authorization': `Bearer ${API_KEY}` }
});

setupLoggingInterceptors(apiClient);
```

**Why this is secure**: Sensitive fields are automatically redacted before logging. Winston provides structured logging with appropriate log levels. Axios interceptors enable automatic request/response logging without modifying individual API calls. Email addresses are partially masked to balance troubleshooting with privacy.

---

## Complete Example: Secure API Client

Here's a complete example combining all best practices:

```javascript
const axios = require('axios');
const https = require('https');
const winston = require('winston');

class SecureAPIClient {
  constructor(baseURL, apiKey = null) {
    this.baseURL = baseURL;
    this.apiKey = apiKey || process.env.API_KEY;
    
    if (!this.apiKey) {
      throw new Error('API key must be provided or set in API_KEY environment variable');
    }
    
    this.client = axios.create({
      baseURL: this.baseURL,
      timeout: 10000,
      headers: {
        'Authorization': `Bearer ${this.apiKey}`,
        'Content-Type': 'application/json'
      },
      httpsAgent: new https.Agent({
        rejectUnauthorized: true,
        minVersion: 'TLSv1.2'
      })
    });
    
    this.logger = winston.createLogger({
      level: 'info',
      format: winston.format.json(),
      transports: [new winston.transports.Console()]
    });
    
    this.setupInterceptors();
  }
  
  setupInterceptors() {
    this.client.interceptors.request.use(
      config => {
        config.metadata = { startTime: Date.now() };
        this.logger.info('API Request', {
          method: config.method,
          url: config.url
        });
        return config;
      }
    );
    
    this.client.interceptors.response.use(
      response => {
        const duration = Date.now() - response.config.metadata.startTime;
        this.logger.info('API Response', {
          status: response.status,
          duration: `${duration}ms`
        });
        return response;
      },
      error => {
        this.logger.error('API Error', {
          message: error.message,
          status: error.response?.status
        });
        return Promise.reject(error);
      }
    );
  }
  
  async request(method, endpoint, options = {}) {
    const maxRetries = options.maxRetries || 3;
    
    for (let attempt = 0; attempt < maxRetries; attempt++) {
      try {
        const response = await this.client.request({
          method,
          url: endpoint,
          ...options
        });
        return response.data;
        
      } catch (error) {
        const status = error.response?.status;
        
        if (status === 429 && attempt < maxRetries - 1) {
          const retryAfter = parseInt(error.response.headers['retry-after'] || '60');
          await this.sleep(retryAfter * 1000);
          continue;
        }
        
        if ((status >= 500 || error.code === 'ETIMEDOUT') && attempt < maxRetries - 1) {
          const waitTime = Math.pow(2, attempt) * 1000 + Math.random() * 1000;
          await this.sleep(waitTime);
          continue;
        }
        
        throw error;
      }
    }
  }
  
  sleep(ms) {
    return new Promise(resolve => setTimeout(resolve, ms));
  }
  
  async get(endpoint, params = null) {
    return this.request('GET', endpoint, { params });
  }
  
  async post(endpoint, data = null) {
    return this.request('POST', endpoint, { data });
  }
  
  async put(endpoint, data = null) {
    return this.request('PUT', endpoint, { data });
  }
  
  async delete(endpoint) {
    return this.request('DELETE', endpoint);
  }
}

// Usage
const client = new SecureAPIClient('https://api.example.com');

async function example() {
  try {
    const user = await client.get('/users/123');
    console.log('User data:', user);
    
    const newUser = await client.post('/users', {
      name: 'John Doe',
      email: 'john@example.com'
    });
    console.log('Created user:', newUser);
  } catch (error) {
    console.error('Operation failed:', error.message);
  }
}
```

**Why this is secure**: This client combines all security best practices: secure credential management from environment variables, certificate validation with minimum TLS version enforcement, automatic retry logic with exponential backoff, comprehensive logging through interceptors, and proper error handling. The class provides a clean, reusable interface for all API interactions.