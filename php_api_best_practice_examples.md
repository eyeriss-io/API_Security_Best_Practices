# PHP API Security Examples

This document provides practical PHP examples demonstrating secure API consumption patterns using modern PHP features.

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

```php
<?php

class SecureAPIClient
{
    private $apiKey;
    private $baseUrl;
    private $timeout = 10;
    
    public function __construct(string $baseUrl)
    {
        // Retrieve API key from environment variable
        $this->apiKey = getenv('API_KEY');
        if (empty($this->apiKey)) {
            throw new RuntimeException('API_KEY environment variable not set');
        }
        
        $this->baseUrl = rtrim($baseUrl, '/');
    }
    
    private function createContext(): array
    {
        return [
            'http' => [
                'method' => 'GET',
                'header' => "Authorization: Bearer {$this->apiKey}\r\n" .
                           "Content-Type: application/json\r\n",
                'timeout' => $this->timeout,
                'ignore_errors' => true
            ]
        ];
    }
    
    public function fetchData(): string
    {
        $url = $this->baseUrl . '/data';
        $context = stream_context_create($this->createContext());
        
        $result = file_get_contents($url, false, $context);
        
        if ($result === false) {
            throw new RuntimeException('Request failed');
        }
        
        return $result;
    }
}

// Usage
try {
    $client = new SecureAPIClient('https://api.example.com');
    $data = $client->fetchData();
    echo $data;
} catch (Exception $e) {
    echo "Error: " . $e->getMessage();
}
```

**Why this approach is secure**: Credentials are retrieved from environment variables using getenv() and never hardcoded. The application throws an exception immediately if credentials are missing. Stream context is configured with appropriate timeouts.

---

## HTTPS Communication with Certificate Validation

Always use HTTPS and verify SSL certificates to prevent man-in-the-middle attacks.

```php
<?php

class SecureHTTPClient
{
    public static function createSecureContext(): array
    {
        return [
            'ssl' => [
                // Certificate verification enabled (default)
                'verify_peer' => true,
                'verify_peer_name' => true,
                // Require TLS 1.2 or higher
                'crypto_method' => STREAM_CRYPTO_METHOD_TLSv1_2_CLIENT |
                                 STREAM_CRYPTO_METHOD_TLSv1_3_CLIENT,
                // Use default CA bundle
                'cafile' => null,
                'allow_self_signed' => false
            ],
            'http' => [
                'timeout' => 10
            ]
        ];
    }
    
    public static function createContextWithCustomCA(string $caFilePath): array
    {
        return [
            'ssl' => [
                'verify_peer' => true,
                'verify_peer_name' => true,
                'cafile' => $caFilePath,
                'crypto_method' => STREAM_CRYPTO_METHOD_TLSv1_2_CLIENT |
                                 STREAM_CRYPTO_METHOD_TLSv1_3_CLIENT
            ],
            'http' => [
                'timeout' => 10
            ]
        ];
    }
    
    public static function makeRequest(string $url): string
    {
        $context = stream_context_create(self::createSecureContext());
        $result = file_get_contents($url, false, $context);
        
        if ($result === false) {
            throw new RuntimeException('Request failed');
        }
        
        return $result;
    }
}

// Usage
try {
    $response = SecureHTTPClient::makeRequest('https://api.example.com/data');
    echo "Response: $response";
} catch (Exception $e) {
    echo "Error: " . $e->getMessage();
}
```

**Why this is secure**: Certificate verification is explicitly enabled with verify_peer and verify_peer_name. Minimum TLS version is enforced through crypto_method. Custom CA certificates can be loaded for internal APIs while maintaining verification.

---

## Retry Logic with Exponential Backoff

Implement intelligent retry logic for transient failures with exponential backoff and jitter.

```php
<?php

class RetryLogic
{
    private const MAX_RETRIES = 3;
    
    public static function sendWithRetry(string $url, array $options = []): string
    {
        $lastError = null;
        
        for ($attempt = 0; $attempt < self::MAX_RETRIES; $attempt++) {
            try {
                $context = stream_context_create($options);
                $result = @file_get_contents($url, false, $context);
                
                // Parse response headers
                $statusCode = self::getStatusCode($http_response_header ?? []);
                
                // Success
                if ($result !== false && $statusCode >= 200 && $statusCode < 300) {
                    return $result;
                }
                
                // Rate limited - respect Retry-After header
                if ($statusCode === 429) {
                    if ($attempt < self::MAX_RETRIES - 1) {
                        $retryAfter = self::getRetryAfter($http_response_header ?? []);
                        sleep($retryAfter);
                        continue;
                    }
                }
                
                // Server error - retry with backoff
                if ($statusCode >= 500) {
                    if ($attempt < self::MAX_RETRIES - 1) {
                        $waitTime = self::calculateBackoff($attempt);
                        usleep($waitTime * 1000000);
                        continue;
                    }
                }
                
                // Client error or final attempt
                return $result ?: '';
                
            } catch (Exception $e) {
                $lastError = $e;
                
                // Network error - retry with backoff
                if ($attempt < self::MAX_RETRIES - 1) {
                    $waitTime = self::calculateBackoff($attempt);
                    usleep($waitTime * 1000000);
                } else {
                    throw $e;
                }
            }
        }
        
        throw new RuntimeException('Max retries exceeded', 0, $lastError);
    }
    
    private static function calculateBackoff(int $attempt): float
    {
        // Exponential backoff with jitter
        $exponential = pow(2, $attempt);
        $jitter = mt_rand(0, 1000) / 1000;
        return $exponential + $jitter;
    }
    
    private static function getStatusCode(array $headers): int
    {
        if (empty($headers)) {
            return 0;
        }
        
        preg_match('/HTTP\/\d\.\d\s+(\d+)/', $headers[0], $matches);
        return isset($matches[1]) ? (int)$matches[1] : 0;
    }
    
    private static function getRetryAfter(array $headers): int
    {
        foreach ($headers as $header) {
            if (stripos($header, 'Retry-After:') === 0) {
                $value = trim(substr($header, 12));
                return (int)$value ?: 60;
            }
        }
        return 60; // Default to 60 seconds
    }
}

// Usage
try {
    $options = [
        'http' => [
            'method' => 'GET',
            'header' => 'Authorization: Bearer ' . getenv('API_KEY'),
            'timeout' => 10
        ]
    ];
    
    $response = RetryLogic::sendWithRetry('https://api.example.com/data', $options);
    echo "Success: $response";
} catch (Exception $e) {
    echo "Request failed: " . $e->getMessage();
}
```

**Why this is secure**: Exponential backoff with jitter prevents overwhelming struggling services. Retry-After headers are parsed and respected. Server errors and network failures trigger retries while client errors do not. Random jitter prevents thundering herd problems.

---

## Proper Error Handling

Handle errors gracefully and avoid exposing sensitive information in error messages.

```php
<?php

// Custom exception classes
class APIException extends Exception
{
    protected $statusCode;
    
    public function __construct(string $message, int $statusCode = 0, ?Throwable $previous = null)
    {
        parent::__construct($message, 0, $previous);
        $this->statusCode = $statusCode;
    }
    
    public function getStatusCode(): int
    {
        return $this->statusCode;
    }
}

class AuthenticationException extends APIException
{
    public function __construct(string $message = 'Invalid credentials')
    {
        parent::__construct($message, 401);
    }
}

class ServiceUnavailableException extends APIException
{
    public function __construct(string $message, int $statusCode)
    {
        parent::__construct($message, $statusCode);
    }
}

class ErrorHandling
{
    private $logger;
    
    public function __construct()
    {
        $this->logger = function($level, $message) {
            error_log("[$level] $message");
        };
    }
    
    public function fetchUserData(string $userId, string $apiKey): string
    {
        try {
            $url = "https://api.example.com/users/$userId";
            
            $options = [
                'http' => [
                    'method' => 'GET',
                    'header' => "Authorization: Bearer $apiKey\r\n",
                    'timeout' => 10,
                    'ignore_errors' => true
                ]
            ];
            
            $context = stream_context_create($options);
            $result = @file_get_contents($url, false, $context);
            
            // Parse status code from response headers
            $statusCode = 0;
            if (isset($http_response_header)) {
                preg_match('/HTTP\/\d\.\d\s+(\d+)/', $http_response_header[0], $matches);
                $statusCode = isset($matches[1]) ? (int)$matches[1] : 0;
            }
            
            // Handle different status codes
            if ($statusCode >= 200 && $statusCode < 300) {
                return $result;
            } elseif ($statusCode === 404) {
                ($this->logger)('WARNING', "User $userId not found");
                throw new APIException('User not found', 404);
            } elseif ($statusCode === 401) {
                ($this->logger)('ERROR', "Authentication failed for user $userId");
                throw new AuthenticationException();
            } elseif ($statusCode === 403) {
                throw new APIException('Access denied', 403);
            } elseif ($statusCode >= 500) {
                ($this->logger)('ERROR', "Server error for user $userId: $statusCode");
                throw new ServiceUnavailableException('Service temporarily unavailable', $statusCode);
            } else {
                ($this->logger)('WARNING', "Request failed for user $userId: $statusCode");
                throw new APIException('Request failed', $statusCode);
            }
            
        } catch (APIException $e) {
            throw $e;
        } catch (Exception $e) {
            ($this->logger)('ERROR', "Connection error for user $userId: " . $e->getMessage());
            throw new APIException('Service unavailable', 0, $e);
        }
    }
}

// Usage
$handler = new ErrorHandling();
$apiKey = getenv('API_KEY');

try {
    $userData = $handler->fetchUserData('123', $apiKey);
    echo "User data: $userData";
} catch (AuthenticationException $e) {
    echo "Authentication error: " . $e->getMessage();
} catch (ServiceUnavailableException $e) {
    echo "Service error: " . $e->getMessage() . " (status: " . $e->getStatusCode() . ")";
} catch (APIException $e) {
    echo "API error: " . $e->getMessage() . " (status: " . $e->getStatusCode() . ")";
}
```

**Why this is secure**: Detailed errors are logged for debugging but generic messages are thrown to callers. Custom exception hierarchy enables appropriate error handling. Network errors and HTTP errors are handled separately with appropriate logging.

---

## Input Validation and Sanitization

Validate and sanitize all inputs before including them in API requests.

```php
<?php

class InputValidation
{
    private const EMAIL_PATTERN = '/^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/';
    
    public static function validateEmail(string $email): bool
    {
        return (bool)preg_match(self::EMAIL_PATTERN, $email);
    }
    
    public static function sanitizeInput(string $input, int $maxLength = 100): string
    {
        if (strlen($input) > $maxLength) {
            throw new InvalidArgumentException("Input exceeds maximum length of $maxLength");
        }
        
        // Remove null bytes and trim whitespace
        $sanitized = str_replace("\0", '', $input);
        return trim($sanitized);
    }
    
    public static function searchUsers(string $searchTerm, string $apiKey): string
    {
        // Sanitize input
        $sanitized = self::sanitizeInput($searchTerm, 50);
        
        // URL encode query parameter
        $encoded = urlencode($sanitized);
        
        $url = "https://api.example.com/users/search?q=$encoded";
        
        $options = [
            'http' => [
                'method' => 'GET',
                'header' => "Authorization: Bearer $apiKey\r\n",
                'timeout' => 10
            ]
        ];
        
        $context = stream_context_create($options);
        $result = file_get_contents($url, false, $context);
        
        return $result;
    }
    
    public static function createUser(string $email, string $name, string $apiKey): string
    {
        // Validate email
        if (!self::validateEmail($email)) {
            throw new InvalidArgumentException('Invalid email format');
        }
        
        // Sanitize name
        $sanitizedName = self::sanitizeInput($name, 100);
        
        // Create JSON payload (json_encode handles escaping)
        $payload = json_encode([
            'email' => $email,
            'name' => $sanitizedName
        ]);
        
        $options = [
            'http' => [
                'method' => 'POST',
                'header' => "Authorization: Bearer $apiKey\r\n" .
                           "Content-Type: application/json\r\n",
                'content' => $payload,
                'timeout' => 10
            ]
        ];
        
        $context = stream_context_create($options);
        $result = file_get_contents('https://api.example.com/users', false, $context);
        
        return $result;
    }
}

// Usage
$apiKey = getenv('API_KEY');

try {
    // Search with validated input
    $results = InputValidation::searchUsers('John', $apiKey);
    echo "Search results: $results\n";
    
    // Create user with validated input
    $newUser = InputValidation::createUser('john@example.com', 'John Doe', $apiKey);
    echo "Created user: $newUser\n";
} catch (InvalidArgumentException $e) {
    echo "Validation error: " . $e->getMessage();
} catch (Exception $e) {
    echo "Request failed: " . $e->getMessage();
}
```

**Why this is secure**: Input validation prevents injection attacks and malformed requests. urlencode() properly handles special characters in query parameters. json_encode() automatically escapes data, preventing injection through manual string concatenation.

---

## Secure Logging with Redaction

Log API interactions for troubleshooting while protecting sensitive information.

```php
<?php

class SecureLogging
{
    private const SENSITIVE_FIELDS = [
        'password', 'api_key', 'apikey', 'token', 'secret',
        'authorization', 'ssn', 'credit_card', 'cvv', 'pin'
    ];
    
    public function redactSensitiveData(?array $data): ?array
    {
        if ($data === null) {
            return null;
        }
        
        $redacted = [];
        
        foreach ($data as $key => $value) {
            $lowerKey = strtolower($key);
            $isSensitive = false;
            
            foreach (self::SENSITIVE_FIELDS as $field) {
                if (strpos($lowerKey, $field) !== false) {
                    $isSensitive = true;
                    break;
                }
            }
            
            if ($isSensitive) {
                $redacted[$key] = '[REDACTED]';
            } elseif (is_array($value)) {
                $redacted[$key] = $this->redactSensitiveData($value);
            } else {
                $redacted[$key] = $value;
            }
        }
        
        return $redacted;
    }
    
    public function maskEmail(string $email): string
    {
        if (empty($email) || strpos($email, '@') === false) {
            return '[INVALID_EMAIL]';
        }
        
        list($local, $domain) = explode('@', $email, 2);
        
        if (strlen($local) <= 2) {
            $masked = str_repeat('*', strlen($local));
        } else {
            $masked = substr($local, 0, 2) . str_repeat('*', strlen($local) - 2);
        }
        
        return "$masked@$domain";
    }
    
    public function logAPIRequest(string $method, string $url, array $headers = [], ?array $payload = null): void
    {
        $safeHeaders = $headers;
        if (isset($safeHeaders['Authorization'])) {
            $safeHeaders['Authorization'] = '[REDACTED]';
        }
        
        $safePayload = $payload ? $this->redactSensitiveData($payload) : null;
        
        $logData = [
            'timestamp' => date('c'),
            'type' => 'request',
            'method' => $method,
            'url' => $url,
            'headers' => $safeHeaders,
            'payload' => $safePayload
        ];
        
        error_log(json_encode($logData));
    }
    
    public function logAPIResponse(int $statusCode, float $responseTimeMs, ?array $payload = null): void
    {
        $safePayload = $payload ? $this->redactSensitiveData($payload) : null;
        
        $logData = [
            'timestamp' => date('c'),
            'type' => 'response',
            'status_code' => $statusCode,
            'response_time_ms' => $responseTimeMs,
            'payload' => $safePayload
        ];
        
        error_log(json_encode($logData));
    }
}

// Usage
$logger = new SecureLogging();

// Example: Log API request
$headers = [
    'Authorization' => 'Bearer secret-token',
    'Content-Type' => 'application/json'
];

$payload = [
    'email' => 'user@example.com',
    'api_key' => 'super-secret-key',
    'name' => 'John Doe'
];

$logger->logAPIRequest('POST', 'https://api.example.com/users', $headers, $payload);

// Example: Log API response
$responsePayload = [
    'id' => 123,
    'email' => 'user@example.com',
    'token' => 'response-token'
];

$logger->logAPIResponse(200, 150.5, $responsePayload);

// Example: Mask email
echo "Masked email: " . $logger->maskEmail('john.doe@example.com') . "\n";
```

**Why this is secure**: Sensitive fields are automatically identified and redacted based on field names. JSON structured logging enables easy parsing. Array operations prevent modification of original data. Email masking balances privacy with troubleshooting needs.

---

## Complete Example: Secure API Client

Here's a complete example combining all best practices:

```php
<?php

class CompleteSecureAPIClient
{
    private const MAX_RETRIES = 3;
    
    private $apiKey;
    private $baseUrl;
    private $logger;
    
    public function __construct(string $baseUrl)
    {
        $this->apiKey = getenv('API_KEY');
        if (empty($this->apiKey)) {
            throw new RuntimeException('API_KEY environment variable not set');
        }
        
        $this->baseUrl = rtrim($baseUrl, '/');
        $this->logger = function($message) {
            error_log($message);
        };
    }
    
    private function doRequest(string $method, string $path, ?array $body = null): string
    {
        for ($attempt = 0; $attempt < self::MAX_RETRIES; $attempt++) {
            try {
                $url = $this->baseUrl . $path;
                
                $options = [
                    'http' => [
                        'method' => $method,
                        'header' => "Authorization: Bearer {$this->apiKey}\r\n" .
                                   "Content-Type: application/json\r\n",
                        'timeout' => 10,
                        'ignore_errors' => true
                    ],
                    'ssl' => [
                        'verify_peer' => true,
                        'verify_peer_name' => true,
                        'crypto_method' => STREAM_CRYPTO_METHOD_TLSv1_2_CLIENT |
                                         STREAM_CRYPTO_METHOD_TLSv1_3_CLIENT
                    ]
                ];
                
                if ($body !== null) {
                    $options['http']['content'] = json_encode($body);
                }
                
                $context = stream_context_create($options);
                
                $startTime = microtime(true);
                $result = @file_get_contents($url, false, $context);
                $elapsed = (microtime(true) - $startTime) * 1000;
                
                // Parse status code
                $statusCode = 0;
                if (isset($http_response_header)) {
                    preg_match('/HTTP\/\d\.\d\s+(\d+)/', $http_response_header[0], $matches);
                    $statusCode = isset($matches[1]) ? (int)$matches[1] : 0;
                }
                
                ($this->logger)("Response: $statusCode ({$elapsed}ms)");
                
                if ($statusCode >= 200 && $statusCode < 300) {
                    return $result;
                }
                
                if ($statusCode >= 500 && $attempt < self::MAX_RETRIES - 1) {
                    $waitTime = $this->calculateBackoff($attempt);
                    usleep($waitTime * 1000000);
                    continue;
                }
                
                return $result ?: '';
                
            } catch (Exception $e) {
                ($this->logger)("Request attempt " . ($attempt + 1) . " failed: " . $e->getMessage());
                
                if ($attempt < self::MAX_RETRIES - 1) {
                    $waitTime = $this->calculateBackoff($attempt);
                    usleep($waitTime * 1000000);
                } else {
                    throw $e;
                }
            }
        }
        
        throw new RuntimeException('Max retries exceeded');
    }
    
    private function calculateBackoff(int $attempt): float
    {
        $exponential = pow(2, $attempt);
        $jitter = mt_rand(0, 1000) / 1000;
        return $exponential + $jitter;
    }
    
    public function get(string $path): string
    {
        return $this->doRequest('GET', $path);
    }
    
    public function post(string $path, array $data): string
    {
        return $this->doRequest('POST', $path, $data);
    }
}

// Usage
try {
    $client = new CompleteSecureAPIClient('https://api.example.com');
    
    // Example GET request
    $user = $client->get('/users/123');
    echo "User: $user\n";
    
    // Example POST request
    $newUser = ['name' => 'John Doe', 'email' => 'john@example.com'];
    $created = $client->post('/users', $newUser);
    echo "Created: $created\n";
} catch (Exception $e) {
    echo "Error: " . $e->getMessage();
}
```

**Why this is secure**: This client combines all security best practices: environment-based credential management, TLS 1.2/1.3 enforcement with certificate validation, automatic retry logic with exponential backoff and jitter, structured logging, and proper error handling. PHP's stream context provides flexible configuration for secure HTTP communication.