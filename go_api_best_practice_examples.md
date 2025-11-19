# Go API Security Examples

This document provides practical Go examples demonstrating secure API consumption patterns.

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

```go
package main

import (
	"fmt"
	"net/http"
	"os"
	"time"
)

// SecureClient wraps http.Client with authentication
type SecureClient struct {
	client *http.Client
	apiKey string
	baseURL string
}

// NewSecureClient creates a new secure API client
func NewSecureClient(baseURL string) (*SecureClient, error) {
	apiKey := os.Getenv("API_KEY")
	if apiKey == "" {
		return nil, fmt.Errorf("API_KEY environment variable not set")
	}
	
	return &SecureClient{
		client: &http.Client{
			Timeout: 10 * time.Second,
		},
		apiKey: apiKey,
		baseURL: baseURL,
	}, nil
}

// NewRequest creates an authenticated HTTP request
func (c *SecureClient) NewRequest(method, path string) (*http.Request, error) {
	url := c.baseURL + path
	req, err := http.NewRequest(method, url, nil)
	if err != nil {
		return nil, err
	}
	
	// Add authentication header
	req.Header.Set("Authorization", "Bearer "+c.apiKey)
	req.Header.Set("Content-Type", "application/json")
	
	return req, nil
}

func main() {
	client, err := NewSecureClient("https://api.example.com")
	if err != nil {
		panic(err)
	}
	
	req, err := client.NewRequest("GET", "/data")
	if err != nil {
		panic(err)
	}
	
	resp, err := client.client.Do(req)
	if err != nil {
		panic(err)
	}
	defer resp.Body.Close()
}
```

**Why this approach is secure**: Credentials are retrieved from environment variables and never hardcoded. The application fails immediately with a clear error if credentials are missing. The client is configured with a reasonable timeout to prevent indefinite hangs.

---

## HTTPS Communication with Certificate Validation

Always use HTTPS and verify SSL certificates to prevent man-in-the-middle attacks.

```go
package main

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io/ioutil"
	"net/http"
	"time"
)

// CreateSecureHTTPClient creates an HTTP client with strict TLS configuration
func CreateSecureHTTPClient() *http.Client {
	return &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				MinVersion: tls.VersionTLS12, // Enforce TLS 1.2 minimum
				MaxVersion: tls.VersionTLS13,
				// InsecureSkipVerify: false is the default - never set to true
			},
		},
	}
}

// CreateClientWithCustomCA creates a client with custom CA certificate
func CreateClientWithCustomCA(caFile string) (*http.Client, error) {
	// Load CA certificate
	caCert, err := ioutil.ReadFile(caFile)
	if err != nil {
		return nil, fmt.Errorf("failed to read CA certificate: %w", err)
	}
	
	// Create certificate pool
	caCertPool := x509.NewCertPool()
	if !caCertPool.AppendCertsFromPEM(caCert) {
		return nil, fmt.Errorf("failed to parse CA certificate")
	}
	
	return &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				RootCAs: caCertPool,
				MinVersion: tls.VersionTLS12,
			},
		},
	}, nil
}

func main() {
	// Use default secure client
	client := CreateSecureHTTPClient()
	
	resp, err := client.Get("https://api.example.com/data")
	if err != nil {
		panic(err)
	}
	defer resp.Body.Close()
}
```

**Why this is secure**: Certificate validation is enabled by default in Go and explicitly configured. Minimum TLS version is enforced to prevent use of deprecated protocols. Custom CA certificates can be loaded for internal APIs while maintaining certificate validation.

---

## Retry Logic with Exponential Backoff

Implement intelligent retry logic for transient failures with exponential backoff and jitter.

```go
package main

import (
	"fmt"
	"math"
	"math/rand"
	"net/http"
	"strconv"
	"time"
)

// RetryConfig holds retry configuration
type RetryConfig struct {
	MaxRetries int
	BaseDelay  time.Duration
}

// DefaultRetryConfig returns default retry configuration
func DefaultRetryConfig() RetryConfig {
	return RetryConfig{
		MaxRetries: 3,
		BaseDelay:  time.Second,
	}
}

// DoWithRetry performs HTTP request with retry logic
func DoWithRetry(client *http.Client, req *http.Request, config RetryConfig) (*http.Response, error) {
	var resp *http.Response
	var err error
	
	for attempt := 0; attempt < config.MaxRetries; attempt++ {
		resp, err = client.Do(req)
		
		// Success
		if err == nil && resp.StatusCode == http.StatusOK {
			return resp, nil
		}
		
		// Handle rate limiting
		if resp != nil && resp.StatusCode == http.StatusTooManyRequests {
			if attempt < config.MaxRetries-1 {
				retryAfter := getRetryAfter(resp)
				time.Sleep(retryAfter)
				continue
			}
		}
		
		// Handle server errors or network errors
		shouldRetry := err != nil || (resp != nil && resp.StatusCode >= 500)
		if shouldRetry && attempt < config.MaxRetries-1 {
			delay := calculateBackoff(attempt, config.BaseDelay)
			time.Sleep(delay)
			continue
		}
		
		// Client error or final attempt
		if err != nil {
			return nil, err
		}
		return resp, nil
	}
	
	return resp, fmt.Errorf("max retries exceeded")
}

// calculateBackoff calculates exponential backoff with jitter
func calculateBackoff(attempt int, baseDelay time.Duration) time.Duration {
	exponential := math.Pow(2, float64(attempt))
	jitter := rand.Float64() // Random value between 0 and 1
	delay := time.Duration(exponential) * baseDelay
	return delay + time.Duration(jitter*float64(time.Second))
}

// getRetryAfter extracts Retry-After header value
func getRetryAfter(resp *http.Response) time.Duration {
	retryAfter := resp.Header.Get("Retry-After")
	if retryAfter == "" {
		return 60 * time.Second // Default to 60 seconds
	}
	
	seconds, err := strconv.Atoi(retryAfter)
	if err != nil {
		return 60 * time.Second
	}
	
	return time.Duration(seconds) * time.Second
}

func main() {
	client := &http.Client{Timeout: 10 * time.Second}
	req, _ := http.NewRequest("GET", "https://api.example.com/data", nil)
	
	resp, err := DoWithRetry(client, req, DefaultRetryConfig())
	if err != nil {
		fmt.Printf("Request failed: %v\n", err)
		return
	}
	defer resp.Body.Close()
	
	fmt.Printf("Success: %d\n", resp.StatusCode)
}
```

**Why this is secure**: Exponential backoff with jitter prevents overwhelming struggling services and avoids thundering herd problems. Retry-After headers are respected for rate limits. Server errors and network failures trigger retries while client errors do not. The randomized jitter prevents synchronized retry attempts.

---

## Proper Error Handling

Handle errors gracefully and avoid exposing sensitive information in error messages.

```go
package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
)

// APIError represents an API error
type APIError struct {
	Message    string
	StatusCode int
	Err        error
}

func (e *APIError) Error() string {
	return e.Message
}

func (e *APIError) Unwrap() error {
	return e.Err
}

// AuthenticationError represents authentication failures
type AuthenticationError struct {
	*APIError
}

// FetchUserData retrieves user data with proper error handling
func FetchUserData(client *http.Client, userID string, apiKey string) (map[string]interface{}, error) {
	url := fmt.Sprintf("https://api.example.com/users/%s", userID)
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, &APIError{
			Message:    "Failed to create request",
			StatusCode: 0,
			Err:        err,
		}
	}
	
	req.Header.Set("Authorization", "Bearer "+apiKey)
	
	resp, err := client.Do(req)
	if err != nil {
		// Log detailed error for debugging
		log.Printf("Request failed for user %s: %v", userID, err)
		return nil, &APIError{
			Message:    "Service unavailable",
			StatusCode: 0,
			Err:        err,
		}
	}
	defer resp.Body.Close()
	
	// Handle different status codes
	switch resp.StatusCode {
	case http.StatusOK:
		var data map[string]interface{}
		body, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			return nil, &APIError{
				Message:    "Failed to read response",
				StatusCode: resp.StatusCode,
				Err:        err,
			}
		}
		
		if err := json.Unmarshal(body, &data); err != nil {
			return nil, &APIError{
				Message:    "Failed to parse response",
				StatusCode: resp.StatusCode,
				Err:        err,
			}
		}
		
		return data, nil
		
	case http.StatusNotFound:
		log.Printf("User %s not found", userID)
		return nil, &APIError{
			Message:    "User not found",
			StatusCode: http.StatusNotFound,
		}
		
	case http.StatusUnauthorized:
		log.Printf("Authentication failed for user %s", userID)
		return nil, &AuthenticationError{
			&APIError{
				Message:    "Invalid credentials",
				StatusCode: http.StatusUnauthorized,
			},
		}
		
	case http.StatusForbidden:
		return nil, &APIError{
			Message:    "Access denied",
			StatusCode: http.StatusForbidden,
		}
		
	default:
		if resp.StatusCode >= 500 {
			log.Printf("Server error for user %s: %d", userID, resp.StatusCode)
			return nil, &APIError{
				Message:    "Service temporarily unavailable",
				StatusCode: resp.StatusCode,
			}
		}
		
		log.Printf("Request failed for user %s: %d", userID, resp.StatusCode)
		return nil, &APIError{
			Message:    "Request failed",
			StatusCode: resp.StatusCode,
		}
	}
}

func main() {
	client := &http.Client{Timeout: 10 * time.Second}
	apiKey := os.Getenv("API_KEY")
	
	userData, err := FetchUserData(client, "123", apiKey)
	if err != nil {
		// Handle different error types
		if authErr, ok := err.(*AuthenticationError); ok {
			fmt.Printf("Authentication error: %s\n", authErr.Message)
		} else if apiErr, ok := err.(*APIError); ok {
			fmt.Printf("API error: %s (status: %d)\n", apiErr.Message, apiErr.StatusCode)
		} else {
			fmt.Printf("Unexpected error: %v\n", err)
		}
		return
	}
	
	fmt.Printf("User data: %v\n", userData)
}
```

**Why this is secure**: Detailed errors are logged for debugging but generic messages are returned to callers through custom error types. Go's error wrapping allows preserving error context without exposing sensitive details. Type assertions enable appropriate handling of different error categories.

---

## Input Validation and Sanitization

Validate and sanitize all inputs before including them in API requests.

```go
package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strings"
)

var emailRegex = regexp.MustCompile(`^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$`)

// ValidateEmail validates email format
func ValidateEmail(email string) bool {
	return emailRegex.MatchString(email)
}

// SanitizeInput sanitizes user input
func SanitizeInput(input string, maxLength int) (string, error) {
	// Validate type (Go is type-safe by default)
	if len(input) > maxLength {
		return "", fmt.Errorf("input exceeds maximum length of %d", maxLength)
	}
	
	// Remove null bytes and trim whitespace
	sanitized := strings.ReplaceAll(input, "\x00", "")
	sanitized = strings.TrimSpace(sanitized)
	
	return sanitized, nil
}

// SearchUsers searches for users with proper input validation
func SearchUsers(client *http.Client, searchTerm, apiKey string) ([]map[string]interface{}, error) {
	// Sanitize input
	sanitized, err := SanitizeInput(searchTerm, 50)
	if err != nil {
		return nil, err
	}
	
	// URL encode query parameter
	baseURL := "https://api.example.com/users/search"
	params := url.Values{}
	params.Add("q", sanitized)
	fullURL := baseURL + "?" + params.Encode()
	
	req, err := http.NewRequest("GET", fullURL, nil)
	if err != nil {
		return nil, err
	}
	
	req.Header.Set("Authorization", "Bearer "+apiKey)
	
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	
	var results []map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&results); err != nil {
		return nil, err
	}
	
	return results, nil
}

// CreateUserRequest represents user creation payload
type CreateUserRequest struct {
	Email string `json:"email"`
	Name  string `json:"name"`
}

// CreateUser creates a user with input validation
func CreateUser(client *http.Client, email, name, apiKey string) (map[string]interface{}, error) {
	// Validate email
	if !ValidateEmail(email) {
		return nil, errors.New("invalid email format")
	}
	
	// Sanitize name
	sanitizedName, err := SanitizeInput(name, 100)
	if err != nil {
		return nil, err
	}
	
	// Create request payload (JSON encoding handles escaping)
	payload := CreateUserRequest{
		Email: email,
		Name:  sanitizedName,
	}
	
	jsonData, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}
	
	req, err := http.NewRequest("POST", "https://api.example.com/users", bytes.NewBuffer(jsonData))
	if err != nil {
		return nil, err
	}
	
	req.Header.Set("Authorization", "Bearer "+apiKey)
	req.Header.Set("Content-Type", "application/json")
	
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	
	var result map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}
	
	return result, nil
}
```

**Why this is secure**: Input validation prevents injection attacks and malformed requests. Go's url.Values automatically handles URL encoding. The json.Marshal function properly escapes JSON data, preventing injection through manual string concatenation. Type-safe structs provide additional validation.

---

## Secure Logging with Redaction

Log API interactions for troubleshooting while protecting sensitive information.

```go
package main

import (
	"encoding/json"
	"log"
	"strings"
	"time"
)

// Logger provides secure logging with redaction
type Logger struct {
	sensitiveFields []string
}

// NewLogger creates a new logger instance
func NewLogger() *Logger {
	return &Logger{
		sensitiveFields: []string{
			"password", "api_key", "apikey", "token", "secret",
			"authorization", "ssn", "credit_card", "cvv", "pin",
		},
	}
}

// RedactSensitiveData redacts sensitive fields from data
func (l *Logger) RedactSensitiveData(data map[string]interface{}) map[string]interface{} {
	redacted := make(map[string]interface{})
	
	for key, value := range data {
		lowerKey := strings.ToLower(key)
		isSensitive := false
		
		for _, field := range l.sensitiveFields {
			if strings.Contains(lowerKey, field) {
				isSensitive = true
				break
			}
		}
		
		if isSensitive {
			redacted[key] = "[REDACTED]"
		} else if nested, ok := value.(map[string]interface{}); ok {
			redacted[key] = l.RedactSensitiveData(nested)
		} else {
			redacted[key] = value
		}
	}
	
	return redacted
}

// MaskEmail partially masks email addresses
func MaskEmail(email string) string {
	parts := strings.Split(email, "@")
	if len(parts) != 2 {
		return "[INVALID_EMAIL]"
	}
	
	local := parts[0]
	domain := parts[1]
	
	if len(local) <= 2 {
		return strings.Repeat("*", len(local)) + "@" + domain
	}
	
	masked := local[:2] + strings.Repeat("*", len(local)-2)
	return masked + "@" + domain
}

// LogAPIRequest logs an API request with redaction
func (l *Logger) LogAPIRequest(method, url string, headers map[string]string, payload map[string]interface{}) {
	safeHeaders := make(map[string]string)
	for k, v := range headers {
		if strings.ToLower(k) == "authorization" {
			safeHeaders[k] = "[REDACTED]"
		} else {
			safeHeaders[k] = v
		}
	}
	
	var safePayload map[string]interface{}
	if payload != nil {
		safePayload = l.RedactSensitiveData(payload)
	}
	
	logData := map[string]interface{}{
		"timestamp": time.Now().Format(time.RFC3339),
		"type":      "request",
		"method":    method,
		"url":       url,
		"headers":   safeHeaders,
		"payload":   safePayload,
	}
	
	jsonLog, _ := json.Marshal(logData)
	log.Println(string(jsonLog))
}

// LogAPIResponse logs an API response with redaction
func (l *Logger) LogAPIResponse(statusCode int, responseTime time.Duration, payload map[string]interface{}) {
	var safePayload map[string]interface{}
	if payload != nil {
		safePayload = l.RedactSensitiveData(payload)
	}
	
	logData := map[string]interface{}{
		"timestamp":     time.Now().Format(time.RFC3339),
		"type":          "response",
		"status_code":   statusCode,
		"response_time": responseTime.Milliseconds(),
		"payload":       safePayload,
	}
	
	jsonLog, _ := json.Marshal(logData)
	log.Println(string(jsonLog))
}

func main() {
	logger := NewLogger()
	
	// Example: Log API request
	headers := map[string]string{
		"Authorization": "Bearer secret-token",
		"Content-Type":  "application/json",
	}
	
	payload := map[string]interface{}{
		"email":   "user@example.com",
		"api_key": "super-secret-key",
		"name":    "John Doe",
	}
	
	logger.LogAPIRequest("POST", "https://api.example.com/users", headers, payload)
	
	// Example: Log API response
	responsePayload := map[string]interface{}{
		"id":    123,
		"email": "user@example.com",
		"token": "response-token",
	}
	
	logger.LogAPIResponse(200, 150*time.Millisecond, responsePayload)
}
```

**Why this is secure**: Sensitive fields are automatically identified and redacted before logging. JSON structured logging enables easy parsing and analysis. Deep copying prevents modification of original data structures. Email masking provides a balance between privacy and troubleshooting capabilities.

---

## Complete Example: Secure API Client

Here's a complete example combining all best practices:

```go
package main

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"math"
	"math/rand"
	"net/http"
	"os"
	"time"
)

// SecureAPIClient implements secure API consumption
type SecureAPIClient struct {
	client  *http.Client
	baseURL string
	apiKey  string
	logger  *Logger
}

// NewSecureAPIClient creates a new secure API client
func NewSecureAPIClient(baseURL string) (*SecureAPIClient, error) {
	apiKey := os.Getenv("API_KEY")
	if apiKey == "" {
		return nil, fmt.Errorf("API_KEY environment variable not set")
	}
	
	return &SecureAPIClient{
		client: &http.Client{
			Timeout: 10 * time.Second,
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{
					MinVersion: tls.VersionTLS12,
				},
			},
		},
		baseURL: baseURL,
		apiKey:  apiKey,
		logger:  NewLogger(),
	}, nil
}

// doRequest performs HTTP request with retry logic
func (c *SecureAPIClient) doRequest(method, path string, body interface{}) (*http.Response, error) {
	maxRetries := 3
	
	for attempt := 0; attempt < maxRetries; attempt++ {
		var reqBody *bytes.Buffer
		if body != nil {
			jsonData, err := json.Marshal(body)
			if err != nil {
				return nil, err
			}
			reqBody = bytes.NewBuffer(jsonData)
		}
		
		var req *http.Request
		var err error
		if reqBody != nil {
			req, err = http.NewRequest(method, c.baseURL+path, reqBody)
		} else {
			req, err = http.NewRequest(method, c.baseURL+path, nil)
		}
		
		if err != nil {
			return nil, err
		}
		
		req.Header.Set("Authorization", "Bearer "+c.apiKey)
		req.Header.Set("Content-Type", "application/json")
		
		startTime := time.Now()
		resp, err := c.client.Do(req)
		responseTime := time.Since(startTime)
		
		if err == nil {
			c.logger.LogAPIResponse(resp.StatusCode, responseTime, nil)
			
			if resp.StatusCode == http.StatusOK {
				return resp, nil
			}
			
			if resp.StatusCode >= 500 && attempt < maxRetries-1 {
				delay := time.Duration(math.Pow(2, float64(attempt))) * time.Second
				jitter := time.Duration(rand.Float64() * float64(time.Second))
				time.Sleep(delay + jitter)
				continue
			}
			
			return resp, nil
		}
		
		if attempt < maxRetries-1 {
			delay := time.Duration(math.Pow(2, float64(attempt))) * time.Second
			jitter := time.Duration(rand.Float64() * float64(time.Second))
			time.Sleep(delay + jitter)
		}
	}
	
	return nil, fmt.Errorf("max retries exceeded")
}

// Get performs GET request
func (c *SecureAPIClient) Get(path string) (map[string]interface{}, error) {
	resp, err := c.doRequest("GET", path, nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	
	var result map[string]interface{}
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, err
	}
	
	return result, nil
}

// Post performs POST request
func (c *SecureAPIClient) Post(path string, data interface{}) (map[string]interface{}, error) {
	resp, err := c.doRequest("POST", path, data)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	
	var result map[string]interface{}
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, err
	}
	
	return result, nil
}

func main() {
	client, err := NewSecureAPIClient("https://api.example.com")
	if err != nil {
		log.Fatal(err)
	}
	
	// Example GET request
	user, err := client.Get("/users/123")
	if err != nil {
		log.Printf("Failed to get user: %v", err)
		return
	}
	fmt.Printf("User: %v\n", user)
}
```

**Why this is secure**: This client combines all security best practices: environment-based credential management, TLS 1.2+ enforcement with certificate validation, automatic retry logic with exponential backoff and jitter, structured logging with automatic redaction, and proper error handling. Go's type safety and explicit error handling make security issues visible at compile time.