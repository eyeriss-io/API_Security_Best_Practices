# C# API Security Examples

This document provides practical C# examples demonstrating secure API consumption patterns using modern .NET features.

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

```csharp
using System;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Threading.Tasks;

public class SecureAPIClient
{
    private readonly HttpClient _client;
    private readonly string _apiKey;
    private readonly string _baseUrl;
    
    public SecureAPIClient(string baseUrl)
    {
        // Retrieve API key from environment variable
        _apiKey = Environment.GetEnvironmentVariable("API_KEY");
        if (string.IsNullOrEmpty(_apiKey))
        {
            throw new InvalidOperationException("API_KEY environment variable not set");
        }
        
        _baseUrl = baseUrl;
        _client = new HttpClient
        {
            BaseAddress = new Uri(baseUrl),
            Timeout = TimeSpan.FromSeconds(10)
        };
        
        // Set default headers
        _client.DefaultRequestHeaders.Authorization = 
            new AuthenticationHeaderValue("Bearer", _apiKey);
        _client.DefaultRequestHeaders.Accept.Add(
            new MediaTypeWithQualityHeaderValue("application/json"));
    }
    
    public async Task<string> FetchDataAsync()
    {
        var response = await _client.GetAsync("/data");
        response.EnsureSuccessStatusCode();
        return await response.Content.ReadAsStringAsync();
    }
    
    public static async Task Main(string[] args)
    {
        try
        {
            var client = new SecureAPIClient("https://api.example.com");
            var data = await client.FetchDataAsync();
            Console.WriteLine(data);
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Error: {ex.Message}");
        }
    }
}
```

**Why this is secure**: Credentials are retrieved from environment variables and never hardcoded. The application fails immediately with a clear error if credentials are missing. HttpClient is configured with appropriate timeouts and reused for connection pooling.

---

## HTTPS Communication with Certificate Validation

Always use HTTPS and verify SSL certificates to prevent man-in-the-middle attacks.

```csharp
using System;
using System.Net.Http;
using System.Net.Security;
using System.Security.Cryptography.X509Certificates;

public class SecureHTTPClient
{
    // Create HttpClient with default secure settings
    public static HttpClient CreateSecureClient()
    {
        var handler = new HttpClientHandler
        {
            // Certificate validation is enabled by default
            ServerCertificateCustomValidationCallback = null,
            // Enforce modern TLS versions
            SslProtocols = System.Security.Authentication.SslProtocols.Tls12 | 
                          System.Security.Authentication.SslProtocols.Tls13
        };
        
        return new HttpClient(handler)
        {
            Timeout = TimeSpan.FromSeconds(10)
        };
    }
    
    // Create client with custom CA certificate
    public static HttpClient CreateClientWithCustomCA(string caFilePath)
    {
        var handler = new HttpClientHandler
        {
            ServerCertificateCustomValidationCallback = (message, cert, chain, errors) =>
            {
                if (errors == SslPolicyErrors.None)
                {
                    return true;
                }
                
                // Load custom CA certificate
                var customCA = new X509Certificate2(caFilePath);
                chain.ChainPolicy.ExtraStore.Add(customCA);
                chain.ChainPolicy.VerificationFlags = 
                    X509VerificationFlags.AllowUnknownCertificateAuthority;
                
                // Verify the certificate chain
                bool isValid = chain.Build(cert);
                
                if (isValid)
                {
                    // Check if chain ends with our custom CA
                    var chainRoot = chain.ChainElements[chain.ChainElements.Count - 1].Certificate;
                    isValid = chainRoot.RawData.SequenceEqual(customCA.RawData);
                }
                
                return isValid;
            },
            SslProtocols = System.Security.Authentication.SslProtocols.Tls12 | 
                          System.Security.Authentication.SslProtocols.Tls13
        };
        
        return new HttpClient(handler)
        {
            Timeout = TimeSpan.FromSeconds(10)
        };
    }
    
    public static async Task Main(string[] args)
    {
        using var client = CreateSecureClient();
        
        var response = await client.GetAsync("https://api.example.com/data");
        var content = await response.Content.ReadAsStringAsync();
        
        Console.WriteLine($"Response: {content}");
    }
}
```

**Why this is secure**: Certificate validation is enabled by default in HttpClientHandler. TLS 1.2 and 1.3 are explicitly enforced. Custom CA certificate validation is implemented securely, verifying the entire certificate chain rather than bypassing validation.

---

## Retry Logic with Exponential Backoff

Implement intelligent retry logic for transient failures with exponential backoff and jitter.

```csharp
using System;
using System.Net;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;

public class RetryLogic
{
    private static readonly Random _random = new Random();
    private const int MaxRetries = 3;
    
    public static async Task<HttpResponseMessage> SendWithRetryAsync(
        HttpClient client,
        HttpRequestMessage request,
        CancellationToken cancellationToken = default)
    {
        HttpResponseMessage response = null;
        Exception lastException = null;
        
        for (int attempt = 0; attempt < MaxRetries; attempt++)
        {
            try
            {
                // Clone the request for retry attempts
                var clonedRequest = await CloneRequestAsync(request);
                response = await client.SendAsync(clonedRequest, cancellationToken);
                
                // Success
                if (response.IsSuccessStatusCode)
                {
                    return response;
                }
                
                // Rate limited - respect Retry-After header
                if (response.StatusCode == HttpStatusCode.TooManyRequests)
                {
                    if (attempt < MaxRetries - 1)
                    {
                        var retryAfter = GetRetryAfter(response);
                        await Task.Delay(retryAfter, cancellationToken);
                        continue;
                    }
                }
                
                // Server error - retry with backoff
                if ((int)response.StatusCode >= 500)
                {
                    if (attempt < MaxRetries - 1)
                    {
                        var delay = CalculateBackoff(attempt);
                        await Task.Delay(delay, cancellationToken);
                        continue;
                    }
                }
                
                // Client error or final attempt
                return response;
            }
            catch (HttpRequestException ex)
            {
                lastException = ex;
                
                // Network error - retry with backoff
                if (attempt < MaxRetries - 1)
                {
                    var delay = CalculateBackoff(attempt);
                    await Task.Delay(delay, cancellationToken);
                }
                else
                {
                    throw;
                }
            }
            catch (TaskCanceledException ex)
            {
                lastException = ex;
                
                // Timeout - retry with backoff
                if (attempt < MaxRetries - 1)
                {
                    var delay = CalculateBackoff(attempt);
                    await Task.Delay(delay, cancellationToken);
                }
                else
                {
                    throw;
                }
            }
        }
        
        throw lastException ?? new Exception("Max retries exceeded");
    }
    
    private static TimeSpan CalculateBackoff(int attempt)
    {
        // Exponential backoff with jitter
        var exponential = Math.Pow(2, attempt) * 1000;
        var jitter = _random.Next(0, 1000);
        return TimeSpan.FromMilliseconds(exponential + jitter);
    }
    
    private static TimeSpan GetRetryAfter(HttpResponseMessage response)
    {
        if (response.Headers.RetryAfter?.Delta.HasValue == true)
        {
            return response.Headers.RetryAfter.Delta.Value;
        }
        
        return TimeSpan.FromSeconds(60); // Default to 60 seconds
    }
    
    private static async Task<HttpRequestMessage> CloneRequestAsync(HttpRequestMessage request)
    {
        var clone = new HttpRequestMessage(request.Method, request.RequestUri);
        
        // Copy headers
        foreach (var header in request.Headers)
        {
            clone.Headers.TryAddWithoutValidation(header.Key, header.Value);
        }
        
        // Copy content if present
        if (request.Content != null)
        {
            var originalContent = await request.Content.ReadAsStreamAsync();
            var clonedContent = new StreamContent(originalContent);
            
            foreach (var header in request.Content.Headers)
            {
                clonedContent.Headers.TryAddWithoutValidation(header.Key, header.Value);
            }
            
            clone.Content = clonedContent;
        }
        
        return clone;
    }
    
    public static async Task Main(string[] args)
    {
        using var client = new HttpClient();
        var request = new HttpRequestMessage(HttpMethod.Get, "https://api.example.com/data");
        request.Headers.Authorization = new AuthenticationHeaderValue(
            "Bearer", 
            Environment.GetEnvironmentVariable("API_KEY")
        );
        
        try
        {
            var response = await SendWithRetryAsync(client, request);
            Console.WriteLine($"Success: {response.StatusCode}");
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Request failed: {ex.Message}");
        }
    }
}
```

**Why this is secure**: Exponential backoff with jitter prevents overwhelming struggling services. Retry-After headers are properly parsed and respected. Server errors and network failures trigger retries while client errors do not. Request cloning ensures retry attempts use fresh request objects.

---

## Proper Error Handling

Handle errors gracefully and avoid exposing sensitive information in error messages.

```csharp
using System;
using System.Net;
using System.Net.Http;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;

// Custom exception hierarchy
public class APIException : Exception
{
    public HttpStatusCode? StatusCode { get; }
    
    public APIException(string message, HttpStatusCode? statusCode = null) 
        : base(message)
    {
        StatusCode = statusCode;
    }
    
    public APIException(string message, HttpStatusCode? statusCode, Exception innerException)
        : base(message, innerException)
    {
        StatusCode = statusCode;
    }
}

public class AuthenticationException : APIException
{
    public AuthenticationException(string message) 
        : base(message, HttpStatusCode.Unauthorized) { }
}

public class ServiceUnavailableException : APIException
{
    public ServiceUnavailableException(string message, HttpStatusCode statusCode)
        : base(message, statusCode) { }
}

public class ErrorHandling
{
    private readonly ILogger<ErrorHandling> _logger;
    
    public ErrorHandling(ILogger<ErrorHandling> logger)
    {
        _logger = logger;
    }
    
    public async Task<string> FetchUserDataAsync(
        HttpClient client, 
        string userId, 
        string apiKey)
    {
        try
        {
            var request = new HttpRequestMessage(
                HttpMethod.Get,
                $"https://api.example.com/users/{userId}"
            );
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", apiKey);
            
            var response = await client.SendAsync(request);
            
            // Handle different status codes
            switch (response.StatusCode)
            {
                case HttpStatusCode.OK:
                    return await response.Content.ReadAsStringAsync();
                    
                case HttpStatusCode.NotFound:
                    _logger.LogWarning("User {UserId} not found", userId);
                    throw new APIException("User not found", HttpStatusCode.NotFound);
                    
                case HttpStatusCode.Unauthorized:
                    _logger.LogError("Authentication failed for user {UserId}", userId);
                    throw new AuthenticationException("Invalid credentials");
                    
                case HttpStatusCode.Forbidden:
                    throw new APIException("Access denied", HttpStatusCode.Forbidden);
                    
                default:
                    if ((int)response.StatusCode >= 500)
                    {
                        _logger.LogError(
                            "Server error for user {UserId}: {StatusCode}", 
                            userId, 
                            response.StatusCode
                        );
                        throw new ServiceUnavailableException(
                            "Service temporarily unavailable",
                            response.StatusCode
                        );
                    }
                    
                    _logger.LogWarning(
                        "Request failed for user {UserId}: {StatusCode}",
                        userId,
                        response.StatusCode
                    );
                    throw new APIException("Request failed", response.StatusCode);
            }
        }
        catch (HttpRequestException ex)
        {
            _logger.LogError(ex, "Connection error for user {UserId}", userId);
            throw new APIException("Service unavailable", null, ex);
        }
        catch (TaskCanceledException ex)
        {
            _logger.LogError(ex, "Request timeout for user {UserId}", userId);
            throw new APIException("Request timed out", null, ex);
        }
    }
    
    public static async Task Main(string[] args)
    {
        using var loggerFactory = LoggerFactory.Create(builder => 
            builder.AddConsole());
        var logger = loggerFactory.CreateLogger<ErrorHandling>();
        
        var handler = new ErrorHandling(logger);
        using var client = new HttpClient();
        var apiKey = Environment.GetEnvironmentVariable("API_KEY");
        
        try
        {
            var userData = await handler.FetchUserDataAsync(client, "123", apiKey);
            Console.WriteLine($"User data: {userData}");
        }
        catch (AuthenticationException ex)
        {
            Console.WriteLine($"Authentication error: {ex.Message}");
        }
        catch (ServiceUnavailableException ex)
        {
            Console.WriteLine($"Service error: {ex.Message}");
        }
        catch (APIException ex)
        {
            Console.WriteLine($"API error: {ex.Message} (status: {ex.StatusCode})");
        }
    }
}
```

**Why this is secure**: Detailed errors are logged for debugging using structured logging, but generic messages are thrown to callers. Custom exception hierarchy enables appropriate error handling at different application layers. ILogger integration follows .NET best practices for secure logging.

---

## Input Validation and Sanitization

Validate and sanitize all inputs before including them in API requests.

```csharp
using System;
using System.Net.Http;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using System.Web;

public class InputValidation
{
    private static readonly Regex EmailRegex = new Regex(
        @"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$",
        RegexOptions.Compiled
    );
    
    public static bool ValidateEmail(string email)
    {
        return EmailRegex.IsMatch(email);
    }
    
    public static string SanitizeInput(string input, int maxLength)
    {
        if (input == null)
        {
            throw new ArgumentNullException(nameof(input));
        }
        
        if (input.Length > maxLength)
        {
            throw new ArgumentException($"Input exceeds maximum length of {maxLength}");
        }
        
        // Remove null bytes and trim whitespace
        return input.Replace("\0", string.Empty).Trim();
    }
    
    public static async Task<string> SearchUsersAsync(
        HttpClient client,
        string searchTerm,
        string apiKey)
    {
        // Sanitize input
        var sanitized = SanitizeInput(searchTerm, 50);
        
        // URL encode the search term
        var encoded = HttpUtility.UrlEncode(sanitized);
        
        var request = new HttpRequestMessage(
            HttpMethod.Get,
            $"https://api.example.com/users/search?q={encoded}"
        );
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", apiKey);
        
        var response = await client.SendAsync(request);
        return await response.Content.ReadAsStringAsync();
    }
    
    public static async Task<string> CreateUserAsync(
        HttpClient client,
        string email,
        string name,
        string apiKey)
    {
        // Validate email
        if (!ValidateEmail(email))
        {
            throw new ArgumentException("Invalid email format");
        }
        
        // Sanitize name
        var sanitizedName = SanitizeInput(name, 100);
        
        // Create JSON payload using JsonSerializer (automatic escaping)
        var payload = new
        {
            email = email,
            name = sanitizedName
        };
        
        var jsonContent = JsonSerializer.Serialize(payload);
        var content = new StringContent(jsonContent, Encoding.UTF8, "application/json");
        
        var request = new HttpRequestMessage(HttpMethod.Post, "https://api.example.com/users")
        {
            Content = content
        };
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", apiKey);
        
        var response = await client.SendAsync(request);
        return await response.Content.ReadAsStringAsync();
    }
    
    public static async Task Main(string[] args)
    {
        using var client = new HttpClient();
        var apiKey = Environment.GetEnvironmentVariable("API_KEY");
        
        try
        {
            // Search with validated input
            var results = await SearchUsersAsync(client, "John", apiKey);
            Console.WriteLine($"Search results: {results}");
            
            // Create user with validated input
            var newUser = await CreateUserAsync(client, "john@example.com", "John Doe", apiKey);
            Console.WriteLine($"Created user: {newUser}");
        }
        catch (ArgumentException ex)
        {
            Console.WriteLine($"Validation error: {ex.Message}");
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Request failed: {ex.Message}");
        }
    }
}
```

**Why this is secure**: Input validation prevents injection attacks and malformed requests. HttpUtility.UrlEncode properly handles special characters. System.Text.Json serialization automatically escapes data, preventing injection through manual string concatenation. Compiled regex improves performance for repeated validations.

---

## Secure Logging with Redaction

Log API interactions for troubleshooting while protecting sensitive information.

```csharp
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.Json;
using Microsoft.Extensions.Logging;

public class SecureLogging
{
    private readonly ILogger _logger;
    private static readonly HashSet<string> SensitiveFields = new HashSet<string>(
        StringComparer.OrdinalIgnoreCase)
    {
        "password", "api_key", "apikey", "token", "secret",
        "authorization", "ssn", "credit_card", "cvv", "pin"
    };
    
    public SecureLogging(ILogger logger)
    {
        _logger = logger;
    }
    
    public static Dictionary<string, object> RedactSensitiveData(
        Dictionary<string, object> data)
    {
        if (data == null) return null;
        
        var redacted = new Dictionary<string, object>();
        
        foreach (var kvp in data)
        {
            // Check if field is sensitive
            bool isSensitive = SensitiveFields.Any(field => 
                kvp.Key.Contains(field, StringComparison.OrdinalIgnoreCase));
            
            if (isSensitive)
            {
                redacted[kvp.Key] = "[REDACTED]";
            }
            else if (kvp.Value is Dictionary<string, object> nestedDict)
            {
                redacted[kvp.Key] = RedactSensitiveData(nestedDict);
            }
            else
            {
                redacted[kvp.Key] = kvp.Value;
            }
        }
        
        return redacted;
    }
    
    public static string MaskEmail(string email)
    {
        if (string.IsNullOrEmpty(email) || !email.Contains("@"))
        {
            return "[INVALID_EMAIL]";
        }
        
        var parts = email.Split('@');
        var local = parts[0];
        var domain = parts[1];
        
        string masked;
        if (local.Length <= 2)
        {
            masked = new string('*', local.Length);
        }
        else
        {
            masked = local.Substring(0, 2) + new string('*', local.Length - 2);
        }
        
        return $"{masked}@{domain}";
    }
    
    public void LogAPIRequest(
        string method,
        string url,
        Dictionary<string, string> headers,
        Dictionary<string, object> payload)
    {
        var safeHeaders = new Dictionary<string, string>(headers);
        if (safeHeaders.ContainsKey("Authorization"))
        {
            safeHeaders["Authorization"] = "[REDACTED]";
        }
        
        var safePayload = payload != null ? RedactSensitiveData(payload) : null;
        
        _logger.LogInformation(
            "API Request: {Method} {Url} Headers: {Headers} Payload: {Payload}",
            method,
            url,
            JsonSerializer.Serialize(safeHeaders),
            safePayload != null ? JsonSerializer.Serialize(safePayload) : "null"
        );
    }
    
    public void LogAPIResponse(
        int statusCode,
        long responseTimeMs,
        Dictionary<string, object> payload)
    {
        var safePayload = payload != null ? RedactSensitiveData(payload) : null;
        
        _logger.LogInformation(
            "API Response: {StatusCode} ({ResponseTime}ms) Payload: {Payload}",
            statusCode,
            responseTimeMs,
            safePayload != null ? JsonSerializer.Serialize(safePayload) : "null"
        );
    }
    
    public static void Main(string[] args)
    {
        using var loggerFactory = LoggerFactory.Create(builder => 
            builder.AddConsole());
        var logger = loggerFactory.CreateLogger<SecureLogging>();
        var secureLogger = new SecureLogging(logger);
        
        // Example: Log API request
        var headers = new Dictionary<string, string>
        {
            { "Authorization", "Bearer secret-token" },
            { "Content-Type", "application/json" }
        };
        
        var payload = new Dictionary<string, object>
        {
            { "email", "user@example.com" },
            { "api_key", "super-secret-key" },
            { "name", "John Doe" }
        };
        
        secureLogger.LogAPIRequest("POST", "https://api.example.com/users", headers, payload);
        
        // Example: Log API response
        var responsePayload = new Dictionary<string, object>
        {
            { "id", 123 },
            { "email", "user@example.com" },
            { "token", "response-token" }
        };
        
        secureLogger.LogAPIResponse(200, 150, responsePayload);
        
        // Example: Mask email
        Console.WriteLine($"Masked email: {MaskEmail("john.doe@example.com")}");
    }
}
```

**Why this is secure**: Sensitive fields are automatically identified and redacted using case-insensitive comparison. Structured logging through ILogger enables proper log levels and formatting. Dictionary operations ensure original data is not modified. Email masking balances privacy with debugging needs.

---

## Complete Example: Secure API Client

Here's a complete example combining all best practices:

```csharp
using System;
using System.Collections.Generic;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;

public class CompleteSecureAPIClient
{
    private readonly HttpClient _client;
    private readonly string _baseUrl;
    private readonly string _apiKey;
    private readonly ILogger _logger;
    private const int MaxRetries = 3;
    private static readonly Random _random = new Random();
    
    public CompleteSecureAPIClient(string baseUrl, ILogger logger)
    {
        _apiKey = Environment.GetEnvironmentVariable("API_KEY");
        if (string.IsNullOrEmpty(_apiKey))
        {
            throw new InvalidOperationException("API_KEY environment variable not set");
        }
        
        _baseUrl = baseUrl;
        _logger = logger;
        
        var handler = new HttpClientHandler
        {
            SslProtocols = System.Security.Authentication.SslProtocols.Tls12 |
                          System.Security.Authentication.SslProtocols.Tls13
        };
        
        _client = new HttpClient(handler)
        {
            BaseAddress = new Uri(baseUrl),
            Timeout = TimeSpan.FromSeconds(10)
        };
        
        _client.DefaultRequestHeaders.Authorization = 
            new AuthenticationHeaderValue("Bearer", _apiKey);
    }
    
    private async Task<HttpResponseMessage> DoRequestAsync(
        HttpMethod method,
        string path,
        object body = null)
    {
        for (int attempt = 0; attempt < MaxRetries; attempt++)
        {
            try
            {
                var request = new HttpRequestMessage(method, path);
                
                if (body != null)
                {
                    var json = JsonSerializer.Serialize(body);
                    request.Content = new StringContent(json, Encoding.UTF8, "application/json");
                }
                
                var startTime = DateTime.UtcNow;
                var response = await _client.SendAsync(request);
                var elapsed = (DateTime.UtcNow - startTime).TotalMilliseconds;
                
                _logger.LogInformation(
                    "Response: {StatusCode} ({ElapsedMs}ms)",
                    (int)response.StatusCode,
                    elapsed
                );
                
                if (response.IsSuccessStatusCode)
                {
                    return response;
                }
                
                if ((int)response.StatusCode >= 500 && attempt < MaxRetries - 1)
                {
                    var delay = CalculateBackoff(attempt);
                    await Task.Delay(delay);
                    continue;
                }
                
                return response;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Request attempt {Attempt} failed", attempt + 1);
                
                if (attempt < MaxRetries - 1)
                {
                    var delay = CalculateBackoff(attempt);
                    await Task.Delay(delay);
                }
                else
                {
                    throw;
                }
            }
        }
        
        throw new Exception("Max retries exceeded");
    }
    
    private TimeSpan CalculateBackoff(int attempt)
    {
        var exponential = Math.Pow(2, attempt) * 1000;
        var jitter = _random.Next(0, 1000);
        return TimeSpan.FromMilliseconds(exponential + jitter);
    }
    
    public async Task<string> GetAsync(string path)
    {
        var response = await DoRequestAsync(HttpMethod.Get, path);
        return await response.Content.ReadAsStringAsync();
    }
    
    public async Task<string> PostAsync(string path, object data)
    {
        var response = await DoRequestAsync(HttpMethod.Post, path, data);
        return await response.Content.ReadAsStringAsync();
    }
    
    public static async Task Main(string[] args)
    {
        using var loggerFactory = LoggerFactory.Create(builder => builder.AddConsole());
        var logger = loggerFactory.CreateLogger<CompleteSecureAPIClient>();
        
        try
        {
            var client = new CompleteSecureAPIClient("https://api.example.com", logger);
            
            // Example GET request
            var user = await client.GetAsync("/users/123");
            Console.WriteLine($"User: {user}");
            
            // Example POST request
            var newUser = new { name = "John Doe", email = "john@example.com" };
            var created = await client.PostAsync("/users", newUser);
            Console.WriteLine($"Created: {created}");
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Error: {ex.Message}");
        }
    }
}
```

**Why this is secure**: This client combines all security best practices: environment-based credential management, TLS 1.2/1.3 enforcement, automatic retry logic with exponential backoff and jitter, structured logging through ILogger, and proper async/await patterns. The HttpClient is properly configured and reused for connection pooling efficiency.