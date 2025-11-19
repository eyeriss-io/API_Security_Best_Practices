# Java API Security Examples

This document provides practical Java examples demonstrating secure API consumption patterns using modern Java features and libraries.

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

```java
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.net.URI;
import java.time.Duration;

public class SecureAPIClient {
    private final HttpClient client;
    private final String apiKey;
    private final String baseURL;
    
    public SecureAPIClient(String baseURL) {
        // Retrieve API key from environment variable
        this.apiKey = System.getenv("API_KEY");
        if (this.apiKey == null || this.apiKey.isEmpty()) {
            throw new IllegalStateException("API_KEY environment variable not set");
        }
        
        this.baseURL = baseURL;
        this.client = HttpClient.newBuilder()
            .connectTimeout(Duration.ofSeconds(10))
            .build();
    }
    
    public HttpRequest createAuthenticatedRequest(String path) {
        return HttpRequest.newBuilder()
            .uri(URI.create(baseURL + path))
            .header("Authorization", "Bearer " + apiKey)
            .header("Content-Type", "application/json")
            .timeout(Duration.ofSeconds(10))
            .GET()
            .build();
    }
    
    public String fetchData() throws Exception {
        HttpRequest request = createAuthenticatedRequest("/data");
        HttpResponse<String> response = client.send(
            request,
            HttpResponse.BodyHandlers.ofString()
        );
        
        return response.body();
    }
    
    public static void main(String[] args) {
        try {
            SecureAPIClient client = new SecureAPIClient("https://api.example.com");
            String data = client.fetchData();
            System.out.println(data);
        } catch (Exception e) {
            System.err.println("Error: " + e.getMessage());
        }
    }
}
```

**Why this approach is secure**: Credentials are retrieved from environment variables and never hardcoded. The application fails immediately with a clear error if credentials are missing. HttpClient is configured with appropriate timeouts to prevent indefinite hangs.

---

## HTTPS Communication with Certificate Validation

Always use HTTPS and verify SSL certificates to prevent man-in-the-middle attacks.

```java
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManagerFactory;
import java.io.FileInputStream;
import java.net.http.HttpClient;
import java.security.KeyStore;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.time.Duration;

public class SecureHTTPClient {
    
    // Create HTTP client with default secure settings
    public static HttpClient createSecureClient() {
        return HttpClient.newBuilder()
            .connectTimeout(Duration.ofSeconds(10))
            .version(HttpClient.Version.HTTP_2) // Prefers HTTP/2, falls back to HTTP/1.1
            // Certificate validation is enabled by default
            .build();
    }
    
    // Create client with custom CA certificate
    public static HttpClient createClientWithCustomCA(String caFilePath) throws Exception {
        // Load the CA certificate
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        FileInputStream fis = new FileInputStream(caFilePath);
        X509Certificate caCert = (X509Certificate) cf.generateCertificate(fis);
        fis.close();
        
        // Create a KeyStore containing the trusted CA
        KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
        keyStore.load(null, null);
        keyStore.setCertificateEntry("ca", caCert);
        
        // Create a TrustManager that trusts the CA in our KeyStore
        TrustManagerFactory tmf = TrustManagerFactory.getInstance(
            TrustManagerFactory.getDefaultAlgorithm()
        );
        tmf.init(keyStore);
        
        // Create an SSLContext that uses our TrustManager
        SSLContext sslContext = SSLContext.getInstance("TLS");
        sslContext.init(null, tmf.getTrustManagers(), null);
        
        return HttpClient.newBuilder()
            .connectTimeout(Duration.ofSeconds(10))
            .sslContext(sslContext)
            .build();
    }
    
    public static void main(String[] args) throws Exception {
        // Use default secure client
        HttpClient client = createSecureClient();
        
        HttpRequest request = HttpRequest.newBuilder()
            .uri(URI.create("https://api.example.com/data"))
            .GET()
            .build();
        
        HttpResponse<String> response = client.send(
            request,
            HttpResponse.BodyHandlers.ofString()
        );
        
        System.out.println("Response: " + response.body());
    }
}
```

**Why this is secure**: Certificate validation is enabled by default in Java's HttpClient. The examples show how to configure custom CA certificates while maintaining validation. TLS version negotiation prefers modern protocols while remaining compatible with TLS 1.2+.

---

## Retry Logic with Exponential Backoff

Implement intelligent retry logic for transient failures with exponential backoff and jitter.

```java
import java.net.http.*;
import java.net.URI;
import java.time.Duration;
import java.util.Random;

public class RetryLogic {
    private static final int MAX_RETRIES = 3;
    private static final Random random = new Random();
    
    public static HttpResponse<String> sendWithRetry(
        HttpClient client,
        HttpRequest request
    ) throws Exception {
        Exception lastException = null;
        
        for (int attempt = 0; attempt < MAX_RETRIES; attempt++) {
            try {
                HttpResponse<String> response = client.send(
                    request,
                    HttpResponse.BodyHandlers.ofString()
                );
                
                // Success
                if (response.statusCode() == 200) {
                    return response;
                }
                
                // Rate limited - respect Retry-After header
                if (response.statusCode() == 429) {
                    if (attempt < MAX_RETRIES - 1) {
                        int retryAfter = getRetryAfter(response);
                        Thread.sleep(retryAfter * 1000L);
                        continue;
                    }
                }
                
                // Server error - retry with backoff
                if (response.statusCode() >= 500) {
                    if (attempt < MAX_RETRIES - 1) {
                        long waitTime = calculateBackoff(attempt);
                        Thread.sleep(waitTime);
                        continue;
                    }
                }
                
                // Client error or final attempt - return response
                return response;
                
            } catch (Exception e) {
                lastException = e;
                
                // Network error - retry with backoff
                if (attempt < MAX_RETRIES - 1) {
                    long waitTime = calculateBackoff(attempt);
                    Thread.sleep(waitTime);
                } else {
                    throw e;
                }
            }
        }
        
        throw lastException != null ? lastException : 
            new Exception("Max retries exceeded");
    }
    
    private static long calculateBackoff(int attempt) {
        // Exponential backoff with jitter
        long exponential = (long) Math.pow(2, attempt) * 1000;
        long jitter = random.nextInt(1000);
        return exponential + jitter;
    }
    
    private static int getRetryAfter(HttpResponse<String> response) {
        return response.headers()
            .firstValue("Retry-After")
            .map(Integer::parseInt)
            .orElse(60); // Default to 60 seconds
    }
    
    public static void main(String[] args) {
        try {
            HttpClient client = HttpClient.newHttpClient();
            HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create("https://api.example.com/data"))
                .header("Authorization", "Bearer " + System.getenv("API_KEY"))
                .GET()
                .build();
            
            HttpResponse<String> response = sendWithRetry(client, request);
            System.out.println("Success: " + response.statusCode());
        } catch (Exception e) {
            System.err.println("Request failed: " + e.getMessage());
        }
    }
}
```

**Why this is secure**: Exponential backoff with jitter prevents overwhelming struggling services. Retry-After headers are respected for rate limits. Server errors and network failures trigger retries while client errors do not. The randomized jitter prevents thundering herd problems.

---

## Proper Error Handling

Handle errors gracefully and avoid exposing sensitive information in error messages.

```java
import java.net.http.*;
import java.net.URI;
import java.util.logging.Logger;
import java.util.logging.Level;

// Custom exception hierarchy
class APIException extends Exception {
    private final int statusCode;
    
    public APIException(String message, int statusCode) {
        super(message);
        this.statusCode = statusCode;
    }
    
    public APIException(String message, int statusCode, Throwable cause) {
        super(message, cause);
        this.statusCode = statusCode;
    }
    
    public int getStatusCode() {
        return statusCode;
    }
}

class AuthenticationException extends APIException {
    public AuthenticationException(String message) {
        super(message, 401);
    }
}

class ServiceUnavailableException extends APIException {
    public ServiceUnavailableException(String message, int statusCode) {
        super(message, statusCode);
    }
}

public class ErrorHandling {
    private static final Logger logger = Logger.getLogger(ErrorHandling.class.getName());
    
    public static String fetchUserData(HttpClient client, String userId, String apiKey) 
        throws APIException {
        
        try {
            HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create("https://api.example.com/users/" + userId))
                .header("Authorization", "Bearer " + apiKey)
                .timeout(Duration.ofSeconds(10))
                .GET()
                .build();
            
            HttpResponse<String> response = client.send(
                request,
                HttpResponse.BodyHandlers.ofString()
            );
            
            // Handle different status codes
            switch (response.statusCode()) {
                case 200:
                    return response.body();
                    
                case 404:
                    logger.warning("User " + userId + " not found");
                    throw new APIException("User not found", 404);
                    
                case 401:
                    logger.severe("Authentication failed for user " + userId);
                    throw new AuthenticationException("Invalid credentials");
                    
                case 403:
                    throw new APIException("Access denied", 403);
                    
                default:
                    if (response.statusCode() >= 500) {
                        logger.severe("Server error for user " + userId + ": " + 
                            response.statusCode());
                        throw new ServiceUnavailableException(
                            "Service temporarily unavailable",
                            response.statusCode()
                        );
                    }
                    
                    logger.warning("Request failed for user " + userId + ": " + 
                        response.statusCode());
                    throw new APIException("Request failed", response.statusCode());
            }
            
        } catch (java.net.http.HttpTimeoutException e) {
            logger.log(Level.SEVERE, "Request timeout for user " + userId, e);
            throw new APIException("Request timed out", 0, e);
            
        } catch (java.io.IOException e) {
            logger.log(Level.SEVERE, "Connection error for user " + userId, e);
            throw new APIException("Service unavailable", 0, e);
            
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new APIException("Request interrupted", 0, e);
        }
    }
    
    public static void main(String[] args) {
        HttpClient client = HttpClient.newHttpClient();
        String apiKey = System.getenv("API_KEY");
        
        try {
            String userData = fetchUserData(client, "123", apiKey);
            System.out.println("User data: " + userData);
        } catch (AuthenticationException e) {
            System.err.println("Authentication error: " + e.getMessage());
        } catch (ServiceUnavailableException e) {
            System.err.println("Service error: " + e.getMessage());
        } catch (APIException e) {
            System.err.println("API error: " + e.getMessage() + 
                " (status: " + e.getStatusCode() + ")");
        }
    }
}
```

**Why this is secure**: Detailed errors are logged for debugging but generic messages are thrown to callers. Custom exception hierarchy enables appropriate error handling at different application layers. Sensitive information is never included in exception messages visible to end users.

---

## Input Validation and Sanitization

Validate and sanitize all inputs before including them in API requests.

```java
import java.net.URLEncoder;
import java.net.http.*;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.regex.Pattern;
import com.google.gson.Gson;
import com.google.gson.JsonObject;

public class InputValidation {
    private static final Pattern EMAIL_PATTERN = Pattern.compile(
        "^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}$"
    );
    private static final Gson gson = new Gson();
    
    public static boolean validateEmail(String email) {
        return EMAIL_PATTERN.matcher(email).matches();
    }
    
    public static String sanitizeInput(String input, int maxLength) 
        throws IllegalArgumentException {
        
        if (input == null) {
            throw new IllegalArgumentException("Input cannot be null");
        }
        
        if (input.length() > maxLength) {
            throw new IllegalArgumentException(
                "Input exceeds maximum length of " + maxLength
            );
        }
        
        // Remove null bytes and trim whitespace
        return input.replace("\0", "").trim();
    }
    
    public static String searchUsers(HttpClient client, String searchTerm, String apiKey) 
        throws Exception {
        
        // Sanitize input
        String sanitized = sanitizeInput(searchTerm, 50);
        
        // URL encode the search term
        String encoded = URLEncoder.encode(sanitized, StandardCharsets.UTF_8);
        
        HttpRequest request = HttpRequest.newBuilder()
            .uri(URI.create("https://api.example.com/users/search?q=" + encoded))
            .header("Authorization", "Bearer " + apiKey)
            .GET()
            .build();
        
        HttpResponse<String> response = client.send(
            request,
            HttpResponse.BodyHandlers.ofString()
        );
        
        return response.body();
    }
    
    public static String createUser(HttpClient client, String email, String name, String apiKey) 
        throws Exception {
        
        // Validate email
        if (!validateEmail(email)) {
            throw new IllegalArgumentException("Invalid email format");
        }
        
        // Sanitize name
        String sanitizedName = sanitizeInput(name, 100);
        
        // Create JSON payload using Gson (automatic escaping)
        JsonObject payload = new JsonObject();
        payload.addProperty("email", email);
        payload.addProperty("name", sanitizedName);
        
        String jsonPayload = gson.toJson(payload);
        
        HttpRequest request = HttpRequest.newBuilder()
            .uri(URI.create("https://api.example.com/users"))
            .header("Authorization", "Bearer " + apiKey)
            .header("Content-Type", "application/json")
            .POST(HttpRequest.BodyPublishers.ofString(jsonPayload))
            .build();
        
        HttpResponse<String> response = client.send(
            request,
            HttpResponse.BodyHandlers.ofString()
        );
        
        return response.body();
    }
    
    public static void main(String[] args) {
        try {
            HttpClient client = HttpClient.newHttpClient();
            String apiKey = System.getenv("API_KEY");
            
            // Search with validated input
            String results = searchUsers(client, "John", apiKey);
            System.out.println("Search results: " + results);
            
            // Create user with validated input
            String newUser = createUser(client, "john@example.com", "John Doe", apiKey);
            System.out.println("Created user: " + newUser);
            
        } catch (IllegalArgumentException e) {
            System.err.println("Validation error: " + e.getMessage());
        } catch (Exception e) {
            System.err.println("Request failed: " + e.getMessage());
        }
    }
}
```

**Why this is secure**: Input validation prevents injection attacks and malformed requests. URLEncoder properly handles special characters in query parameters. Using Gson for JSON serialization prevents injection through manual string concatenation. Type-safe validation occurs before any API calls.

---

## Secure Logging with Redaction

Log API interactions for troubleshooting while protecting sensitive information.

```java
import java.util.*;
import java.util.logging.*;
import java.time.Instant;
import com.google.gson.Gson;
import com.google.gson.GsonBuilder;

public class SecureLogging {
    private static final Logger logger = Logger.getLogger(SecureLogging.class.getName());
    private static final Gson gson = new GsonBuilder().setPrettyPrinting().create();
    
    private static final Set<String> SENSITIVE_FIELDS = new HashSet<>(Arrays.asList(
        "password", "api_key", "apikey", "token", "secret",
        "authorization", "ssn", "credit_card", "cvv", "pin"
    ));
    
    public static Map<String, Object> redactSensitiveData(Map<String, Object> data) {
        if (data == null) {
            return null;
        }
        
        Map<String, Object> redacted = new HashMap<>();
        
        for (Map.Entry<String, Object> entry : data.entrySet()) {
            String key = entry.getKey();
            Object value = entry.getValue();
            
            // Check if field is sensitive
            boolean isSensitive = SENSITIVE_FIELDS.stream()
                .anyMatch(field -> key.toLowerCase().contains(field));
            
            if (isSensitive) {
                redacted.put(key, "[REDACTED]");
            } else if (value instanceof Map) {
                @SuppressWarnings("unchecked")
                Map<String, Object> nestedMap = (Map<String, Object>) value;
                redacted.put(key, redactSensitiveData(nestedMap));
            } else {
                redacted.put(key, value);
            }
        }
        
        return redacted;
    }
    
    public static String maskEmail(String email) {
        if (email == null || !email.contains("@")) {
            return "[INVALID_EMAIL]";
        }
        
        String[] parts = email.split("@");
        String local = parts[0];
        String domain = parts[1];
        
        String masked;
        if (local.length() <= 2) {
            masked = "*".repeat(local.length());
        } else {
            masked = local.substring(0, 2) + "*".repeat(local.length() - 2);
        }
        
        return masked + "@" + domain;
    }
    
    public static void logAPIRequest(
        String method,
        String url,
        Map<String, String> headers,
        Map<String, Object> payload
    ) {
        Map<String, Object> logData = new HashMap<>();
        logData.put("timestamp", Instant.now().toString());
        logData.put("type", "request");
        logData.put("method", method);
        logData.put("url", url);
        
        // Redact authorization headers
        Map<String, String> safeHeaders = new HashMap<>(headers);
        if (safeHeaders.containsKey("Authorization")) {
            safeHeaders.put("Authorization", "[REDACTED]");
        }
        logData.put("headers", safeHeaders);
        
        // Redact sensitive payload data
        if (payload != null) {
            logData.put("payload", redactSensitiveData(payload));
        }
        
        logger.info(gson.toJson(logData));
    }
    
    public static void logAPIResponse(
        int statusCode,
        long responseTimeMs,
        Map<String, Object> payload
    ) {
        Map<String, Object> logData = new HashMap<>();
        logData.put("timestamp", Instant.now().toString());
        logData.put("type", "response");
        logData.put("status_code", statusCode);
        logData.put("response_time_ms", responseTimeMs);
        
        // Redact sensitive response data
        if (payload != null) {
            logData.put("payload", redactSensitiveData(payload));
        }
        
        logger.info(gson.toJson(logData));
    }
    
    public static void main(String[] args) {
        // Example: Log API request
        Map<String, String> headers = new HashMap<>();
        headers.put("Authorization", "Bearer secret-token");
        headers.put("Content-Type", "application/json");
        
        Map<String, Object> payload = new HashMap<>();
        payload.put("email", "user@example.com");
        payload.put("api_key", "super-secret-key");
        payload.put("name", "John Doe");
        
        logAPIRequest("POST", "https://api.example.com/users", headers, payload);
        
        // Example: Log API response
        Map<String, Object> responsePayload = new HashMap<>();
        responsePayload.put("id", 123);
        responsePayload.put("email", "user@example.com");
        responsePayload.put("token", "response-token");
        
        logAPIResponse(200, 150, responsePayload);
        
        // Example: Mask email
        System.out.println("Masked email: " + maskEmail("john.doe@example.com"));
    }
}
```

**Why this is secure**: Sensitive fields are automatically identified and redacted based on field names. Structured JSON logging enables easy parsing and analysis. Deep copying through map operations prevents modification of original data. Email masking provides a balance between privacy and debugging capabilities.

---

## Complete Example: Secure API Client

Here's a complete example combining all best practices:

```java
import java.net.http.*;
import java.net.URI;
import java.time.Duration;
import java.util.*;
import java.util.logging.Logger;
import com.google.gson.Gson;

public class CompleteSecureAPIClient {
    private final HttpClient client;
    private final String baseURL;
    private final String apiKey;
    private final Logger logger;
    private final Gson gson;
    private static final int MAX_RETRIES = 3;
    private static final Random random = new Random();
    
    public CompleteSecureAPIClient(String baseURL) {
        this.apiKey = System.getenv("API_KEY");
        if (this.apiKey == null || this.apiKey.isEmpty()) {
            throw new IllegalStateException("API_KEY environment variable not set");
        }
        
        this.baseURL = baseURL;
        this.client = HttpClient.newBuilder()
            .connectTimeout(Duration.ofSeconds(10))
            .build();
        this.logger = Logger.getLogger(getClass().getName());
        this.gson = new Gson();
    }
    
    private HttpResponse<String> doRequest(String method, String path, Object body) 
        throws Exception {
        
        for (int attempt = 0; attempt < MAX_RETRIES; attempt++) {
            HttpRequest.Builder requestBuilder = HttpRequest.newBuilder()
                .uri(URI.create(baseURL + path))
                .header("Authorization", "Bearer " + apiKey)
                .header("Content-Type", "application/json")
                .timeout(Duration.ofSeconds(10));
            
            if (body != null) {
                String jsonBody = gson.toJson(body);
                requestBuilder.method(method, HttpRequest.BodyPublishers.ofString(jsonBody));
            } else {
                requestBuilder.method(method, HttpRequest.BodyPublishers.noBody());
            }
            
            HttpRequest request = requestBuilder.build();
            long startTime = System.currentTimeMillis();
            
            try {
                HttpResponse<String> response = client.send(
                    request,
                    HttpResponse.BodyHandlers.ofString()
                );
                
                long responseTime = System.currentTimeMillis() - startTime;
                logger.info("Response: " + response.statusCode() + " (" + responseTime + "ms)");
                
                if (response.statusCode() == 200) {
                    return response;
                }
                
                if (response.statusCode() >= 500 && attempt < MAX_RETRIES - 1) {
                    long waitTime = calculateBackoff(attempt);
                    Thread.sleep(waitTime);
                    continue;
                }
                
                return response;
                
            } catch (Exception e) {
                if (attempt < MAX_RETRIES - 1) {
                    long waitTime = calculateBackoff(attempt);
                    Thread.sleep(waitTime);
                } else {
                    throw e;
                }
            }
        }
        
        throw new Exception("Max retries exceeded");
    }
    
    private long calculateBackoff(int attempt) {
        long exponential = (long) Math.pow(2, attempt) * 1000;
        long jitter = random.nextInt(1000);
        return exponential + jitter;
    }
    
    public String get(String path) throws Exception {
        HttpResponse<String> response = doRequest("GET", path, null);
        return response.body();
    }
    
    public String post(String path, Object data) throws Exception {
        HttpResponse<String> response = doRequest("POST", path, data);
        return response.body();
    }
    
    public static void main(String[] args) {
        try {
            CompleteSecureAPIClient client = new CompleteSecureAPIClient(
                "https://api.example.com"
            );
            
            // Example GET request
            String user = client.get("/users/123");
            System.out.println("User: " + user);
            
            // Example POST request
            Map<String, String> newUser = new HashMap<>();
            newUser.put("name", "John Doe");
            newUser.put("email", "john@example.com");
            
            String created = client.post("/users", newUser);
            System.out.println("Created: " + created);
            
        } catch (Exception e) {
            System.err.println("Error: " + e.getMessage());
        }
    }
}
```

**Why this is secure**: This client combines all security best practices: environment-based credential management, certificate validation with appropriate timeouts, automatic retry logic with exponential backoff and jitter, structured logging, and proper error handling. Java's type safety and exception handling make security issues visible at compile time.