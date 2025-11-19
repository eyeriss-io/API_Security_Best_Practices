# Rust API Security Examples

This document provides practical Rust examples demonstrating secure API consumption patterns using modern Rust features and libraries.

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

```rust
use reqwest::{Client, header};
use std::env;
use std::time::Duration;

pub struct SecureAPIClient {
    client: Client,
    api_key: String,
    base_url: String,
}

impl SecureAPIClient {
    pub fn new(base_url: String) -> Result<Self, Box<dyn std::error::Error>> {
        // Retrieve API key from environment variable
        let api_key = env::var("API_KEY")
            .map_err(|_| "API_KEY environment variable not set")?;
        
        let client = Client::builder()
            .timeout(Duration::from_secs(10))
            .build()?;
        
        Ok(Self {
            client,
            api_key,
            base_url,
        })
    }
    
    fn create_headers(&self) -> header::HeaderMap {
        let mut headers = header::HeaderMap::new();
        headers.insert(
            header::AUTHORIZATION,
            header::HeaderValue::from_str(&format!("Bearer {}", self.api_key))
                .expect("Invalid API key"),
        );
        headers.insert(
            header::CONTENT_TYPE,
            header::HeaderValue::from_static("application/json"),
        );
        headers
    }
    
    pub async fn fetch_data(&self) -> Result<String, Box<dyn std::error::Error>> {
        let url = format!("{}/data", self.base_url);
        let response = self.client
            .get(&url)
            .headers(self.create_headers())
            .send()
            .await?;
        
        let body = response.text().await?;
        Ok(body)
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let client = SecureAPIClient::new("https://api.example.com".to_string())?;
    let data = client.fetch_data().await?;
    println!("{}", data);
    Ok(())
}
```

**Why this is secure**: Credentials are retrieved from environment variables using env::var and never hardcoded. The application returns an error immediately if credentials are missing. The reqwest client is configured with appropriate timeouts using Rust's Duration type.

---

## HTTPS Communication with Certificate Validation

Always use HTTPS and verify SSL certificates to prevent man-in-the-middle attacks.

```rust
use reqwest::{Client, Certificate};
use std::fs;
use std::time::Duration;

pub struct SecureHTTPClient;

impl SecureHTTPClient {
    // Create client with default secure settings
    pub fn create_secure_client() -> Result<Client, Box<dyn std::error::Error>> {
        let client = Client::builder()
            .timeout(Duration::from_secs(10))
            // Certificate validation is enabled by default
            .https_only(true)
            // Enforce modern TLS versions (TLS 1.2+)
            .min_tls_version(reqwest::tls::Version::TLS_1_2)
            .build()?;
        
        Ok(client)
    }
    
    // Create client with custom CA certificate
    pub fn create_client_with_custom_ca(
        ca_file_path: &str
    ) -> Result<Client, Box<dyn std::error::Error>> {
        // Load CA certificate
        let ca_cert_bytes = fs::read(ca_file_path)?;
        let ca_cert = Certificate::from_pem(&ca_cert_bytes)?;
        
        let client = Client::builder()
            .timeout(Duration::from_secs(10))
            .add_root_certificate(ca_cert)
            .https_only(true)
            .min_tls_version(reqwest::tls::Version::TLS_1_2)
            .build()?;
        
        Ok(client)
    }
    
    pub async fn make_request(url: &str) -> Result<String, Box<dyn std::error::Error>> {
        let client = Self::create_secure_client()?;
        let response = client.get(url).send().await?;
        let body = response.text().await?;
        Ok(body)
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let response = SecureHTTPClient::make_request("https://api.example.com/data").await?;
    println!("Response: {}", response);
    Ok(())
}
```

**Why this is secure**: Certificate validation is enabled by default in reqwest. HTTPS-only mode is enforced explicitly. Minimum TLS version is set to TLS 1.2. Custom CA certificates can be loaded for internal APIs while maintaining validation. Rust's type system ensures proper error handling.

---

## Retry Logic with Exponential Backoff

Implement intelligent retry logic for transient failures with exponential backoff and jitter.

```rust
use reqwest::{Client, Response, StatusCode};
use std::time::Duration;
use tokio::time::sleep;
use rand::Rng;
use anyhow::{Context, Result};

const MAX_RETRIES: u32 = 3;

pub async fn send_with_retry(
    client: &Client,
    url: &str,
    headers: reqwest::header::HeaderMap,
) -> Result<Response> {
    let mut last_error = None;
    
    for attempt in 0..MAX_RETRIES {
        match client.get(url).headers(headers.clone()).send().await {
            Ok(response) => {
                // Success
                if response.status().is_success() {
                    return Ok(response);
                }
                
                // Rate limited - respect Retry-After header
                if response.status() == StatusCode::TOO_MANY_REQUESTS {
                    if attempt < MAX_RETRIES - 1 {
                        let retry_after = get_retry_after(&response);
                        sleep(Duration::from_secs(retry_after)).await;
                        continue;
                    }
                }
                
                // Server error - retry with backoff
                if response.status().is_server_error() {
                    if attempt < MAX_RETRIES - 1 {
                        let wait_time = calculate_backoff(attempt);
                        sleep(wait_time).await;
                        continue;
                    }
                }
                
                // Client error or final attempt
                return Ok(response);
            }
            Err(e) => {
                last_error = Some(e);
                
                // Network error - retry with backoff
                if attempt < MAX_RETRIES - 1 {
                    let wait_time = calculate_backoff(attempt);
                    sleep(wait_time).await;
                } else {
                    return Err(anyhow::anyhow!(last_error.unwrap()))
                        .context("All retry attempts failed");
                }
            }
        }
    }
    
    anyhow::bail!("Max retries exceeded")
}

fn calculate_backoff(attempt: u32) -> Duration {
    // Exponential backoff with jitter
    let mut rng = rand::thread_rng();
    let exponential = 2_u64.pow(attempt);
    let jitter = rng.gen_range(0..1000);
    Duration::from_millis(exponential * 1000 + jitter)
}

fn get_retry_after(response: &Response) -> u64 {
    response
        .headers()
        .get("Retry-After")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.parse::<u64>().ok())
        .unwrap_or(60) // Default to 60 seconds
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let client = Client::new();
    let api_key = std::env::var("API_KEY")?;
    
    let mut headers = reqwest::header::HeaderMap::new();
    headers.insert(
        reqwest::header::AUTHORIZATION,
        reqwest::header::HeaderValue::from_str(&format!("Bearer {}", api_key))?,
    );
    
    let response = send_with_retry(&client, "https://api.example.com/data", headers).await?;
    println!("Success: {}", response.status());
    Ok(())
}
```

**Why this approach is secure**: Exponential backoff with jitter prevents overwhelming struggling services. Retry-After headers are properly parsed and respected. Server errors and network failures trigger retries while client errors do not. Rust's ownership system prevents data races in retry logic. Using anyhow provides better error context and chaining.

---

## Proper Error Handling

Handle errors gracefully and avoid exposing sensitive information in error messages.

```rust
use reqwest::{Client, StatusCode};
use thiserror::Error;
use log::{error, warn};

// Custom error types using thiserror
#[derive(Error, Debug)]
pub enum APIError {
    #[error("User not found")]
    NotFound,
    
    #[error("Invalid credentials")]
    Authentication,
    
    #[error("Access denied")]
    Forbidden,
    
    #[error("Service temporarily unavailable")]
    ServiceUnavailable(StatusCode),
    
    #[error("Request failed")]
    RequestFailed(StatusCode),
    
    #[error("Request timed out")]
    Timeout,
    
    #[error("Service unavailable")]
    ConnectionError,
    
    #[error(transparent)]
    Other(#[from] Box<dyn std::error::Error>),
}

pub struct ErrorHandling {
    client: Client,
}

impl ErrorHandling {
    pub fn new() -> Self {
        Self {
            client: Client::builder()
                .timeout(std::time::Duration::from_secs(10))
                .build()
                .expect("Failed to create HTTP client"),
        }
    }
    
    pub async fn fetch_user_data(
        &self,
        user_id: &str,
        api_key: &str,
    ) -> Result<String, APIError> {
        let url = format!("https://api.example.com/users/{}", user_id);
        
        let response = self.client
            .get(&url)
            .header("Authorization", format!("Bearer {}", api_key))
            .send()
            .await
            .map_err(|e| {
                if e.is_timeout() {
                    error!("Request timeout for user {}", user_id);
                    APIError::Timeout
                } else if e.is_connect() {
                    error!("Connection error for user {}: {:?}", user_id, e);
                    APIError::ConnectionError
                } else {
                    error!("Request error for user {}: {:?}", user_id, e);
                    APIError::Other(Box::new(e))
                }
            })?;
        
        // Handle different status codes
        match response.status() {
            StatusCode::OK => {
                let body = response.text().await
                    .map_err(|e| APIError::Other(Box::new(e)))?;
                Ok(body)
            }
            StatusCode::NOT_FOUND => {
                warn!("User {} not found", user_id);
                Err(APIError::NotFound)
            }
            StatusCode::UNAUTHORIZED => {
                error!("Authentication failed for user {}", user_id);
                Err(APIError::Authentication)
            }
            StatusCode::FORBIDDEN => {
                Err(APIError::Forbidden)
            }
            status if status.is_server_error() => {
                error!("Server error for user {}: {}", user_id, status);
                Err(APIError::ServiceUnavailable(status))
            }
            status => {
                warn!("Request failed for user {}: {}", user_id, status);
                Err(APIError::RequestFailed(status))
            }
        }
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::init();
    
    let handler = ErrorHandling::new();
    let api_key = std::env::var("API_KEY")?;
    
    match handler.fetch_user_data("123", &api_key).await {
        Ok(user_data) => println!("User data: {}", user_data),
        Err(APIError::Authentication) => {
            eprintln!("Authentication error: Invalid credentials");
        }
        Err(APIError::ServiceUnavailable(status)) => {
            eprintln!("Service error: temporarily unavailable (status: {})", status);
        }
        Err(e) => {
            eprintln!("API error: {}", e);
        }
    }
    
    Ok(())
}
```

**Why this is secure**: Custom error types using thiserror provide type-safe error handling. Detailed errors are logged using the log crate but generic messages are returned to callers. Rust's Result type forces explicit error handling at every call site. Pattern matching ensures all error cases are handled.

---

## Input Validation and Sanitization

Validate and sanitize all inputs before including them in API requests.

```rust
use regex::Regex;
use reqwest::Client;
use serde_json::json;
use urlencoding::encode;

lazy_static::lazy_static! {
    static ref EMAIL_REGEX: Regex = Regex::new(
        r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"
    ).unwrap();
}

pub fn validate_email(email: &str) -> bool {
    EMAIL_REGEX.is_match(email)
}

pub fn sanitize_input(input: &str, max_length: usize) -> Result<String, String> {
    if input.len() > max_length {
        return Err(format!("Input exceeds maximum length of {}", max_length));
    }
    
    // Remove null bytes and trim whitespace
    let sanitized = input.replace('\0', "").trim().to_string();
    Ok(sanitized)
}

pub async fn search_users(
    client: &Client,
    search_term: &str,
    api_key: &str,
) -> Result<String, Box<dyn std::error::Error>> {
    // Sanitize input
    let sanitized = sanitize_input(search_term, 50)?;
    
    // URL encode query parameter
    let encoded = encode(&sanitized);
    
    let url = format!("https://api.example.com/users/search?q={}", encoded);
    
    let response = client
        .get(&url)
        .header("Authorization", format!("Bearer {}", api_key))
        .send()
        .await?;
    
    let body = response.text().await?;
    Ok(body)
}

pub async fn create_user(
    client: &Client,
    email: &str,
    name: &str,
    api_key: &str,
) -> Result<String, Box<dyn std::error::Error>> {
    // Validate email
    if !validate_email(email) {
        return Err("Invalid email format".into());
    }
    
    // Sanitize name
    let sanitized_name = sanitize_input(name, 100)?;
    
    // Create JSON payload (serde_json handles escaping)
    let payload = json!({
        "email": email,
        "name": sanitized_name
    });
    
    let response = client
        .post("https://api.example.com/users")
        .header("Authorization", format!("Bearer {}", api_key))
        .json(&payload)
        .send()
        .await?;
    
    let body = response.text().await?;
    Ok(body)
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let client = Client::new();
    let api_key = std::env::var("API_KEY")?;
    
    // Search with validated input
    let results = search_users(&client, "John", &api_key).await?;
    println!("Search results: {}", results);
    
    // Create user with validated input
    let new_user = create_user(&client, "john@example.com", "John Doe", &api_key).await?;
    println!("Created user: {}", new_user);
    
    Ok(())
}
```

**Why this is secure**: Input validation prevents injection attacks and malformed requests. The urlencoding crate properly handles special characters. serde_json automatically escapes data when serializing, preventing injection through manual string concatenation. Rust's type system ensures validation happens before API calls.

---

## Secure Logging with Redaction

Log API interactions for troubleshooting while protecting sensitive information.

```rust
use log::{info, LevelFilter};
use serde_json::{json, Value};
use std::collections::HashMap;
use chrono::Utc;

const SENSITIVE_FIELDS: &[&str] = &[
    "password", "api_key", "apikey", "token", "secret",
    "authorization", "ssn", "credit_card", "cvv", "pin"
];

pub struct SecureLogging;

impl SecureLogging {
    pub fn redact_sensitive_data(data: &mut Value) {
        match data {
            Value::Object(map) => {
                for (key, value) in map.iter_mut() {
                    let key_lower = key.to_lowercase();
                    let is_sensitive = SENSITIVE_FIELDS.iter()
                        .any(|&field| key_lower.contains(field));
                    
                    if is_sensitive {
                        *value = Value::String("[REDACTED]".to_string());
                    } else if value.is_object() {
                        Self::redact_sensitive_data(value);
                    }
                }
            }
            _ => {}
        }
    }
    
    pub fn mask_email(email: &str) -> String {
        if !email.contains('@') {
            return "[INVALID_EMAIL]".to_string();
        }
        
        let parts: Vec<&str> = email.split('@').collect();
        if parts.len() != 2 {
            return "[INVALID_EMAIL]".to_string();
        }
        
        let local = parts[0];
        let domain = parts[1];
        
        let masked = if local.len() <= 2 {
            "*".repeat(local.len())
        } else {
            format!("{}{}", &local[..2], "*".repeat(local.len() - 2))
        };
        
        format!("{}@{}", masked, domain)
    }
    
    pub fn log_api_request(
        method: &str,
        url: &str,
        headers: &HashMap<String, String>,
        payload: Option<Value>,
    ) {
        let mut safe_headers = headers.clone();
        if let Some(auth) = safe_headers.get_mut("Authorization") {
            *auth = "[REDACTED]".to_string();
        }
        
        let mut safe_payload = payload;
        if let Some(ref mut p) = safe_payload {
            Self::redact_sensitive_data(p);
        }
        
        let log_data = json!({
            "timestamp": Utc::now().to_rfc3339(),
            "type": "request",
            "method": method,
            "url": url,
            "headers": safe_headers,
            "payload": safe_payload
        });
        
        info!("{}", log_data);
    }
    
    pub fn log_api_response(
        status_code: u16,
        response_time_ms: u64,
        payload: Option<Value>,
    ) {
        let mut safe_payload = payload;
        if let Some(ref mut p) = safe_payload {
            Self::redact_sensitive_data(p);
        }
        
        let log_data = json!({
            "timestamp": Utc::now().to_rfc3339(),
            "type": "response",
            "status_code": status_code,
            "response_time_ms": response_time_ms,
            "payload": safe_payload
        });
        
        info!("{}", log_data);
    }
}

fn main() {
    env_logger::Builder::new()
        .filter_level(LevelFilter::Info)
        .init();
    
    // Example: Log API request
    let mut headers = HashMap::new();
    headers.insert("Authorization".to_string(), "Bearer secret-token".to_string());
    headers.insert("Content-Type".to_string(), "application/json".to_string());
    
    let payload = json!({
        "email": "user@example.com",
        "api_key": "super-secret-key",
        "name": "John Doe"
    });
    
    SecureLogging::log_api_request("POST", "https://api.example.com/users", &headers, Some(payload));
    
    // Example: Log API response
    let response_payload = json!({
        "id": 123,
        "email": "user@example.com",
        "token": "response-token"
    });
    
    SecureLogging::log_api_response(200, 150, Some(response_payload));
    
    // Example: Mask email
    println!("Masked email: {}", SecureLogging::mask_email("john.doe@example.com"));
}
```

**Why this is secure**: Sensitive fields are automatically identified and redacted. The log crate provides structured logging with appropriate levels. Mutable references ensure safe modification without cloning entire structures unnecessarily. Email masking balances privacy with troubleshooting needs. Rust's ownership system prevents accidental data leakage.

---

## Complete Example: Secure API Client

Here's a complete example combining all best practices:

```rust
use reqwest::{Client, StatusCode};
use serde_json::Value;
use std::env;
use std::time::{Duration, Instant};
use tokio::time::sleep;
use log::{info, error};
use rand::Rng;

const MAX_RETRIES: u32 = 3;

pub struct CompleteSecureAPIClient {
    client: Client,
    base_url: String,
    api_key: String,
}

impl CompleteSecureAPIClient {
    pub fn new(base_url: String) -> Result<Self, Box<dyn std::error::Error>> {
        let api_key = env::var("API_KEY")
            .map_err(|_| "API_KEY environment variable not set")?;
        
        let client = Client::builder()
            .timeout(Duration::from_secs(10))
            .https_only(true)
            .min_tls_version(reqwest::tls::Version::TLS_1_2)
            .build()?;
        
        Ok(Self {
            client,
            base_url,
            api_key,
        })
    }
    
    async fn do_request(
        &self,
        method: reqwest::Method,
        path: &str,
        body: Option<Value>,
    ) -> Result<String, Box<dyn std::error::Error>> {
        for attempt in 0..MAX_RETRIES {
            let url = format!("{}{}", self.base_url, path);
            
            let mut request = self.client
                .request(method.clone(), &url)
                .header("Authorization", format!("Bearer {}", self.api_key))
                .header("Content-Type", "application/json");
            
            if let Some(ref b) = body {
                request = request.json(b);
            }
            
            let start_time = Instant::now();
            
            match request.send().await {
                Ok(response) => {
                    let elapsed = start_time.elapsed().as_millis();
                    info!("Response: {} ({}ms)", response.status(), elapsed);
                    
                    if response.status().is_success() {
                        let body = response.text().await?;
                        return Ok(body);
                    }
                    
                    if response.status().is_server_error() && attempt < MAX_RETRIES - 1 {
                        let wait_time = Self::calculate_backoff(attempt);
                        sleep(wait_time).await;
                        continue;
                    }
                    
                    let body = response.text().await?;
                    return Ok(body);
                }
                Err(e) => {
                    error!("Request attempt {} failed: {:?}", attempt + 1, e);
                    
                    if attempt < MAX_RETRIES - 1 {
                        let wait_time = Self::calculate_backoff(attempt);
                        sleep(wait_time).await;
                    } else {
                        return Err(Box::new(e));
                    }
                }
            }
        }
        
        Err("Max retries exceeded".into())
    }
    
    fn calculate_backoff(attempt: u32) -> Duration {
        let mut rng = rand::thread_rng();
        let exponential = 2_u64.pow(attempt);
        let jitter = rng.gen_range(0..1000);
        Duration::from_millis(exponential * 1000 + jitter)
    }
    
    pub async fn get(&self, path: &str) -> Result<String, Box<dyn std::error::Error>> {
        self.do_request(reqwest::Method::GET, path, None).await
    }
    
    pub async fn post(
        &self,
        path: &str,
        data: Value,
    ) -> Result<String, Box<dyn std::error::Error>> {
        self.do_request(reqwest::Method::POST, path, Some(data)).await
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::init();
    
    let client = CompleteSecureAPIClient::new("https://api.example.com".to_string())?;
    
    // Example GET request
    let user = client.get("/users/123").await?;
    println!("User: {}", user);
    
    // Example POST request
    let new_user = serde_json::json!({
        "name": "John Doe",
        "email": "john@example.com"
    });
    let created = client.post("/users", new_user).await?;
    println!("Created: {}", created);
    
    Ok(())
}
```

**Why this is secure**: This client combines all security best practices: environment-based credential management, TLS 1.2+ enforcement with HTTPS-only mode, automatic retry logic with exponential backoff and jitter, structured logging through the log crate, and comprehensive error handling. Rust's ownership system, type safety, and Result-based error handling make security patterns compile-time enforced rather than runtime conventions.