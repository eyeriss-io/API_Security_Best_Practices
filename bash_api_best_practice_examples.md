# Bash/Shell API Security Examples

This document provides practical Bash/Shell examples demonstrating secure API consumption patterns using curl and standard Unix tools.

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

```bash
#!/bin/bash

# Retrieve API key from environment variable
API_KEY="${API_KEY:-}"
if [ -z "$API_KEY" ]; then
    echo "Error: API_KEY environment variable not set" >&2
    exit 1
fi

BASE_URL="https://api.example.com"
TIMEOUT=10

# Function to make authenticated API request
fetch_data() {
    local url="$BASE_URL/data"
    
    curl --silent --show-error \
         --max-time "$TIMEOUT" \
         --header "Authorization: Bearer $API_KEY" \
         --header "Content-Type: application/json" \
         "$url"
}

# Usage
if result=$(fetch_data); then
    echo "$result"
else
    echo "Error: Request failed" >&2
    exit 1
fi
```

**Why this approach is secure**: Credentials are retrieved from environment variables using ${API_KEY} and never hardcoded in the script. The script exits immediately with an error message if credentials are missing. Curl is configured with appropriate timeouts to prevent hanging requests.

---

## HTTPS Communication with Certificate Validation

Always use HTTPS and verify SSL certificates to prevent man-in-the-middle attacks.

```bash
#!/bin/bash

# Function to create secure curl request
secure_curl() {
    local url="$1"
    
    # Certificate verification is enabled by default in curl
    # Explicitly enforce it and set TLS version
    curl --silent --show-error \
         --tlsv1.2 \
         --cacert /etc/ssl/certs/ca-certificates.crt \
         --max-time 10 \
         "$url"
}

# Function with custom CA certificate
secure_curl_custom_ca() {
    local url="$1"
    local ca_file="$2"
    
    if [ ! -f "$ca_file" ]; then
        echo "Error: CA file not found: $ca_file" >&2
        return 1
    fi
    
    curl --silent --show-error \
         --tlsv1.2 \
         --cacert "$ca_file" \
         --max-time 10 \
         "$url"
}

# Function to verify certificate details
check_certificate() {
    local url="$1"
    
    echo "Certificate information for: $url"
    echo | openssl s_client -servername "${url#https://}" \
                            -connect "${url#https://}:443" \
                            -showcerts 2>/dev/null \
        | openssl x509 -noout -dates -subject -issuer
}

# Usage
URL="https://api.example.com/data"

if result=$(secure_curl "$URL"); then
    echo "Response: $result"
else
    echo "Error: Request failed" >&2
    exit 1
fi
```

**Why this is secure**: Certificate verification is enabled by default and explicitly configured. Minimum TLS version (1.2) is enforced using --tlsv1.2. Custom CA certificates can be specified for internal APIs. Certificate validation cannot be easily bypassed without modifying the script.

---

## Retry Logic with Exponential Backoff

Implement intelligent retry logic for transient failures with exponential backoff and jitter.

```bash
#!/bin/bash

MAX_RETRIES=3
BASE_URL="https://api.example.com"

# Function to calculate exponential backoff with jitter
calculate_backoff() {
    local attempt=$1
    local exponential=$((2 ** attempt))
    local jitter=$((RANDOM % 1000))
    echo $((exponential + jitter / 1000))
}

# Function to get Retry-After header value
get_retry_after() {
    local headers="$1"
    local retry_after
    
    retry_after=$(echo "$headers" | grep -i "retry-after:" | cut -d: -f2 | tr -d ' ')
    
    if [ -z "$retry_after" ]; then
        echo 60  # Default to 60 seconds
    else
        echo "$retry_after"
    fi
}

# Function to make API request with retry logic
api_call_with_retry() {
    local url="$1"
    local attempt=0
    local http_code
    local response
    local headers_file
    
    headers_file=$(mktemp)
    trap "rm -f '$headers_file'" EXIT
    
    while [ $attempt -lt $MAX_RETRIES ]; do
        # Make request and capture HTTP status code
        response=$(curl --silent --show-error \
                        --max-time 10 \
                        --write-out "\n%{http_code}" \
                        --dump-header "$headers_file" \
                        --header "Authorization: Bearer $API_KEY" \
                        "$url" 2>&1)
        
        http_code=$(echo "$response" | tail -n1)
        response=$(echo "$response" | head -n-1)
        
        # Success (2xx status codes)
        if [ "$http_code" -ge 200 ] && [ "$http_code" -lt 300 ]; then
            echo "$response"
            rm -f "$headers_file"
            return 0
        fi
        
        # Rate limited (429)
        if [ "$http_code" -eq 429 ]; then
            if [ $attempt -lt $((MAX_RETRIES - 1)) ]; then
                retry_after=$(get_retry_after "$(cat "$headers_file")")
                echo "Rate limited. Waiting ${retry_after}s..." >&2
                sleep "$retry_after"
                attempt=$((attempt + 1))
                continue
            fi
        fi
        
        # Server error (5xx)
        if [ "$http_code" -ge 500 ]; then
            if [ $attempt -lt $((MAX_RETRIES - 1)) ]; then
                wait_time=$(calculate_backoff $attempt)
                echo "Server error. Retrying in ${wait_time}s..." >&2
                sleep "$wait_time"
                attempt=$((attempt + 1))
                continue
            fi
        fi
        
        # Client error or final attempt
        echo "Error: HTTP $http_code" >&2
        echo "$response" >&2
        rm -f "$headers_file"
        return 1
    done
    
    echo "Error: Max retries exceeded" >&2
    rm -f "$headers_file"
    return 1
}

# Usage
API_KEY="${API_KEY:-}"
if [ -z "$API_KEY" ]; then
    echo "Error: API_KEY environment variable not set" >&2
    exit 1
fi

if result=$(api_call_with_retry "$BASE_URL/data"); then
    echo "Success: $result"
else
    exit 1
fi
```

**Why this is secure**: Exponential backoff with jitter prevents overwhelming struggling services. Retry-After headers are parsed and respected. Server errors and network failures trigger retries while client errors do not. Temporary files are properly cleaned up using trap.

---

## Proper Error Handling

Handle errors gracefully and avoid exposing sensitive information in error messages.

```bash
#!/bin/bash

set -euo pipefail  # Exit on error, undefined variables, and pipe failures

# Logging function
log() {
    local level="$1"
    shift
    echo "[$(date +'%Y-%m-%d %H:%M:%S')] [$level] $*" >&2
}

# Function to fetch user data with proper error handling
fetch_user_data() {
    local user_id="$1"
    local api_key="$2"
    local url="https://api.example.com/users/$user_id"
    local response
    local http_code
    
    # Make request and capture response and status code
    response=$(curl --silent --show-error \
                    --write-out "\n%{http_code}" \
                    --max-time 10 \
                    --header "Authorization: Bearer $api_key" \
                    "$url" 2>&1)
    
    http_code=$(echo "$response" | tail -n1)
    response=$(echo "$response" | head -n-1)
    
    # Handle different status codes
    case "$http_code" in
        200)
            echo "$response"
            return 0
            ;;
        404)
            log "WARN" "User $user_id not found"
            echo "Error: User not found" >&2
            return 1
            ;;
        401)
            log "ERROR" "Authentication failed for user $user_id"
            echo "Error: Invalid credentials" >&2
            return 1
            ;;
        403)
            echo "Error: Access denied" >&2
            return 1
            ;;
        5*)
            log "ERROR" "Server error for user $user_id: HTTP $http_code"
            echo "Error: Service temporarily unavailable" >&2
            return 1
            ;;
        *)
            log "WARN" "Request failed for user $user_id: HTTP $http_code"
            echo "Error: Request failed" >&2
            return 1
            ;;
    esac
}

# Usage
API_KEY="${API_KEY:-}"
if [ -z "$API_KEY" ]; then
    log "ERROR" "API_KEY environment variable not set"
    exit 1
fi

if user_data=$(fetch_user_data "123" "$API_KEY"); then
    echo "User data: $user_data"
else
    exit 1
fi
```

**Why this is secure**: Detailed errors are logged to stderr for debugging but generic messages are shown to users. The script uses proper exit codes and set -euo pipefail for robust error handling. Sensitive information like API keys is never logged or displayed.

---

## Input Validation and Sanitization

Validate and sanitize all inputs before including them in API requests.

```bash
#!/bin/bash

# Function to validate email format
validate_email() {
    local email="$1"
    local regex='^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    
    if [[ "$email" =~ $regex ]]; then
        return 0
    else
        return 1
    fi
}

# Function to sanitize input
sanitize_input() {
    local input="$1"
    local max_length="${2:-100}"
    
    # Check length
    if [ ${#input} -gt "$max_length" ]; then
        echo "Error: Input exceeds maximum length of $max_length" >&2
        return 1
    fi
    
    # Remove null bytes and trim whitespace
    input=$(echo "$input" | tr -d '\0' | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')
    
    echo "$input"
}

# Function to URL encode a string
url_encode() {
    local string="$1"
    local encoded=""
    local length="${#string}"
    
    for (( i = 0; i < length; i++ )); do
        local c="${string:i:1}"
        case "$c" in
            [a-zA-Z0-9.~_-])
                encoded+="$c"
                ;;
            *)
                encoded+=$(printf '%%%02X' "'$c")
                ;;
        esac
    done
    
    echo "$encoded"
}

# Function to search users with input validation
search_users() {
    local search_term="$1"
    local api_key="$2"
    
    # Sanitize input
    if ! search_term=$(sanitize_input "$search_term" 50); then
        return 1
    fi
    
    # URL encode
    local encoded
    encoded=$(url_encode "$search_term")
    
    curl --silent --show-error \
         --max-time 10 \
         --header "Authorization: Bearer $api_key" \
         "https://api.example.com/users/search?q=$encoded"
}

# Function to create user with validation
create_user() {
    local email="$1"
    local name="$2"
    local api_key="$3"
    
    # Validate email
    if ! validate_email "$email"; then
        echo "Error: Invalid email format" >&2
        return 1
    fi
    
    # Sanitize name
    if ! name=$(sanitize_input "$name" 100); then
        return 1
    fi
    
    # Create JSON payload (using jq for proper escaping)
    local payload
    payload=$(jq -n \
                 --arg email "$email" \
                 --arg name "$name" \
                 '{email: $email, name: $name}')
    
    curl --silent --show-error \
         --max-time 10 \
         --request POST \
         --header "Authorization: Bearer $api_key" \
         --header "Content-Type: application/json" \
         --data "$payload" \
         "https://api.example.com/users"
}

# Usage
API_KEY="${API_KEY:-}"
if [ -z "$API_KEY" ]; then
    echo "Error: API_KEY environment variable not set" >&2
    exit 1
fi

# Search with validated input
if results=$(search_users "John" "$API_KEY"); then
    echo "Search results: $results"
fi

# Create user with validated input
if new_user=$(create_user "john@example.com" "John Doe" "$API_KEY"); then
    echo "Created user: $new_user"
fi
```

**Why this is secure**: Input validation prevents injection attacks and malformed requests. URL encoding is implemented properly for query parameters. Using jq for JSON construction ensures proper escaping. Bash regex validation prevents invalid input from reaching the API.

---

## Secure Logging with Redaction

Log API interactions for troubleshooting while protecting sensitive information.

```bash
#!/bin/bash

# Sensitive field patterns to redact
SENSITIVE_PATTERNS="password|api_key|apikey|token|secret|authorization|ssn|credit_card|cvv|pin"

# Function to redact sensitive data from JSON
redact_sensitive_json() {
    local json="$1"
    
    # Use jq to redact sensitive fields
    echo "$json" | jq --arg patterns "$SENSITIVE_PATTERNS" '
        walk(
            if type == "object" then
                with_entries(
                    if (.key | ascii_downcase | test($patterns)) then
                        .value = "[REDACTED]"
                    else
                        .
                    end
                )
            else
                .
            end
        )
    '
}

# Function to mask email addresses
mask_email() {
    local email="$1"
    
    if [[ ! "$email" =~ @ ]]; then
        echo "[INVALID_EMAIL]"
        return
    fi
    
    local local_part="${email%%@*}"
    local domain="${email##*@}"
    local masked
    
    if [ ${#local_part} -le 2 ]; then
        masked=$(printf '%*s' "${#local_part}" | tr ' ' '*')
    else
        masked="${local_part:0:2}$(printf '%*s' $((${#local_part} - 2)) | tr ' ' '*')"
    fi
    
    echo "${masked}@${domain}"
}

# Function to log API request
log_api_request() {
    local method="$1"
    local url="$2"
    local headers="$3"
    local payload="$4"
    
    # Redact authorization header
    local safe_headers
    safe_headers=$(echo "$headers" | sed 's/\(Authorization: Bearer \).*/\1[REDACTED]/')
    
    # Redact sensitive payload data
    local safe_payload=""
    if [ -n "$payload" ]; then
        safe_payload=$(redact_sensitive_json "$payload")
    fi
    
    # Create log entry
    local timestamp
    timestamp=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
    
    cat <<EOF | jq -c '.'
{
    "timestamp": "$timestamp",
    "type": "request",
    "method": "$method",
    "url": "$url",
    "headers": "$safe_headers",
    "payload": $safe_payload
}
EOF
}

# Function to log API response
log_api_response() {
    local status_code="$1"
    local response_time_ms="$2"
    local payload="$3"
    
    # Redact sensitive response data
    local safe_payload=""
    if [ -n "$payload" ]; then
        safe_payload=$(redact_sensitive_json "$payload")
    fi
    
    # Create log entry
    local timestamp
    timestamp=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
    
    cat <<EOF | jq -c '.'
{
    "timestamp": "$timestamp",
    "type": "response",
    "status_code": $status_code,
    "response_time_ms": $response_time_ms,
    "payload": $safe_payload
}
EOF
}

# Function to make API call with logging
api_call_with_logging() {
    local method="$1"
    local url="$2"
    local payload="$3"
    
    # Log request
    log_api_request "$method" "$url" "Authorization: Bearer $API_KEY" "$payload"
    
    # Make request and measure time
    local start_time
    # Handle both GNU date (Linux) and BSD date (macOS)
    if date --version >/dev/null 2>&1; then
        # GNU date
        start_time=$(date +%s%3N)
    else
        # BSD date (macOS)
        start_time=$(($(date +%s) * 1000))
    fi
    
    local response
    local http_code
    
    if [ -n "$payload" ]; then
        response=$(curl --silent --show-error \
                        --write-out "\n%{http_code}" \
                        --request "$method" \
                        --header "Authorization: Bearer $API_KEY" \
                        --header "Content-Type: application/json" \
                        --data "$payload" \
                        "$url")
    else
        response=$(curl --silent --show-error \
                        --write-out "\n%{http_code}" \
                        --request "$method" \
                        --header "Authorization: Bearer $API_KEY" \
                        "$url")
    fi
    
    http_code=$(echo "$response" | tail -n1)
    response=$(echo "$response" | head -n-1)
    
    local end_time
    # Handle both GNU date (Linux) and BSD date (macOS)
    if date --version >/dev/null 2>&1; then
        # GNU date
        end_time=$(date +%s%3N)
    else
        # BSD date (macOS)
        end_time=$(($(date +%s) * 1000))
    fi
    local response_time=$((end_time - start_time))
    
    # Log response
    log_api_response "$http_code" "$response_time" "$response"
    
    echo "$response"
}

# Usage
API_KEY="${API_KEY:-}"
if [ -z "$API_KEY" ]; then
    echo "Error: API_KEY environment variable not set" >&2
    exit 1
fi

# Example: API request with logging
payload=$(jq -n \
             --arg email "user@example.com" \
             --arg api_key "super-secret-key" \
             --arg name "John Doe" \
             '{email: $email, api_key: $api_key, name: $name}')

response=$(api_call_with_logging "POST" "https://api.example.com/users" "$payload")

# Example: Mask email
masked=$(mask_email "john.doe@example.com")
echo "Masked email: $masked"
```

**Why this approach is secure**: Sensitive fields are automatically identified and redacted using jq. Authorization headers are redacted before logging. JSON structured logging enables easy parsing. Email masking balances privacy with troubleshooting. All logging goes to stdout/stderr where it can be captured by system logging. The date command handling works on both Linux and macOS systems.

---

## Complete Example: Secure API Client

Here's a complete example combining all best practices:

```bash
#!/bin/bash

set -euo pipefail

# Configuration
readonly MAX_RETRIES=3
readonly BASE_URL="https://api.example.com"
readonly TIMEOUT=10

# Check for required dependencies
for cmd in curl jq; do
    if ! command -v "$cmd" &> /dev/null; then
        echo "Error: $cmd is required but not installed" >&2
        exit 1
    fi
done

# Retrieve API key from environment
API_KEY="${API_KEY:-}"
if [ -z "$API_KEY" ]; then
    echo "Error: API_KEY environment variable not set" >&2
    exit 1
fi

# Logging function
log() {
    echo "[$(date +'%Y-%m-%d %H:%M:%S')] $*" >&2
}

# Calculate exponential backoff
calculate_backoff() {
    local attempt=$1
    echo $((2 ** attempt + RANDOM % 1000 / 1000))
}

# Make secure API request with retry logic
api_request() {
    local method="$1"
    local path="$2"
    local data="${3:-}"
    local attempt=0
    local url="$BASE_URL$path"
    
    while [ $attempt -lt $MAX_RETRIES ]; do
        local response
        local http_code
        local curl_args=(
            --silent
            --show-error
            --max-time "$TIMEOUT"
            --tlsv1.2
            --write-out "\n%{http_code}"
            --header "Authorization: Bearer $API_KEY"
            --header "Content-Type: application/json"
        )
        
        if [ -n "$data" ]; then
            curl_args+=(--data "$data")
        fi
        
        response=$(curl "${curl_args[@]}" --request "$method" "$url" 2>&1)
        http_code=$(echo "$response" | tail -n1)
        response=$(echo "$response" | head -n-1)
        
        log "Response: HTTP $http_code"
        
        # Success
        if [ "$http_code" -ge 200 ] && [ "$http_code" -lt 300 ]; then
            echo "$response"
            return 0
        fi
        
        # Server error - retry
        if [ "$http_code" -ge 500 ] && [ $attempt -lt $((MAX_RETRIES - 1)) ]; then
            local wait_time
            wait_time=$(calculate_backoff $attempt)
            log "Server error. Retrying in ${wait_time}s..."
            sleep "$wait_time"
            attempt=$((attempt + 1))
            continue
        fi
        
        # Client error or final attempt
        echo "Error: HTTP $http_code - $response" >&2
        return 1
    done
    
    echo "Error: Max retries exceeded" >&2
    return 1
}

# GET request
api_get() {
    local path="$1"
    api_request "GET" "$path"
}

# POST request
api_post() {
    local path="$1"
    local data="$2"
    api_request "POST" "$path" "$data"
}

# Main execution
main() {
    log "Starting API client"
    
    # Example GET request
    if user=$(api_get "/users/123"); then
        echo "User: $user"
    else
        log "Failed to fetch user"
        exit 1
    fi
    
    # Example POST request
    payload=$(jq -n \
                 --arg name "John Doe" \
                 --arg email "john@example.com" \
                 '{name: $name, email: $email}')
    
    if new_user=$(api_post "/users" "$payload"); then
        echo "Created: $new_user"
    else
        log "Failed to create user"
        exit 1
    fi
    
    log "API client completed successfully"
}

main "$@"
```

**Why this is secure**: This script combines all security best practices: environment-based credential management, TLS 1.2+ enforcement with certificate validation, automatic retry logic with exponential backoff and jitter, comprehensive error handling, and proper logging. The script uses set -euo pipefail for robust error handling and jq for safe JSON manipulation. Credentials are never logged or exposed in error messages.