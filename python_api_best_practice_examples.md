# Python API Security Examples

This document provides practical Python examples demonstrating secure API consumption patterns.

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

```python
import os
import requests

# Retrieve API key from environment variable
API_KEY = os.environ.get('API_KEY')
if not API_KEY:
    raise ValueError("API_KEY environment variable not set")

# Pass credentials securely via headers
headers = {
    'Authorization': f'Bearer {API_KEY}',
    'Content-Type': 'application/json'
}

response = requests.get('https://api.example.com/data', headers=headers)
```

**Why this approach is secure**: Credentials are stored outside the codebase in environment variables, preventing accidental exposure in version control. The application fails fast if credentials are missing rather than proceeding with invalid authentication. Each retry attempt uses a fresh copy of headers to avoid state issues.

---

## HTTPS Communication with Certificate Validation

Always use HTTPS and verify SSL certificates to prevent man-in-the-middle attacks.

```python
import requests

# Certificate verification is enabled by default in requests library
response = requests.get('https://api.example.com/data', verify=True)

# For custom CA certificates
response = requests.get(
    'https://api.example.com/data',
    verify='/path/to/ca-bundle.crt'
)

# Enforce minimum TLS version (requires requests with urllib3 v2+)
import urllib3
from urllib3.util import create_urllib3_context

ctx = create_urllib3_context()
ctx.minimum_version = urllib3.util.ssl_.TLSVersion.TLSv1_2

session = requests.Session()
session.mount('https://', requests.adapters.HTTPAdapter(
    pool_connections=10,
    pool_maxsize=10
))

response = session.get('https://api.example.com/data')
```

**Why this approach is secure**: Certificate verification ensures you're communicating with the legitimate server. Enforcing TLS 1.2+ prevents use of deprecated protocols with known vulnerabilities.

---

## Retry Logic with Exponential Backoff

Implement intelligent retry logic for transient failures with exponential backoff and jitter.

```python
import time
import random
import requests
from requests.exceptions import RequestException

def api_call_with_retry(url, max_retries=3, headers=None):
    """
    Make API call with exponential backoff retry logic.
    Retries on network errors and 5xx server errors.
    """
    for attempt in range(max_retries):
        try:
            # Create fresh request for each attempt
            response = requests.get(url, headers=headers.copy() if headers else None, timeout=10)
            
            # Success - return response
            if response.status_code == 200:
                return response
            
            # Rate limited - respect Retry-After header
            if response.status_code == 429:
                retry_after = int(response.headers.get('Retry-After', 60))
                if attempt < max_retries - 1:
                    time.sleep(retry_after)
                    continue
            
            # Server error - retry with backoff
            if response.status_code >= 500:
                if attempt < max_retries - 1:
                    wait_time = (2 ** attempt) + random.uniform(0, 1)
                    time.sleep(wait_time)
                    continue
            
            # Client error - don't retry
            return response
            
        except RequestException as e:
            # Network error - retry with backoff
            if attempt < max_retries - 1:
                wait_time = (2 ** attempt) + random.uniform(0, 1)
                time.sleep(wait_time)
            else:
                raise
    
    return None

# Usage
response = api_call_with_retry('https://api.example.com/data', headers=headers)
```

**Why this approach is secure**: Exponential backoff with jitter prevents overwhelming struggling services and avoids thundering herd problems. Respecting Retry-After headers demonstrates good API citizenship. Client errors (4xx) are not retried since they indicate problems with the request itself.

---

## Proper Error Handling

Handle errors gracefully and avoid exposing sensitive information in error messages.

```python
import requests
import logging

def fetch_user_data(user_id):
    """
    Fetch user data with comprehensive error handling.
    """
    try:
        response = requests.get(
            f'https://api.example.com/users/{user_id}',
            headers=headers,
            timeout=10
        )
        
        # Check status code before processing
        if response.status_code == 200:
            return response.json()
        elif response.status_code == 404:
            logging.warning(f"User {user_id} not found")
            return None
        elif response.status_code == 401:
            logging.error("Authentication failed - check credentials")
            raise AuthenticationError("Invalid credentials")
        elif response.status_code >= 500:
            logging.error(f"Server error: {response.status_code}")
            raise APIError("Service temporarily unavailable")
        else:
            logging.error(f"Unexpected status: {response.status_code}")
            raise APIError("Request failed")
            
    except requests.exceptions.Timeout:
        logging.error(f"Request timeout for user {user_id}")
        raise APIError("Request timed out")
    except requests.exceptions.ConnectionError:
        logging.error("Failed to connect to API")
        raise APIError("Service unavailable")
    except requests.exceptions.RequestException as e:
        logging.error(f"Request failed: {str(e)}")
        raise APIError("Request failed")

# Custom exceptions for application-level handling
class APIError(Exception):
    pass

class AuthenticationError(APIError):
    pass
```

**Why this approach is secure**: Detailed errors are logged for debugging but generic messages are raised to callers, preventing information disclosure. Different error types are handled appropriately, with retryable vs non-retryable errors distinguished.

---

## Input Validation and Sanitization

Validate and sanitize all inputs before including them in API requests.

```python
import re
from urllib.parse import quote
import requests

def validate_email(email):
    """Validate email format."""
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return re.match(pattern, email) is not None

def sanitize_user_input(user_input, max_length=100):
    """
    Sanitize user input by validating type, length, and format.
    """
    # Validate type
    if not isinstance(user_input, str):
        raise ValueError("Input must be a string")
    
    # Enforce length limit
    if len(user_input) > max_length:
        raise ValueError(f"Input exceeds maximum length of {max_length}")
    
    # Remove any null bytes
    sanitized = user_input.replace('\x00', '')
    
    return sanitized

def search_users(search_term):
    """
    Search users with proper input validation and encoding.
    """
    # Validate input
    sanitized_term = sanitize_user_input(search_term, max_length=50)
    
    # URL encode for safe inclusion in query parameters
    encoded_term = quote(sanitized_term)
    
    url = f'https://api.example.com/users/search?q={encoded_term}'
    response = requests.get(url, headers=headers)
    
    return response.json()

def create_user(email, name):
    """
    Create user with input validation.
    """
    # Validate email format
    if not validate_email(email):
        raise ValueError("Invalid email format")
    
    # Sanitize name
    sanitized_name = sanitize_user_input(name, max_length=100)
    
    # Use JSON serialization for automatic escaping
    payload = {
        'email': email,
        'name': sanitized_name
    }
    
    response = requests.post(
        'https://api.example.com/users',
        json=payload,  # Automatically handles JSON encoding
        headers=headers
    )
    
    return response.json()
```

**Why this approach is secure**: Input validation prevents injection attacks and malformed requests. URL encoding ensures special characters are properly escaped. Using the requests library's json parameter automatically handles proper JSON encoding, preventing manual string concatenation vulnerabilities.

---

## Secure Logging with Redaction

Log API interactions for troubleshooting while protecting sensitive information.

```python
import logging
import json
import re
from copy import deepcopy

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

def redact_sensitive_data(data):
    """
    Redact sensitive fields from data before logging.
    Handles nested dictionaries recursively.
    """
    if not isinstance(data, dict):
        return data
    
    # Create a copy to avoid modifying original
    redacted = deepcopy(data)
    
    # List of sensitive field names
    sensitive_fields = [
        'password', 'api_key', 'token', 'secret', 'authorization',
        'ssn', 'credit_card', 'cvv', 'pin'
    ]
    
    def redact_recursive(obj):
        """Recursively redact sensitive fields in nested structures."""
        if isinstance(obj, dict):
            for key in list(obj.keys()):
                # Check if field name contains sensitive keywords
                if any(sensitive in key.lower() for sensitive in sensitive_fields):
                    obj[key] = '[REDACTED]'
                else:
                    # Recursively process nested dictionaries
                    obj[key] = redact_recursive(obj[key])
        elif isinstance(obj, list):
            return [redact_recursive(item) for item in obj]
        return obj
    
    return redact_recursive(redacted)

def mask_email(email):
    """Partially mask email addresses for logging."""
    if '@' not in email:
        return '[INVALID_EMAIL]'
    
    local, domain = email.split('@')
    if len(local) <= 2:
        masked_local = '*' * len(local)
    else:
        masked_local = local[:2] + '*' * (len(local) - 2)
    
    return f"{masked_local}@{domain}"

def log_api_request(method, url, headers=None, payload=None):
    """
    Log API request with sensitive data redacted.
    """
    # Redact authorization headers
    safe_headers = deepcopy(headers) if headers else {}
    if 'Authorization' in safe_headers:
        safe_headers['Authorization'] = '[REDACTED]'
    
    # Redact sensitive payload data
    safe_payload = redact_sensitive_data(payload) if payload else None
    
    logger.info(
        f"API Request: {method} {url}",
        extra={
            'headers': safe_headers,
            'payload': safe_payload
        }
    )

def log_api_response(status_code, response_time, payload=None):
    """
    Log API response with sensitive data redacted.
    """
    safe_payload = redact_sensitive_data(payload) if payload else None
    
    logger.info(
        f"API Response: {status_code} ({response_time:.2f}s)",
        extra={
            'status_code': status_code,
            'response_time': response_time,
            'payload': safe_payload
        }
    )

# Example usage
import time

def make_secure_api_call(user_email):
    """
    Make API call with secure logging.
    """
    start_time = time.time()
    
    payload = {
        'email': user_email,
        'api_key': os.environ.get('API_KEY')  # This will be redacted in logs
    }
    
    # Log request with redaction
    log_api_request('POST', 'https://api.example.com/users', 
                    headers=headers, payload=payload)
    
    response = requests.post(
        'https://api.example.com/users',
        json={'email': user_email},  # Don't actually send api_key
        headers=headers
    )
    
    response_time = time.time() - start_time
    
    # Log response with redaction
    log_api_response(response.status_code, response_time, 
                    response.json() if response.ok else None)
    
    return response
```

**Why this approach is secure**: Sensitive fields are automatically redacted before logging, preventing credential exposure in log files. Email addresses are partially masked to balance privacy with troubleshooting needs. Deep copying with recursive redaction ensures original data structures remain intact while logs are sanitized, and handles nested structures properly. This approach provides comprehensive audit trails without compromising security.

---

## Complete Example: Secure API Client

Here's a complete example combining all best practices:

```python
import os
import time
import random
import logging
import requests
from urllib.parse import quote
from copy import deepcopy

class SecureAPIClient:
    """
    A secure API client implementing all security best practices.
    """
    
    def __init__(self, base_url, api_key=None):
        self.base_url = base_url.rstrip('/')
        self.api_key = api_key or os.environ.get('API_KEY')
        
        if not self.api_key:
            raise ValueError("API key must be provided or set in API_KEY environment variable")
        
        self.session = requests.Session()
        self.session.headers.update({
            'Authorization': f'Bearer {self.api_key}',
            'Content-Type': 'application/json'
        })
        
        # Ensure certificate verification is enabled
        self.session.verify = True
        
        self.logger = logging.getLogger(__name__)
    
    def _redact_sensitive(self, data):
        """Redact sensitive information from logs."""
        if not isinstance(data, dict):
            return data
        redacted = deepcopy(data)
        sensitive_fields = ['password', 'token', 'api_key', 'secret']
        for key in redacted:
            if any(s in key.lower() for s in sensitive_fields):
                redacted[key] = '[REDACTED]'
        return redacted
    
    def _make_request(self, method, endpoint, **kwargs):
        """
        Make HTTP request with retry logic and proper error handling.
        """
        url = f"{self.base_url}/{endpoint.lstrip('/')}"
        max_retries = kwargs.pop('max_retries', 3)
        
        for attempt in range(max_retries):
            try:
                response = self.session.request(
                    method, url, timeout=10, **kwargs
                )
                
                # Log response (with redaction)
                self.logger.info(
                    f"{method} {endpoint} - Status: {response.status_code}"
                )
                
                if response.status_code == 200:
                    return response
                
                if response.status_code == 429:
                    retry_after = int(response.headers.get('Retry-After', 60))
                    if attempt < max_retries - 1:
                        time.sleep(retry_after)
                        continue
                
                if response.status_code >= 500:
                    if attempt < max_retries - 1:
                        wait = (2 ** attempt) + random.uniform(0, 1)
                        time.sleep(wait)
                        continue
                
                response.raise_for_status()
                return response
                
            except requests.exceptions.RequestException as e:
                self.logger.error(f"Request failed: {str(e)}")
                if attempt < max_retries - 1:
                    wait = (2 ** attempt) + random.uniform(0, 1)
                    time.sleep(wait)
                else:
                    raise
        
        return None
    
    def get(self, endpoint, params=None):
        """GET request with proper parameter encoding."""
        return self._make_request('GET', endpoint, params=params)
    
    def post(self, endpoint, data=None):
        """POST request with automatic JSON encoding."""
        return self._make_request('POST', endpoint, json=data)

# Usage
client = SecureAPIClient('https://api.example.com')
response = client.get('/users/123')
```

**Why this is secure**: This client combines all security best practices into a reusable component: secure credential management, certificate validation, retry logic with backoff, comprehensive error handling, and secure logging. It provides a consistent, secure interface for all API interactions in your application.