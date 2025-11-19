# Ruby API Security Examples

This document provides practical Ruby examples demonstrating secure API consumption patterns.

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

```ruby
require 'net/http'
require 'uri'
require 'json'

class SecureAPIClient
  def initialize(base_url)
    # Retrieve API key from environment variable
    @api_key = ENV['API_KEY']
    raise 'API_KEY environment variable not set' if @api_key.nil? || @api_key.empty?
    
    @base_url = base_url
    @timeout = 10
  end
  
  def create_request(method, path)
    uri = URI.join(@base_url, path)
    request_class = case method
                    when :get then Net::HTTP::Get
                    when :post then Net::HTTP::Post
                    when :put then Net::HTTP::Put
                    when :delete then Net::HTTP::Delete
                    else raise ArgumentError, "Unsupported method: #{method}"
                    end
    
    request = request_class.new(uri)
    request['Authorization'] = "Bearer #{@api_key}"
    request['Content-Type'] = 'application/json'
    request
  end
  
  def fetch_data
    uri = URI.join(@base_url, '/data')
    request = create_request(:get, '/data')
    
    response = Net::HTTP.start(uri.hostname, uri.port,
                               use_ssl: uri.scheme == 'https',
                               read_timeout: @timeout,
                               open_timeout: @timeout) do |http|
      http.request(request)
    end
    
    response.body
  end
end

# Usage
begin
  client = SecureAPIClient.new('https://api.example.com')
  data = client.fetch_data
  puts data
rescue StandardError => e
  puts "Error: #{e.message}"
end
```

**Why this is secure**: Credentials are retrieved from environment variables and never hardcoded. The application raises an exception immediately if credentials are missing. Timeouts are configured to prevent hanging requests.

---

## HTTPS Communication with Certificate Validation

Always use HTTPS and verify SSL certificates to prevent man-in-the-middle attacks.

```ruby
require 'net/http'
require 'openssl'

class SecureHTTPClient
  def self.create_secure_client(uri)
    http = Net::HTTP.new(uri.hostname, uri.port)
    
    # Enable HTTPS
    http.use_ssl = (uri.scheme == 'https')
    
    # Certificate verification is enabled by default
    http.verify_mode = OpenSSL::SSL::VERIFY_PEER
    
    # Enforce minimum TLS version
    http.min_version = OpenSSL::SSL::TLS1_2_VERSION
    http.max_version = OpenSSL::SSL::TLS1_3_VERSION
    
    # Set timeouts
    http.read_timeout = 10
    http.open_timeout = 10
    
    http
  end
  
  def self.create_client_with_custom_ca(uri, ca_file_path)
    http = Net::HTTP.new(uri.hostname, uri.port)
    http.use_ssl = (uri.scheme == 'https')
    
    # Load custom CA certificate
    http.ca_file = ca_file_path
    http.verify_mode = OpenSSL::SSL::VERIFY_PEER
    
    # Enforce minimum TLS version
    http.min_version = OpenSSL::SSL::TLS1_2_VERSION
    
    http.read_timeout = 10
    http.open_timeout = 10
    
    http
  end
  
  def self.make_request(url)
    uri = URI(url)
    http = create_secure_client(uri)
    
    request = Net::HTTP::Get.new(uri)
    response = http.request(request)
    
    puts "Response: #{response.body}"
  end
end

# Usage
SecureHTTPClient.make_request('https://api.example.com/data')
```

**Why this is secure**: Certificate verification is explicitly enabled with VERIFY_PEER. Minimum TLS version is enforced to prevent use of deprecated protocols. Custom CA certificates can be loaded for internal APIs while maintaining verification.

---

## Retry Logic with Exponential Backoff

Implement intelligent retry logic for transient failures with exponential backoff and jitter.

```ruby
require 'net/http'
require 'json'

class RetryLogic
  MAX_RETRIES = 3
  
  def self.send_with_retry(uri, request)
    attempt = 0
    
    while attempt < MAX_RETRIES
      begin
        http = Net::HTTP.new(uri.hostname, uri.port)
        http.use_ssl = (uri.scheme == 'https')
        http.read_timeout = 10
        http.open_timeout = 10
        
        response = http.request(request)
        
        # Success
        return response if response.is_a?(Net::HTTPSuccess)
        
        # Rate limited - respect Retry-After header
        if response.is_a?(Net::HTTPTooManyRequests)
          if attempt < MAX_RETRIES - 1
            retry_after = get_retry_after(response)
            sleep(retry_after)
            attempt += 1
            next
          end
        end
        
        # Server error - retry with backoff
        if response.is_a?(Net::HTTPServerError)
          if attempt < MAX_RETRIES - 1
            wait_time = calculate_backoff(attempt)
            sleep(wait_time)
            attempt += 1
            next
          end
        end
        
        # Client error or final attempt
        return response
        
      rescue Net::OpenTimeout, Net::ReadTimeout, SocketError => e
        # Network error - retry with backoff
        if attempt < MAX_RETRIES - 1
          wait_time = calculate_backoff(attempt)
          sleep(wait_time)
          attempt += 1
        else
          raise e
        end
      end
    end
    
    raise 'Max retries exceeded'
  end
  
  def self.calculate_backoff(attempt)
    # Exponential backoff with jitter
    exponential = (2 ** attempt)
    jitter = rand
    exponential + jitter
  end
  
  def self.get_retry_after(response)
    retry_after = response['Retry-After']
    return 60 if retry_after.nil?
    
    retry_after.to_i
  end
end

# Usage
begin
  uri = URI('https://api.example.com/data')
  request = Net::HTTP::Get.new(uri)
  request['Authorization'] = "Bearer #{ENV['API_KEY']}"
  
  response = RetryLogic.send_with_retry(uri, request)
  puts "Success: #{response.code}"
rescue StandardError => e
  puts "Request failed: #{e.message}"
end
```

**Why this is secure**: Exponential backoff with jitter prevents overwhelming struggling services. Retry-After headers are respected for rate limits. Network errors and server errors trigger retries while client errors do not. Random jitter prevents synchronized retry attempts.

---

## Proper Error Handling

Handle errors gracefully and avoid exposing sensitive information in error messages.

```ruby
require 'net/http'
require 'logger'

# Custom exception classes
class APIError < StandardError
  attr_reader :status_code
  
  def initialize(message, status_code = nil)
    super(message)
    @status_code = status_code
  end
end

class AuthenticationError < APIError
  def initialize(message = 'Invalid credentials')
    super(message, 401)
  end
end

class ServiceUnavailableError < APIError
  def initialize(message, status_code)
    super(message, status_code)
  end
end

class ErrorHandling
  def initialize
    @logger = Logger.new($stdout)
    @logger.level = Logger::INFO
  end
  
  def fetch_user_data(user_id, api_key)
    uri = URI("https://api.example.com/users/#{user_id}")
    request = Net::HTTP::Get.new(uri)
    request['Authorization'] = "Bearer #{api_key}"
    
    http = Net::HTTP.new(uri.hostname, uri.port)
    http.use_ssl = true
    http.read_timeout = 10
    
    begin
      response = http.request(request)
      
      case response
      when Net::HTTPSuccess
        response.body
      when Net::HTTPNotFound
        @logger.warn("User #{user_id} not found")
        raise APIError.new('User not found', 404)
      when Net::HTTPUnauthorized
        @logger.error("Authentication failed for user #{user_id}")
        raise AuthenticationError.new
      when Net::HTTPForbidden
        raise APIError.new('Access denied', 403)
      when Net::HTTPServerError
        @logger.error("Server error for user #{user_id}: #{response.code}")
        raise ServiceUnavailableError.new('Service temporarily unavailable', response.code.to_i)
      else
        @logger.warn("Request failed for user #{user_id}: #{response.code}")
        raise APIError.new('Request failed', response.code.to_i)
      end
      
    rescue Net::OpenTimeout, Net::ReadTimeout => e
      @logger.error("Request timeout for user #{user_id}: #{e.message}")
      raise APIError.new('Request timed out')
    rescue SocketError => e
      @logger.error("Connection error for user #{user_id}: #{e.message}")
      raise APIError.new('Service unavailable')
    end
  end
end

# Usage
handler = ErrorHandling.new
api_key = ENV['API_KEY']

begin
  user_data = handler.fetch_user_data('123', api_key)
  puts "User data: #{user_data}"
rescue AuthenticationError => e
  puts "Authentication error: #{e.message}"
rescue ServiceUnavailableError => e
  puts "Service error: #{e.message} (status: #{e.status_code})"
rescue APIError => e
  puts "API error: #{e.message} (status: #{e.status_code})"
end
```

**Why this is secure**: Detailed errors are logged for debugging but generic messages are raised to callers. Custom exception hierarchy enables appropriate error handling. Network errors and HTTP errors are handled separately with appropriate logging.

---

## Input Validation and Sanitization

Validate and sanitize all inputs before including them in API requests.

```ruby
require 'net/http'
require 'uri'
require 'json'
require 'cgi'

class InputValidation
  EMAIL_REGEX = /\A[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\z/
  
  def self.validate_email(email)
    !!(email =~ EMAIL_REGEX)
  end
  
  def self.sanitize_input(input, max_length = 100)
    raise ArgumentError, 'Input cannot be nil' if input.nil?
    raise ArgumentError, 'Input must be a string' unless input.is_a?(String)
    raise ArgumentError, "Input exceeds maximum length of #{max_length}" if input.length > max_length
    
    # Remove null bytes and trim whitespace
    input.gsub("\u0000", '').strip
  end
  
  def self.search_users(search_term, api_key)
    # Sanitize input
    sanitized = sanitize_input(search_term, 50)
    
    # URL encode query parameter
    encoded = CGI.escape(sanitized)
    
    uri = URI("https://api.example.com/users/search?q=#{encoded}")
    request = Net::HTTP::Get.new(uri)
    request['Authorization'] = "Bearer #{api_key}"
    
    http = Net::HTTP.new(uri.hostname, uri.port)
    http.use_ssl = true
    
    response = http.request(request)
    response.body
  end
  
  def self.create_user(email, name, api_key)
    # Validate email
    raise ArgumentError, 'Invalid email format' unless validate_email(email)
    
    # Sanitize name
    sanitized_name = sanitize_input(name, 100)
    
    # Create JSON payload (automatic escaping)
    payload = {
      email: email,
      name: sanitized_name
    }.to_json
    
    uri = URI('https://api.example.com/users')
    request = Net::HTTP::Post.new(uri)
    request['Authorization'] = "Bearer #{api_key}"
    request['Content-Type'] = 'application/json'
    request.body = payload
    
    http = Net::HTTP.new(uri.hostname, uri.port)
    http.use_ssl = true
    
    response = http.request(request)
    response.body
  end
end

# Usage
api_key = ENV['API_KEY']

begin
  # Search with validated input
  results = InputValidation.search_users('John', api_key)
  puts "Search results: #{results}"
  
  # Create user with validated input
  new_user = InputValidation.create_user('john@example.com', 'John Doe', api_key)
  puts "Created user: #{new_user}"
rescue ArgumentError => e
  puts "Validation error: #{e.message}"
rescue StandardError => e
  puts "Request failed: #{e.message}"
end
```

**Why this approach is secure**: Input validation prevents injection attacks and malformed requests. CGI.escape properly handles special characters in query parameters. Ruby's to_json method automatically escapes data, preventing injection through manual string concatenation.

---

## Secure Logging with Redaction

Log API interactions for troubleshooting while protecting sensitive information.

```ruby
require 'logger'
require 'json'

class SecureLogging
  SENSITIVE_FIELDS = %w[password api_key apikey token secret authorization ssn credit_card cvv pin]
  
  def initialize
    @logger = Logger.new($stdout)
    @logger.level = Logger::INFO
    @logger.formatter = proc do |severity, datetime, progname, msg|
      "#{datetime.strftime('%Y-%m-%d %H:%M:%S')} [#{severity}] #{msg}\n"
    end
  end
  
  def redact_sensitive_data(data)
    return nil if data.nil?
    return data unless data.is_a?(Hash)
    
    redacted = {}
    
    data.each do |key, value|
      key_str = key.to_s.downcase
      
      # Check if field is sensitive
      is_sensitive = SENSITIVE_FIELDS.any? { |field| key_str.include?(field) }
      
      if is_sensitive
        redacted[key] = '[REDACTED]'
      elsif value.is_a?(Hash)
        redacted[key] = redact_sensitive_data(value)
      else
        redacted[key] = value
      end
    end
    
    redacted
  end
  
  def mask_email(email)
    return '[INVALID_EMAIL]' if email.nil? || !email.include?('@')
    
    local, domain = email.split('@')
    
    masked = if local.length <= 2
               '*' * local.length
             else
               local[0..1] + ('*' * (local.length - 2))
             end
    
    "#{masked}@#{domain}"
  end
  
  def log_api_request(method, url, headers = {}, payload = nil)
    safe_headers = headers.dup
    safe_headers['Authorization'] = '[REDACTED]' if safe_headers.key?('Authorization')
    
    safe_payload = payload ? redact_sensitive_data(payload) : nil
    
    log_data = {
      timestamp: Time.now.iso8601,
      type: 'request',
      method: method,
      url: url,
      headers: safe_headers,
      payload: safe_payload
    }
    
    @logger.info(JSON.generate(log_data))
  end
  
  def log_api_response(status_code, response_time_ms, payload = nil)
    safe_payload = payload ? redact_sensitive_data(payload) : nil
    
    log_data = {
      timestamp: Time.now.iso8601,
      type: 'response',
      status_code: status_code,
      response_time_ms: response_time_ms,
      payload: safe_payload
    }
    
    @logger.info(JSON.generate(log_data))
  end
end

# Usage
logger = SecureLogging.new

# Example: Log API request
headers = {
  'Authorization' => 'Bearer secret-token',
  'Content-Type' => 'application/json'
}

payload = {
  'email' => 'user@example.com',
  'api_key' => 'super-secret-key',
  'name' => 'John Doe'
}

logger.log_api_request('POST', 'https://api.example.com/users', headers, payload)

# Example: Log API response
response_payload = {
  'id' => 123,
  'email' => 'user@example.com',
  'token' => 'response-token'
}

logger.log_api_response(200, 150, response_payload)

# Example: Mask email
puts "Masked email: #{logger.mask_email('john.doe@example.com')}"
```

**Why this is secure**: Sensitive fields are automatically identified and redacted based on field names. JSON structured logging enables easy parsing. Deep copying through hash duplication prevents modification of original data. Email masking balances privacy with troubleshooting needs.

---

## Complete Example: Secure API Client

Here's a complete example combining all best practices:

```ruby
require 'net/http'
require 'uri'
require 'json'
require 'logger'
require 'openssl'

class CompleteSecureAPIClient
  MAX_RETRIES = 3
  
  def initialize(base_url)
    @api_key = ENV['API_KEY']
    raise 'API_KEY environment variable not set' if @api_key.nil? || @api_key.empty?
    
    @base_url = base_url
    @logger = Logger.new($stdout)
    @logger.level = Logger::INFO
  end
  
  def do_request(method, path, body = nil)
    attempt = 0
    
    while attempt < MAX_RETRIES
      begin
        uri = URI.join(@base_url, path)
        
        request = case method
                  when :get then Net::HTTP::Get.new(uri)
                  when :post then Net::HTTP::Post.new(uri)
                  when :put then Net::HTTP::Put.new(uri)
                  when :delete then Net::HTTP::Delete.new(uri)
                  end
        
        request['Authorization'] = "Bearer #{@api_key}"
        request['Content-Type'] = 'application/json'
        
        if body
          request.body = body.to_json
        end
        
        http = Net::HTTP.new(uri.hostname, uri.port)
        http.use_ssl = (uri.scheme == 'https')
        http.verify_mode = OpenSSL::SSL::VERIFY_PEER
        http.min_version = OpenSSL::SSL::TLS1_2_VERSION
        http.read_timeout = 10
        http.open_timeout = 10
        
        start_time = Time.now
        response = http.request(request)
        elapsed = ((Time.now - start_time) * 1000).to_i
        
        @logger.info("Response: #{response.code} (#{elapsed}ms)")
        
        return response if response.is_a?(Net::HTTPSuccess)
        
        if response.is_a?(Net::HTTPServerError) && attempt < MAX_RETRIES - 1
          wait_time = calculate_backoff(attempt)
          sleep(wait_time)
          attempt += 1
          next
        end
        
        return response
        
      rescue Net::OpenTimeout, Net::ReadTimeout, SocketError => e
        @logger.error("Request attempt #{attempt + 1} failed: #{e.message}")
        
        if attempt < MAX_RETRIES - 1
          wait_time = calculate_backoff(attempt)
          sleep(wait_time)
          attempt += 1
        else
          raise e
        end
      end
    end
    
    raise 'Max retries exceeded'
  end
  
  def calculate_backoff(attempt)
    exponential = 2 ** attempt
    jitter = rand
    exponential + jitter
  end
  
  def get(path)
    response = do_request(:get, path)
    response.body
  end
  
  def post(path, data)
    response = do_request(:post, path, data)
    response.body
  end
end

# Usage
begin
  client = CompleteSecureAPIClient.new('https://api.example.com')
  
  # Example GET request
  user = client.get('/users/123')
  puts "User: #{user}"
  
  # Example POST request
  new_user = { name: 'John Doe', email: 'john@example.com' }
  created = client.post('/users', new_user)
  puts "Created: #{created}"
rescue StandardError => e
  puts "Error: #{e.message}"
end
```

**Why this is secure**: This client combines all security best practices: environment-based credential management, TLS 1.2+ enforcement with certificate validation, automatic retry logic with exponential backoff and jitter, structured logging, and proper error handling. Ruby's elegant syntax makes the security patterns readable and maintainable.