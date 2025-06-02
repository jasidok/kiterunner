# Kiterunner Upgrades

This document describes the new features and upgrades added to Kiterunner.

## Table of Contents

1. [Token-aware GraphQL Support](#token-aware-graphql-support)
2. [Rate-limit Evasions](#rate-limit-evasions)
3. [Payload Scripting](#payload-scripting)
4. [JWT Brute Mode](#jwt-brute-mode)
5. [Replay Engine](#replay-engine)

## Token-aware GraphQL Support

Kiterunner now includes enhanced support for GraphQL APIs, with automatic Bearer token injection and introspection scanning.

### Features

- **Auto-inject Bearer tokens**: Automatically injects Bearer tokens into GraphQL requests
- **Introspection scanning**: Automatically scans GraphQL endpoints for introspection capabilities
- **GraphQL detection**: Automatically detects GraphQL endpoints based on path, content type, and request body

### Configuration

```yaml
graphql:
  auto_inject_token: true
  token: "your-bearer-token"
  scan_introspection: true
```

### Usage

```bash
# Scan a GraphQL endpoint with token injection
kr scan https://example.com/graphql --graphql-token "your-bearer-token"

# Scan a GraphQL endpoint with introspection
kr scan https://example.com/graphql --graphql-introspection
```

## Rate-limit Evasions

Kiterunner now includes advanced rate-limit evasion techniques to help bypass rate limiting mechanisms.

### Features

- **X-Forwarded-For rotation**: Automatically rotates X-Forwarded-For headers to evade IP-based rate limiting
- **Delay injection**: Adds configurable delays between requests with random jitter to avoid detection
- **Header randomization**: Randomizes common headers to mimic different clients

### Configuration

```yaml
stealth:
  rotate_x_forwarded_for: true
  x_forwarded_for_ips:
    - "203.0.113.1"
    - "198.51.100.1"
    - "192.0.2.1"
  delay_range: [50, 200]  # Min and max delay in milliseconds
  delay_jitter: true      # Add random jitter to delays
```

### Usage

```bash
# Enable rate-limit evasions
kr scan https://example.com --stealth --xff-rotation --delay-jitter
```

## Payload Scripting

Kiterunner now includes a parameter injection engine that uses templates to generate payloads for various types of injections.

### Features

- **Template-based payloads**: Uses JSON templates to define payloads for different types of injections
- **Multiple injection points**: Supports injecting payloads into query parameters, headers, body parameters, and path parameters
- **Categorized payloads**: Organizes payloads by category (SQL injection, XSS, command injection, etc.)

### Configuration

Payload templates are defined in `payloadTemplates.json`:

```json
[
  {
    "name": "SQL Injection - Basic",
    "description": "Basic SQL injection payloads",
    "category": "sql-injection",
    "payloads": [
      "'", "\"", "' OR '1'='1", "' OR 1=1--"
    ],
    "enabled": true,
    "risk": "high"
  },
  {
    "name": "XSS - Basic",
    "description": "Basic cross-site scripting payloads",
    "category": "xss",
    "payloads": [
      "<script>alert(1)</script>",
      "<img src=x onerror=alert(1)>"
    ],
    "enabled": true,
    "risk": "medium"
  }
]
```

### Usage

```bash
# Use payload templates for injection
kr scan https://example.com --payload-templates payloadTemplates.json

# Use specific payload categories
kr scan https://example.com --payload-categories sql-injection,xss
```

## JWT Brute Mode

Kiterunner now includes a JWT brute force mode that can manipulate JWT tokens to bypass authentication.

### Features

- **alg=none attack**: Attempts to bypass signature verification by setting the algorithm to "none"
- **Weak HMAC keys**: Tries common secrets for HMAC signing
- **Header injection**: Injects malicious values into JWT headers
- **Payload injection**: Modifies JWT payloads to escalate privileges

### Configuration

```yaml
jwt_brute:
  enable_none_alg: true
  enable_weak_hmac: true
  enable_header_injection: true
  enable_payload_injection: true
  common_secrets:
    - "secret"
    - "key"
    - "password"
  payload_injections:
    - admin: true
    - role: "admin"
```

### Usage

```bash
# Use JWT brute mode with a token
kr scan https://example.com --jwt-brute --jwt-token "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."

# Use JWT brute mode with specific techniques
kr scan https://example.com --jwt-brute --jwt-none-alg --jwt-weak-hmac
```

## Replay Engine

Kiterunner now includes a replay engine that can send bypassed requests to follow-up fuzzers for deeper analysis.

### Features

- **Request storage**: Stores bypassed requests for later analysis
- **FFUF integration**: Sends bypassed requests to FFUF for further fuzzing
- **Param Miner integration**: Sends bypassed requests to Param Miner for parameter discovery
- **Custom fuzzer support**: Supports sending requests to custom fuzzers

### Configuration

```yaml
replay:
  enabled: true
  output_directory: "replay_output"
  ffuf_enabled: true
  ffuf_path: "ffuf"
  ffuf_wordlist: "/usr/share/wordlists/dirb/common.txt"
  param_miner_enabled: false
  param_miner_path: ""
  custom_fuzzer_enabled: false
  custom_fuzzer_command: ""
```

### Usage

```bash
# Enable replay engine
kr scan https://example.com --replay --replay-output replay_output

# Enable specific fuzzers
kr scan https://example.com --replay --ffuf --ffuf-wordlist wordlist.txt
```

## Integration Example

Here's an example of how to use all the new features together:

```bash
kr scan https://example.com \
  --graphql-token "your-bearer-token" \
  --graphql-introspection \
  --stealth \
  --xff-rotation \
  --delay-jitter \
  --payload-templates payloadTemplates.json \
  --payload-categories sql-injection,xss \
  --jwt-brute \
  --jwt-token "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..." \
  --replay \
  --ffuf \
  --ffuf-wordlist wordlist.txt
```

This command will:
1. Scan the target with GraphQL support and token injection
2. Use rate-limit evasion techniques
3. Apply payload templates for SQL injection and XSS
4. Attempt JWT token manipulation
5. Send bypassed requests to FFUF for further fuzzing