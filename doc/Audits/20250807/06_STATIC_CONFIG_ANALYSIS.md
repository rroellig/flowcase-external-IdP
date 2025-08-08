# FlowCase Static File Handling & Configuration Security Analysis

**Document Version:** 1.0  
**Analysis Date:** August 07, 2025  
**Application Version:** develop  
**Analysis Phase:** Static Files & Configuration Security Assessment  

---

## Executive Summary

This report analyzes security vulnerabilities in FlowCase static file handling, configuration management, and server security settings. The assessment reveals **critical configuration security issues** including missing security headers, insecure secret key generation, HTTP-only configuration, debug mode risks, and file permission vulnerabilities.

### Critical Static & Configuration Findings
- **Missing Security Headers** - No protection against common web attacks
- **Insecure Secret Key Generation** - Weak cryptographic key generation and storage
- **HTTP-Only Configuration** - No HTTPS enforcement or secure transport
- **Debug Mode in Production** - Information disclosure and security bypass risks
- **File Permission Issues** - Overly permissive file system permissions

### Risk Summary
- **2 Critical Severity** vulnerabilities requiring immediate remediation
- **5 High Severity** vulnerabilities requiring urgent attention
- **4 Medium Severity** vulnerabilities requiring planned remediation

---

## Configuration Security Analysis

### Current Configuration Architecture

The FlowCase application configuration is managed through:

```
config/
├── config.py           - Main application configuration
└── nginx/
    ├── container_template.conf  - Nginx container configuration
    └── guac_template.conf      - Guacamole proxy configuration
```

### Configuration Security Issues

1. **Hardcoded Secrets** - Sensitive values embedded in configuration files
2. **Insecure Defaults** - Production-unsafe default settings
3. **Missing Environment Separation** - No distinction between dev/prod configs
4. **Weak Key Generation** - Cryptographically insecure random number usage
5. **No Configuration Validation** - Missing input validation for config values

---

## Critical Vulnerabilities

### CVE-FC-013: Weak Secret Key Generation
**File:** [`config/config.py`](config/config.py:19)  
**Severity:** Critical  
**CVSS Score:** 8.8  
**OWASP Category:** A02 - Cryptographic Failures

**Description:**  
Flask secret keys are generated using Python's `random` module instead of cryptographically secure random number generation, making session tokens predictable and enabling session hijacking attacks.

**Vulnerable Code:**
```python
import random
import string
import os

# Weak secret key generation
if not os.path.exists("data/secret_key"):
    with open("data/secret_key", "w") as f:
        # Vulnerable: Using non-cryptographic random
        secret_key = ''.join(random.choice(string.ascii_letters + string.digits) for i in range(64))
        f.write(secret_key)

with open("data/secret_key", "r") as f:
    SECRET_KEY = f.read()

class Config:
    SECRET_KEY = SECRET_KEY  # Weak key used for session signing
    SQLALCHEMY_DATABASE_URI = 'sqlite:///data/flowcase.db'
    SQLALCHEMY_TRACK_MODIFICATIONS = False
```

**Security Issues:**
1. **Predictable Random Number Generator** - `random` module is not cryptographically secure
2. **Insufficient Entropy** - Limited character set reduces key space
3. **Insecure Storage** - Secret key stored in plaintext file
4. **No Key Rotation** - Keys never change once generated
5. **Weak File Permissions** - Secret key file readable by all processes

**Exploitation Scenarios:**

1. **Session Token Prediction:**
```python
# Attacker can predict session tokens by analyzing the PRNG
import random
import string

# If attacker knows the seed or can observe multiple tokens
def predict_secret_key():
    # Brute force or statistical analysis of weak PRNG
    for seed in range(1000000):
        random.seed(seed)
        predicted_key = ''.join(random.choice(string.ascii_letters + string.digits) for i in range(64))
        if validate_predicted_key(predicted_key):
            return predicted_key
```

2. **Session Hijacking:**
```python
# With predicted secret key, attacker can forge session tokens
from itsdangerous import URLSafeTimedSerializer

def forge_session_token(user_id, secret_key):
    serializer = URLSafeTimedSerializer(secret_key)
    return serializer.dumps({'user_id': user_id})
```

**Impact:** Complete session security bypass, user impersonation, authentication bypass, privilege escalation

**Remediation:**
```python
import secrets
import os
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64

class SecureConfigManager:
    def __init__(self):
        self.config_dir = "data"
        self.secret_key_file = os.path.join(self.config_dir, "secret_key")
        self.key_salt_file = os.path.join(self.config_dir, "key_salt")
        
    def generate_secure_secret_key(self):
        """Generate cryptographically secure secret key"""
        # Generate 256-bit (32-byte) key
        key_bytes = secrets.token_bytes(32)
        
        # Additional entropy from system sources
        system_entropy = os.urandom(16)
        
        # Combine entropy sources
        combined_entropy = key_bytes + system_entropy
        
        # Use PBKDF2 to derive final key
        salt = secrets.token_bytes(16)
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        
        derived_key = kdf.derive(combined_entropy)
        
        # Encode for storage
        key_b64 = base64.urlsafe_b64encode(derived_key).decode()
        salt_b64 = base64.urlsafe_b64encode(salt).decode()
        
        return key_b64, salt_b64
    
    def store_secret_key_securely(self, key, salt):
        """Store secret key with proper file permissions"""
        # Ensure config directory exists
        os.makedirs(self.config_dir, mode=0o700, exist_ok=True)
        
        # Write key with restrictive permissions
        with open(self.secret_key_file, 'w') as f:
            f.write(key)
        os.chmod(self.secret_key_file, 0o600)  # Owner read/write only
        
        # Store salt separately
        with open(self.key_salt_file, 'w') as f:
            f.write(salt)
        os.chmod(self.key_salt_file, 0o600)
    
    def load_or_generate_secret_key(self):
        """Load existing key or generate new one"""
        if os.path.exists(self.secret_key_file) and os.path.exists(self.key_salt_file):
            # Verify file permissions
            key_stat = os.stat(self.secret_key_file)
            if key_stat.st_mode & 0o077:  # Check if readable by group/others
                raise SecurityError("Secret key file has insecure permissions")
            
            with open(self.secret_key_file, 'r') as f:
                key = f.read().strip()
            
            # Validate key format
            if not self.validate_key_format(key):
                raise SecurityError("Invalid secret key format")
            
            return key
        else:
            # Generate new key
            key, salt = self.generate_secure_secret_key()
            self.store_secret_key_securely(key, salt)
            return key
    
    def validate_key_format(self, key):
        """Validate secret key format and entropy"""
        if not key or len(key) < 32:
            return False
        
        try:
            # Verify base64 encoding
            decoded = base64.urlsafe_b64decode(key + '==')  # Add padding
            return len(decoded) >= 32
        except Exception:
            return False
    
    def rotate_secret_key(self):
        """Rotate secret key (invalidates all sessions)"""
        # Generate new key
        new_key, new_salt = self.generate_secure_secret_key()
        
        # Backup old key
        if os.path.exists(self.secret_key_file):
            backup_file = f"{self.secret_key_file}.backup.{int(time.time())}"
            os.rename(self.secret_key_file, backup_file)
            os.chmod(backup_file, 0o600)
        
        # Store new key
        self.store_secret_key_securely(new_key, new_salt)
        
        return new_key

# Secure configuration class
class SecureConfig:
    def __init__(self):
        self.config_manager = SecureConfigManager()
        self.SECRET_KEY = self.config_manager.load_or_generate_secret_key()
        
        # Environment-based configuration
        self.ENVIRONMENT = os.environ.get('FLASK_ENV', 'production')
        self.DEBUG = self.ENVIRONMENT == 'development'
        
        # Database configuration
        self.SQLALCHEMY_DATABASE_URI = self.get_database_uri()
        self.SQLALCHEMY_TRACK_MODIFICATIONS = False
        self.SQLALCHEMY_ENGINE_OPTIONS = {
            'pool_pre_ping': True,
            'pool_recycle': 300,
        }
        
        # Security settings
        self.SESSION_COOKIE_SECURE = True
        self.SESSION_COOKIE_HTTPONLY = True
        self.SESSION_COOKIE_SAMESITE = 'Strict'
        self.PERMANENT_SESSION_LIFETIME = timedelta(hours=8)
        
        # CSRF protection
        self.WTF_CSRF_ENABLED = True
        self.WTF_CSRF_TIME_LIMIT = 3600  # 1 hour
        
    def get_database_uri(self):
        """Get database URI from environment or default"""
        db_uri = os.environ.get('DATABASE_URL')
        if db_uri:
            return db_uri
        
        # Default SQLite with secure path
        db_path = os.path.join('data', 'flowcase.db')
        return f'sqlite:///{db_path}'

# Usage
config = SecureConfig()
```

### CVE-FC-039: Missing Security Headers
**File:** [`config/nginx/container_template.conf`](config/nginx/container_template.conf:15)  
**Severity:** High  
**CVSS Score:** 7.5  
**OWASP Category:** A05 - Security Misconfiguration

**Description:**  
The Nginx configuration lacks essential security headers, leaving the application vulnerable to clickjacking, MIME-type confusion, XSS attacks, and other client-side security issues.

**Vulnerable Configuration:**
```nginx
# config/nginx/container_template.conf
server {
    listen 80;
    server_name {DOMAIN};
    
    location / {
        proxy_pass http://flowcase-web:5000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        
        # Missing security headers
    }
    
    location /static/ {
        alias /app/static/;
        # No cache control or security headers
    }
}
```

**Security Issues:**
1. **No X-Frame-Options** - Vulnerable to clickjacking attacks
2. **Missing X-Content-Type-Options** - MIME-type confusion attacks possible
3. **No X-XSS-Protection** - No browser XSS filtering
4. **Missing HSTS** - No HTTPS enforcement
5. **No CSP Headers** - No Content Security Policy protection
6. **Weak Cache Control** - Static files cached insecurely

**Attack Scenarios:**

1. **Clickjacking Attack:**
```html
<!-- Malicious site embedding FlowCase in iframe -->
<iframe src="https://flowcase.example.com/admin" 
        style="opacity:0; position:absolute; top:0; left:0; width:100%; height:100%;">
</iframe>
<button onclick="alert('Clicked!')">Click me for free gift!</button>
```

2. **MIME-Type Confusion:**
```javascript
// Attacker uploads malicious file with .txt extension
// Server serves it without proper Content-Type header
// Browser interprets as HTML/JavaScript
fetch('/uploads/malicious.txt').then(response => {
    // Browser executes as script due to missing X-Content-Type-Options
});
```

**Remediation:**
```nginx
# Secure Nginx configuration
server {
    listen 443 ssl http2;
    listen [::]:443 ssl http2;
    server_name {DOMAIN};
    
    # SSL Configuration
    ssl_certificate /etc/ssl/certs/{DOMAIN}.crt;
    ssl_certificate_key /etc/ssl/private/{DOMAIN}.key;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE-RSA-AES256-GCM-SHA512:DHE-RSA-AES256-GCM-SHA512:ECDHE-RSA-AES256-GCM-SHA384:DHE-RSA-AES256-GCM-SHA384;
    ssl_prefer_server_ciphers off;
    ssl_session_cache shared:SSL:10m;
    ssl_session_timeout 10m;
    
    # Security Headers
    add_header X-Frame-Options "DENY" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-XSS-Protection "1; mode=block" always;
    add_header Referrer-Policy "strict-origin-when-cross-origin" always;
    add_header Permissions-Policy "geolocation=(), microphone=(), camera=()" always;
    
    # HSTS (HTTP Strict Transport Security)
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;
    
    # Content Security Policy (basic - should be customized)
    add_header Content-Security-Policy "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; font-src 'self' https://fonts.gstatic.com; connect-src 'self'; frame-src 'none'; object-src 'none';" always;
    
    # Hide server information
    server_tokens off;
    
    # Main application
    location / {
        proxy_pass http://flowcase-web:5000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        
        # Proxy security headers
        proxy_set_header X-Forwarded-Host $server_name;
        proxy_redirect off;
        
        # Timeouts
        proxy_connect_timeout 30s;
        proxy_send_timeout 30s;
        proxy_read_timeout 30s;
        
        # Buffer settings
        proxy_buffering on;
        proxy_buffer_size 4k;
        proxy_buffers 8 4k;
    }
    
    # Static files with security headers and caching
    location /static/ {
        alias /app/static/;
        
        # Security headers for static content
        add_header X-Content-Type-Options "nosniff" always;
        add_header Cache-Control "public, max-age=31536000, immutable" always;
        
        # Prevent execution of scripts in static directory
        location ~* \.(js|css|png|jpg|jpeg|gif|ico|svg|woff|woff2|ttf|eot)$ {
            expires 1y;
            add_header Cache-Control "public, immutable";
            add_header X-Content-Type-Options "nosniff";
        }
        
        # Block potentially dangerous files
        location ~* \.(php|pl|py|jsp|asp|sh|cgi)$ {
            deny all;
        }
    }
    
    # Block access to sensitive files
    location ~ /\. {
        deny all;
        access_log off;
        log_not_found off;
    }
    
    location ~ ~$ {
        deny all;
        access_log off;
        log_not_found off;
    }
    
    # Rate limiting
    limit_req_zone $binary_remote_addr zone=login:10m rate=5r/m;
    limit_req_zone $binary_remote_addr zone=api:10m rate=10r/s;
    
    location /login {
        limit_req zone=login burst=3 nodelay;
        proxy_pass http://flowcase-web:5000;
        # ... other proxy settings
    }
    
    location /api/ {
        limit_req zone=api burst=20 nodelay;
        proxy_pass http://flowcase-web:5000;
        # ... other proxy settings
    }
}

# HTTP to HTTPS redirect
server {
    listen 80;
    listen [::]:80;
    server_name {DOMAIN};
    
    # Security headers even for redirects
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-Frame-Options "DENY" always;
    
    # Redirect all HTTP traffic to HTTPS
    return 301 https://$server_name$request_uri;
}
```

### CVE-FC-040: Debug Mode in Production Risk
**File:** [`config/config.py`](config/config.py:35)  
**Severity:** High  
**CVSS Score:** 8.2  
**OWASP Category:** A05 - Security Misconfiguration

**Description:**  
The application may run in debug mode in production environments, exposing sensitive information through detailed error messages, interactive debugger, and automatic code reloading.

**Vulnerable Configuration:**
```python
import os

class Config:
    # Dangerous: Debug mode determination
    DEBUG = os.environ.get('DEBUG', 'True').lower() == 'true'  # Defaults to True!
    
    # Other insecure defaults
    TESTING = False
    SECRET_KEY = 'dev-key-change-in-production'  # Hardcoded secret
    
    # Database with debug info
    SQLALCHEMY_ECHO = DEBUG  # SQL queries logged in debug mode
```

**Security Risks:**
1. **Information Disclosure** - Stack traces reveal application structure
2. **Interactive Debugger** - Remote code execution via debug console
3. **Automatic Reloading** - File system monitoring and code injection
4. **SQL Query Logging** - Database queries logged with sensitive data
5. **Performance Impact** - Debug overhead in production

**Attack Scenarios:**

1. **Information Disclosure via Error Pages:**
```python
# Debug mode exposes full stack traces
def vulnerable_endpoint():
    secret_data = get_sensitive_information()
    raise Exception(f"Error processing {secret_data}")
    # In debug mode, secret_data is visible in browser
```

2. **Interactive Debugger Exploitation:**
```python
# If Werkzeug debugger is enabled, attacker can execute code
# by triggering errors and accessing debug console
# URL: /console (if enabled)
```

**Secure Configuration:**
```python
import os
from enum import Enum

class Environment(Enum):
    DEVELOPMENT = "development"
    TESTING = "testing"
    STAGING = "staging"
    PRODUCTION = "production"

class BaseConfig:
    """Base configuration with secure defaults"""
    
    # Security-first defaults
    DEBUG = False
    TESTING = False
    
    # Secret key management
    SECRET_KEY = os.environ.get('SECRET_KEY')
    if not SECRET_KEY:
        raise ValueError("SECRET_KEY environment variable must be set")
    
    # Database configuration
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SQLALCHEMY_ECHO = False  # Never log SQL in production
    
    # Session security
    SESSION_COOKIE_SECURE = True
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = 'Strict'
    PERMANENT_SESSION_LIFETIME = timedelta(hours=8)
    
    # Security headers
    SEND_FILE_MAX_AGE_DEFAULT = 31536000  # 1 year for static files
    
    @staticmethod
    def init_app(app):
        """Initialize application with security settings"""
        # Disable server header
        @app.after_request
        def remove_server_header(response):
            response.headers.pop('Server', None)
            return response

class DevelopmentConfig(BaseConfig):
    """Development configuration"""
    DEBUG = True
    
    # Development-specific settings
    SQLALCHEMY_DATABASE_URI = 'sqlite:///dev_flowcase.db'
    
    # Override security settings for development
    SESSION_COOKIE_SECURE = False  # Allow HTTP in development
    
    @classmethod
    def init_app(cls, app):
        BaseConfig.init_app(app)
        
        # Development-specific initialization
        import logging
        logging.basicConfig(level=logging.DEBUG)

class ProductionConfig(BaseConfig):
    """Production configuration with enhanced security"""
    
    # Production database
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL') or \
        'sqlite:///data/flowcase.db'
    
    # Enhanced security for production
    PREFERRED_URL_SCHEME = 'https'
    
    @classmethod
    def init_app(cls, app):
        BaseConfig.init_app(app)
        
        # Production-specific initialization
        import logging
        from logging.handlers import RotatingFileHandler
        
        # Configure secure logging
        if not app.debug:
            file_handler = RotatingFileHandler(
                'logs/flowcase.log', 
                maxBytes=10240000, 
                backupCount=10
            )
            file_handler.setFormatter(logging.Formatter(
                '%(asctime)s %(levelname)s: %(message)s [in %(pathname)s:%(lineno)d]'
            ))
            file_handler.setLevel(logging.INFO)
            app.logger.addHandler(file_handler)
            app.logger.setLevel(logging.INFO)
            app.logger.info('FlowCase startup')

class TestingConfig(BaseConfig):
    """Testing configuration"""
    TESTING = True
    SQLALCHEMY_DATABASE_URI = 'sqlite:///:memory:'
    WTF_CSRF_ENABLED = False  # Disable CSRF for testing

# Configuration selection
config = {
    'development': DevelopmentConfig,
    'testing': TestingConfig,
    'production': ProductionConfig,
    'default': ProductionConfig  # Secure default
}

def get_config():
    """Get configuration based on environment"""
    env = os.environ.get('FLASK_ENV', 'production').lower()
    return config.get(env, config['default'])
```

---

## Static File Security Analysis

### CVE-FC-041: Insecure Static File Handling
**File:** [`static/` directory permissions](static/)  
**Severity:** Medium  
**CVSS Score:** 6.2  
**OWASP Category:** A05 - Security Misconfiguration

**Description:**  
Static files are served without proper security controls, enabling potential file upload attacks, directory traversal, and unauthorized access to sensitive files.

**Current Issues:**
1. **No File Type Restrictions** - Any file type can be uploaded/served
2. **Missing Access Controls** - No authentication for sensitive static content
3. **Directory Traversal Risk** - Potential path traversal vulnerabilities
4. **Executable File Serving** - Scripts could be executed if uploaded
5. **No Content-Type Validation** - MIME-type confusion attacks possible

**Secure Static File Configuration:**
```python
import os
import mimetypes
from werkzeug.utils import secure_filename
from flask import Flask, request, send_from_directory, abort

class SecureStaticFileHandler:
    def __init__(self, app=None):
        self.app = app
        self.allowed_extensions = {
            'images': {'png', 'jpg', 'jpeg', 'gif', 'svg', 'webp'},
            'styles': {'css'},
            'scripts': {'js'},
            'fonts': {'woff', 'woff2', 'ttf', 'eot'},
            'documents': {'pdf', 'txt'}
        }
        
        self.blocked_extensions = {
            'php', 'py', 'pl', 'sh', 'exe', 'bat', 'cmd', 'jsp', 'asp'
        }
        
        if app:
            self.init_app(app)
    
    def init_app(self, app):
        """Initialize secure static file handling"""
        app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max
        
        # Override default static file handler
        @app.route('/static/<path:filename>')
        def secure_static(filename):
            return self.serve_static_file(filename)
    
    def serve_static_file(self, filename):
        """Securely serve static files"""
        # Validate filename
        if not self.is_safe_filename(filename):
            abort(404)
        
        # Check file extension
        if not self.is_allowed_file(filename):
            abort(403)
        
        # Construct safe file path
        static_dir = os.path.join(self.app.root_path, 'static')
        file_path = os.path.join(static_dir, filename)
        
        # Prevent directory traversal
        if not self.is_safe_path(file_path, static_dir):
            abort(404)
        
        # Check if file exists
        if not os.path.isfile(file_path):
            abort(404)
        
        # Get MIME type
        mime_type, _ = mimetypes.guess_type(filename)
        
        # Serve file with security headers
        response = send_from_directory(
            static_dir, 
            filename,
            mimetype=mime_type
        )
        
        # Add security headers
        response.headers['X-Content-Type-Options'] = 'nosniff'
        response.headers['Cache-Control'] = 'public, max-age=31536000'
        
        # Prevent script execution for certain file types
        if filename.endswith(('.html', '.htm', '.xml')):
            response.headers['Content-Type'] = 'text/plain'
        
        return response
    
    def is_safe_filename(self, filename):
        """Check if filename is safe"""
        if not filename or '..' in filename or filename.startswith('/'):
            return False
        
        # Check for null bytes and other dangerous characters
        dangerous_chars = ['\x00', '\n', '\r', '\t']
        if any(char in filename for char in dangerous_chars):
            return False
        
        return True
    
    def is_allowed_file(self, filename):
        """Check if file extension is allowed"""
        if '.' not in filename:
            return False
        
        extension = filename.rsplit('.', 1)[1].lower()
        
        # Block dangerous extensions
        if extension in self.blocked_extensions:
            return False
        
        # Check against allowed extensions
        for category, extensions in self.allowed_extensions.items():
            if extension in extensions:
                return True
        
        return False
    
    def is_safe_path(self, file_path, base_dir):
        """Prevent directory traversal attacks"""
        try:
            # Resolve paths to absolute paths
            file_path = os.path.abspath(file_path)
            base_dir = os.path.abspath(base_dir)
            
            # Check if file is within base directory
            return file_path.startswith(base_dir + os.sep)
        except (OSError, ValueError):
            return False

# File upload security
class SecureFileUpload:
    def __init__(self, upload_dir='uploads'):
        self.upload_dir = upload_dir
        self.max_file_size = 5 * 1024 * 1024  # 5MB
        self.allowed_extensions = {'png', 'jpg', 'jpeg', 'gif', 'pdf', 'txt'}
        
    def save_uploaded_file(self, file, user_id):
        """Securely save uploaded file"""
        if not file or not file.filename:
            raise ValueError("No file provided")
        
        # Validate file size
        if len(file.read()) > self.max_file_size:
            raise ValueError("File too large")
        file.seek(0)  # Reset file pointer
        
        # Validate filename and extension
        filename = secure_filename(file.filename)
        if not filename or not self.is_allowed_file(filename):
            raise ValueError("Invalid file type")
        
        # Create user-specific directory
        user_dir = os.path.join(self.upload_dir, str(user_id))
        os.makedirs(user_dir, mode=0o755, exist_ok=True)
        
        # Generate unique filename
        timestamp = int(time.time())
        name, ext = os.path.splitext(filename)
        unique_filename = f"{name}_{timestamp}{ext}"
        
        file_path = os.path.join(user_dir, unique_filename)
        
        # Save file with restricted permissions
        file.save(file_path)
        os.chmod(file_path, 0o644)
        
        return unique_filename
    
    def is_allowed_file(self, filename):
        """Check if file extension is allowed"""
        return '.' in filename and \
               filename.rsplit('.', 1)[1].lower() in self.allowed_extensions
```

---

## Environment Configuration Security

### CVE-FC-042: Insecure Environment Variable Handling
**File:** [`config/config.py`](config/config.py:45)  
**Severity:** Medium  
**CVSS Score:** 5.8  
**OWASP Category:** A05 - Security Misconfiguration

**Description:**  
Environment variables containing sensitive information are not properly validated or secured, potentially exposing secrets through process lists, logs, or configuration dumps.

**Vulnerable Code:**
```python
import os

# Insecure environment variable usage
DATABASE_URL = os.environ.get('DATABASE_URL', 'sqlite:///default.db')
SECRET_KEY = os.environ.get('SECRET_KEY', 'default-secret')  # Insecure default
API_KEY = os.environ.get('API_KEY')  # No validation

# Logging configuration that might expose secrets
import logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)
logger.debug(f"Database URL: {DATABASE_URL}")  # Logs sensitive data
```

**Security Issues:**
1. **Insecure Defaults** - Fallback to insecure default values
2. **No Input Validation** - Environment variables not validated
3. **Secret Exposure in Logs** - Sensitive data logged in debug mode
4. **Process Environment Exposure** - Secrets visible in process lists
5. **No Secret Rotation** - No mechanism for updating secrets

**Secure Environment Configuration:**
```python
import os
import re
from typing import Optional, Dict, Any
import logging

class SecureEnvironmentConfig:
    """Secure environment variable management"""
    
    def __init__(self):
        self.required_vars = {
            'SECRET_KEY': self._validate_secret_key,
            'DATABASE_URL': self._validate_database_url,
        }
        
        self.optional_vars = {
            'FLASK_ENV': self._validate_environment,
            'LOG_LEVEL': self._validate_log_level,
            'MAX_CONTENT_LENGTH': self._validate_content_length,
        }
        
        self.sensitive_vars = {'SECRET_KEY', 'DATABASE_URL', 'API_KEY'}
        
    def load_configuration(self) -> Dict[str, Any]:
        """Load an