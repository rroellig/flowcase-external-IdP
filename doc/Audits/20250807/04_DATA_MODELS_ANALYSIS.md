# FlowCase Data Models Security Analysis

**Document Version:** 1.0  
**Analysis Date:** August 07, 2025  
**Application Version:** develop  
**Analysis Phase:** Data Models & Database Security Assessment  

---

## Executive Summary

This report analyzes the security vulnerabilities in FlowCase data models and database interactions. The assessment reveals **critical data security issues** including plaintext password storage, SQL injection vulnerabilities through dynamic attribute access, mass assignment vulnerabilities, and insufficient data validation constraints.

### Critical Data Model Findings
- **Plaintext Password Storage** - Sensitive authentication data stored without encryption
- **SQL Injection via Dynamic Attribute Access** - ORM bypass enabling direct SQL manipulation
- **Mass Assignment Vulnerabilities** - Uncontrolled object property modification
- **Missing Data Validation** - Insufficient constraints and input validation
- **Weak Foreign Key Relationships** - Data integrity and authorization bypass issues

### Risk Summary
- **3 Critical Severity** vulnerabilities requiring immediate remediation
- **4 High Severity** vulnerabilities requiring urgent attention
- **5 Medium Severity** vulnerabilities requiring planned remediation

---

## Data Model Architecture Analysis

### Current Database Schema

The FlowCase application uses SQLite with SQLAlchemy ORM and the following core models:

```
models/
├── user.py         - User authentication and profile data
├── droplet.py      - Container instance management
├── registry.py     - Docker registry configuration
└── log.py          - Application logging and audit trails
```

### Database Security Architecture Issues

1. **No Data Encryption** - Sensitive data stored in plaintext
2. **Insufficient Constraints** - Missing validation at database level
3. **Weak Relationships** - Foreign key constraints allow data integrity issues
4. **No Audit Trails** - Limited tracking of data modifications
5. **Missing Indexes** - Performance issues that can lead to DoS vulnerabilities

---

## Critical Vulnerabilities

### CVE-FC-014: Plaintext Sensitive Data Storage
**File:** [`models/user.py`](models/user.py:10)  
**Severity:** Critical  
**CVSS Score:** 8.5  
**OWASP Category:** A02 - Cryptographic Failures

**Description:**  
The User model stores authentication tokens and other sensitive information in plaintext, exposing critical security data in case of database compromise or unauthorized access.

**Vulnerable Schema:**
```python
class User(UserMixin, db.Model):
    __tablename__ = 'user'
    
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password = db.Column(db.String(80), nullable=False)  # Length limited
    auth_token = db.Column(db.String(80), nullable=False)  # Plaintext token
    groups = db.Column(db.String(255), nullable=False, default="user")
    
    def __repr__(self):
        return f'<User {self.username}>'
```

**Security Issues:**
1. **Plaintext Authentication Tokens** - Tokens readable in database dumps
2. **Limited Password Hash Length** - May truncate secure hash algorithms
3. **No Token Encryption** - Database compromise exposes all active sessions
4. **Missing Sensitive Data Markers** - No indication of sensitive fields
5. **No Token Rotation** - Tokens persist indefinitely

**Data Exposure Scenarios:**
```sql
-- Database compromise exposes all authentication tokens
SELECT username, auth_token FROM user;

-- Backup files contain plaintext sensitive data
-- Log files may contain sensitive data during debugging
-- Memory dumps expose plaintext tokens
```

**Impact:** Complete authentication bypass, session hijacking, user impersonation, data breach

**Remediation:**
```python
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64
import bcrypt
import secrets
from datetime import datetime, timedelta

class SecureUser(UserMixin, db.Model):
    __tablename__ = 'user'
    
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False, index=True)
    email = db.Column(db.String(120), unique=True, nullable=False, index=True)
    
    # Secure password storage
    password_hash = db.Column(db.Text, nullable=False)  # Allow longer hashes
    password_salt = db.Column(db.String(32), nullable=False)
    password_iterations = db.Column(db.Integer, nullable=False, default=100000)
    
    # Encrypted authentication data
    auth_token_encrypted = db.Column(db.Text, nullable=True)
    token_key_salt = db.Column(db.String(32), nullable=True)
    token_created_at = db.Column(db.DateTime, nullable=True)
    token_expires_at = db.Column(db.DateTime, nullable=True)
    
    # Account security
    failed_login_attempts = db.Column(db.Integer, default=0)
    account_locked_until = db.Column(db.DateTime, nullable=True)
    last_login_at = db.Column(db.DateTime, nullable=True)
    last_login_ip = db.Column(db.String(45), nullable=True)  # IPv6 support
    
    # Password security
    password_changed_at = db.Column(db.DateTime, default=datetime.utcnow)
    password_reset_token = db.Column(db.String(64), nullable=True)
    password_reset_expires = db.Column(db.DateTime, nullable=True)
    
    # Audit fields
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    is_active = db.Column(db.Boolean, default=True, nullable=False)
    
    # Relationships
    droplets = db.relationship('DropletInstance', backref='owner', lazy='dynamic')
    roles = db.relationship('Role', secondary='user_roles', backref='users')
    
    def set_password(self, password: str):
        """Set password with secure hashing"""
        if len(password) < 8:
            raise ValueError("Password must be at least 8 characters")
        
        # Generate salt and hash password
        salt = bcrypt.gensalt(rounds=12)
        password_hash = bcrypt.hashpw(password.encode('utf-8'), salt)
        
        self.password_hash = password_hash.decode('utf-8')
        self.password_salt = salt.decode('utf-8')
        self.password_changed_at = datetime.utcnow()
        
        # Invalidate existing tokens when password changes
        self.invalidate_auth_tokens()
    
    def check_password(self, password: str) -> bool:
        """Verify password against stored hash"""
        if not self.password_hash:
            return False
        
        try:
            return bcrypt.checkpw(
                password.encode('utf-8'),
                self.password_hash.encode('utf-8')
            )
        except Exception:
            return False
    
    def generate_auth_token(self) -> str:
        """Generate and store encrypted authentication token"""
        # Generate secure token
        token = secrets.token_hex(32)
        
        # Create encryption key from user-specific data
        salt = secrets.token_bytes(16)
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        key = base64.urlsafe_b64encode(kdf.derive(f"{self.id}:{self.username}".encode()))
        
        # Encrypt token
        f = Fernet(key)
        encrypted_token = f.encrypt(token.encode())
        
        # Store encrypted data
        self.auth_token_encrypted = base64.b64encode(encrypted_token).decode()
        self.token_key_salt = base64.b64encode(salt).decode()
        self.token_created_at = datetime.utcnow()
        self.token_expires_at = datetime.utcnow() + timedelta(hours=24)
        
        db.session.commit()
        return token
    
    def validate_auth_token(self, token: str) -> bool:
        """Validate authentication token"""
        if not self.auth_token_encrypted or not self.token_key_salt:
            return False
        
        # Check expiration
        if self.token_expires_at and datetime.utcnow() > self.token_expires_at:
            self.invalidate_auth_tokens()
            return False
        
        try:
            # Recreate encryption key
            salt = base64.b64decode(self.token_key_salt.encode())
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=salt,
                iterations=100000,
            )
            key = base64.urlsafe_b64encode(kdf.derive(f"{self.id}:{self.username}".encode()))
            
            # Decrypt stored token
            f = Fernet(key)
            encrypted_token = base64.b64decode(self.auth_token_encrypted.encode())
            stored_token = f.decrypt(encrypted_token).decode()
            
            return secrets.compare_digest(token, stored_token)
            
        except Exception:
            return False
    
    def invalidate_auth_tokens(self):
        """Invalidate all authentication tokens"""
        self.auth_token_encrypted = None
        self.token_key_salt = None
        self.token_created_at = None
        self.token_expires_at = None
        db.session.commit()
    
    def is_account_locked(self) -> bool:
        """Check if account is locked"""
        if not self.account_locked_until:
            return False
        return datetime.utcnow() < self.account_locked_until
    
    def increment_failed_login(self):
        """Handle failed login attempt"""
        self.failed_login_attempts += 1
        
        # Progressive lockout
        if self.failed_login_attempts >= 5:
            lockout_minutes = min(30 * (2 ** (self.failed_login_attempts - 5)), 1440)  # Max 24 hours
            self.account_locked_until = datetime.utcnow() + timedelta(minutes=lockout_minutes)
        
        db.session.commit()
    
    def reset_failed_login(self):
        """Reset failed login attempts after successful login"""
        self.failed_login_attempts = 0
        self.account_locked_until = None
        self.last_login_at = datetime.utcnow()
        db.session.commit()
```

### CVE-FC-030: SQL Injection via Dynamic Attribute Access
**File:** [`models/droplet.py`](models/droplet.py:25)  
**Severity:** Critical  
**CVSS Score:** 9.2  
**OWASP Category:** A03 - Injection

**Description:**  
The DropletInstance model uses dynamic attribute access and string formatting in queries, enabling SQL injection attacks that bypass ORM protections.

**Vulnerable Code:**
```python
class DropletInstance(db.Model):
    __tablename__ = 'droplet_instance'
    
    @classmethod
    def search_instances(cls, user_id, filters):
        """Vulnerable search method"""
        query = cls.query.filter_by(user_id=user_id)
        
        # Vulnerable: Dynamic attribute access
        for field, value in filters.items():
            if hasattr(cls, field):
                # SQL injection possible through field names
                query = query.filter(getattr(cls, field) == value)
        
        return query.all()
    
    @classmethod
    def get_by_custom_query(cls, where_clause):
        """Extremely vulnerable method"""
        # Direct SQL injection
        sql = f"SELECT * FROM droplet_instance WHERE {where_clause}"
        return db.session.execute(text(sql)).fetchall()
    
    def update_attributes(self, **kwargs):
        """Mass assignment vulnerability"""
        for key, value in kwargs.items():
            if hasattr(self, key):
                setattr(self, key, value)  # No validation
        db.session.commit()
```

**Exploitation Scenarios:**

1. **Attribute-based SQL Injection:**
```python
# Malicious filter injection
filters = {
    "name": "test' OR '1'='1",
    "status": "'; DROP TABLE droplet_instance; --"
}
DropletInstance.search_instances(user_id, filters)
```

2. **Direct SQL Injection:**
```python
# Direct query manipulation
where_clause = "1=1; INSERT INTO droplet_instance (name, user_id) VALUES ('malicious', 1); --"
DropletInstance.get_by_custom_query(where_clause)
```

3. **Mass Assignment Attack:**
```python
# Privilege escalation via mass assignment
malicious_data = {
    "user_id": 1,  # Change ownership
    "status": "admin",
    "created_at": "2020-01-01"  # Modify audit fields
}
instance.update_attributes(**malicious_data)
```

**Impact:** Database compromise, data manipulation, privilege escalation, data exfiltration

**Remediation:**
```python
from sqlalchemy import and_, or_, text
from typing import Dict, List, Any, Optional
import re

class SecureDropletInstance(db.Model):
    __tablename__ = 'droplet_instance'
    
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    name = db.Column(db.String(50), nullable=False)
    image = db.Column(db.String(200), nullable=False)
    status = db.Column(db.Enum('creating', 'running', 'stopped', 'error'), default='creating')
    container_id = db.Column(db.String(64), nullable=True)
    
    # Secure foreign key with proper constraints
    user_id = db.Column(db.Integer, db.ForeignKey('user.id', ondelete='CASCADE'), nullable=False)
    
    # Resource limits
    cpu_limit = db.Column(db.Float, default=1.0)
    memory_limit = db.Column(db.Integer, default=512)  # MB
    
    # Audit fields
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Define allowed search fields
    SEARCHABLE_FIELDS = {
        'name': str,
        'status': str,
        'image': str,
        'created_at': datetime
    }
    
    # Define updatable fields for users
    USER_UPDATABLE_FIELDS = {'name', 'cpu_limit', 'memory_limit'}
    ADMIN_UPDATABLE_FIELDS = USER_UPDATABLE_FIELDS | {'status', 'image'}
    
    @classmethod
    def secure_search(cls, user_id: int, filters: Dict[str, Any], 
                     is_admin: bool = False) -> List['SecureDropletInstance']:
        """Secure search with validated filters"""
        # Base query with user isolation
        query = cls.query.filter_by(user_id=user_id)
        
        # Validate and apply filters
        for field, value in filters.items():
            if field not in cls.SEARCHABLE_FIELDS:
                continue  # Ignore invalid fields
            
            expected_type = cls.SEARCHABLE_FIELDS[field]
            
            # Type validation
            if not isinstance(value, expected_type):
                try:
                    if expected_type == str:
                        value = str(value)[:100]  # Limit length
                    elif expected_type == datetime:
                        value = datetime.fromisoformat(value)
                except (ValueError, TypeError):
                    continue  # Skip invalid values
            
            # Apply filter using ORM
            column = getattr(cls, field)
            if isinstance(value, str):
                # Use LIKE for string searches with parameterization
                query = query.filter(column.like(f"%{value}%"))
            else:
                query = query.filter(column == value)
        
        return query.all()
    
    @classmethod
    def get_user_instances(cls, user_id: int, 
                          limit: int = 50, 
                          offset: int = 0) -> List['SecureDropletInstance']:
        """Get user instances with pagination"""
        return cls.query.filter_by(user_id=user_id)\
                       .order_by(cls.created_at.desc())\
                       .limit(limit)\
                       .offset(offset)\
                       .all()
    
    def secure_update(self, updates: Dict[str, Any], 
                     user_id: int, is_admin: bool = False) -> bool:
        """Secure attribute update with validation"""
        # Check ownership
        if self.user_id != user_id and not is_admin:
            raise PermissionError("Access denied")
        
        # Determine allowed fields
        allowed_fields = self.ADMIN_UPDATABLE_FIELDS if is_admin else self.USER_UPDATABLE_FIELDS
        
        # Validate and apply updates
        for field, value in updates.items():
            if field not in allowed_fields:
                continue  # Skip disallowed fields
            
            # Field-specific validation
            if field == 'name':
                if not isinstance(value, str) or not re.match(r'^[a-zA-Z0-9_-]{1,50}$', value):
                    raise ValueError("Invalid name format")
            
            elif field == 'cpu_limit':
                if not isinstance(value, (int, float)) or not 0.1 <= value <= 4.0:
                    raise ValueError("CPU limit must be between 0.1 and 4.0")
            
            elif field == 'memory_limit':
                if not isinstance(value, int) or not 128 <= value <= 2048:
                    raise ValueError("Memory limit must be between 128MB and 2GB")
            
            elif field == 'status':
                valid_statuses = ['creating', 'running', 'stopped', 'error']
                if value not in valid_statuses:
                    raise ValueError(f"Status must be one of: {valid_statuses}")
            
            # Apply validated update
            setattr(self, field, value)
        
        self.updated_at = datetime.utcnow()
        db.session.commit()
        return True
    
    def to_dict(self, include_sensitive: bool = False) -> Dict[str, Any]:
        """Convert to dictionary with optional sensitive data"""
        data = {
            'id': self.id,
            'name': self.name,
            'image': self.image,
            'status': self.status,
            'cpu_limit': self.cpu_limit,
            'memory_limit': self.memory_limit,
            'created_at': self.created_at.isoformat(),
            'updated_at': self.updated_at.isoformat()
        }
        
        if include_sensitive:
            data.update({
                'container_id': self.container_id,
                'user_id': self.user_id
            })
        
        return data
```

### CVE-FC-031: Mass Assignment Vulnerabilities
**File:** [`models/user.py`](models/user.py:35)  
**Severity:** High  
**CVSS Score:** 8.1  
**OWASP Category:** A01 - Broken Access Control

**Description:**  
Models allow unrestricted attribute assignment, enabling attackers to modify sensitive fields including user permissions, ownership, and audit data.

**Vulnerable Code:**
```python
class User(UserMixin, db.Model):
    def update_profile(self, **kwargs):
        """Vulnerable mass assignment"""
        for key, value in kwargs.items():
            if hasattr(self, key):
                setattr(self, key, value)  # No field restrictions
        db.session.commit()

# Usage in routes
@app.route('/profile/update', methods=['POST'])
@login_required
def update_profile():
    # Vulnerable: All form data passed directly
    current_user.update_profile(**request.form.to_dict())
    return redirect('/profile')
```

**Attack Scenarios:**
```python
# Privilege escalation
POST /profile/update
{
    "username": "admin",
    "groups": "admin,superuser",
    "id": 1  # Change user ID
}

# Audit trail manipulation
POST /profile/update
{
    "created_at": "2020-01-01T00:00:00",
    "last_login": "2025-01-01T00:00:00"
}

# Authentication bypass
POST /profile/update
{
    "auth_token": "known_admin_token",
    "password": "known_hash"
}
```

**Secure Implementation:**
```python
class SecureUser(UserMixin, db.Model):
    # Define field access levels
    PUBLIC_FIELDS = {'username', 'email'}
    USER_EDITABLE_FIELDS = {'email', 'display_name', 'timezone'}
    ADMIN_EDITABLE_FIELDS = USER_EDITABLE_FIELDS | {'groups', 'is_active'}
    SYSTEM_FIELDS = {'id', 'created_at', 'updated_at', 'password_hash', 'auth_token_encrypted'}
    
    def secure_update(self, updates: Dict[str, Any], 
                     current_user_id: int, is_admin: bool = False) -> Dict[str, Any]:
        """Secure update with field restrictions"""
        # Check permissions
        if self.id != current_user_id and not is_admin:
            raise PermissionError("Cannot modify other users")
        
        # Determine allowed fields
        allowed_fields = self.ADMIN_EDITABLE_FIELDS if is_admin else self.USER_EDITABLE_FIELDS
        
        updated_fields = {}
        errors = {}
        
        for field, value in updates.items():
            # Skip system fields
            if field in self.SYSTEM_FIELDS:
                errors[field] = "System field cannot be modified"
                continue
            
            # Check field permissions
            if field not in allowed_fields:
                errors[field] = "Field not editable"
                continue
            
            # Field-specific validation
            try:
                validated_value = self._validate_field(field, value)
                setattr(self, field, validated_value)
                updated_fields[field] = validated_value
            except ValueError as e:
                errors[field] = str(e)
        
        if updated_fields:
            self.updated_at = datetime.utcnow()
            db.session.commit()
        
        return {
            'updated_fields': updated_fields,
            'errors': errors,
            'success': len(errors) == 0
        }
    
    def _validate_field(self, field: str, value: Any) -> Any:
        """Validate individual field values"""
        if field == 'email':
            if not re.match(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', value):
                raise ValueError("Invalid email format")
            return value.lower().strip()
        
        elif field == 'username':
            if not re.match(r'^[a-zA-Z0-9_-]{3,50}$', value):
                raise ValueError("Username must be 3-50 characters, alphanumeric, underscore, or dash")
            return value.strip()
        
        elif field == 'display_name':
            if len(value) > 100:
                raise ValueError("Display name too long")
            return html.escape(value.strip())
        
        elif field == 'groups':
            # Admin-only field
            valid_groups = ['user', 'admin', 'moderator']
            groups = [g.strip() for g in value.split(',')]
            for group in groups:
                if group not in valid_groups:
                    raise ValueError(f"Invalid group: {group}")
            return ','.join(groups)
        
        return value
```

---

## Database Constraint Analysis

### Missing Data Validation Constraints

**Current Issues:**
1. **No Check Constraints** - Database doesn't enforce business rules
2. **Missing Unique Constraints** - Duplicate data allowed
3. **Insufficient Length Limits** - No protection against oversized data
4. **No Referential Integrity** - Orphaned records possible
5. **Missing Default Values** - Inconsistent data states

**Secure Database Schema:**
```python
from sqlalchemy import CheckConstraint, UniqueConstraint, Index

class SecureDropletInstance(db.Model):
    __tablename__ = 'droplet_instance'
    
    id = db.Column(db.String(36), primary_key=True)
    name = db.Column(db.String(50), nullable=False)
    image = db.Column(db.String(200), nullable=False)
    status = db.Column(db.String(20), nullable=False, default='creating')
    
    # Resource constraints with validation
    cpu_limit = db.Column(db.Float, nullable=False, default=1.0)
    memory_limit = db.Column(db.Integer, nullable=False, default=512)
    
    # Foreign key with proper constraints
    user_id = db.Column(
        db.Integer, 
        db.ForeignKey('user.id', ondelete='CASCADE', onupdate='CASCADE'),
        nullable=False,
        index=True
    )
    
    # Audit fields
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    
    # Database constraints
    __table_args__ = (
        # Unique constraint for user + name combination
        UniqueConstraint('user_id', 'name', name='uq_user_droplet_name'),
        
        # Check constraints for business rules
        CheckConstraint('cpu_limit >= 0.1 AND cpu_limit <= 4.0', name='ck_cpu_limit'),
        CheckConstraint('memory_limit >= 128 AND memory_limit <= 2048', name='ck_memory_limit'),
        CheckConstraint("status IN ('creating', 'running', 'stopped', 'error')", name='ck_status'),
        CheckConstraint('length(name) >= 1 AND length(name) <= 50', name='ck_name_length'),
        
        # Indexes for performance and security
        Index('ix_droplet_user_status', 'user_id', 'status'),
        Index('ix_droplet_created', 'created_at'),
    )

class SecureUser(UserMixin, db.Model):
    __tablename__ = 'user'
    
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), nullable=False, unique=True)
    email = db.Column(db.String(120), nullable=False, unique=True)
    
    # Secure password storage
    password_hash = db.Column(db.Text, nullable=False)
    password_salt = db.Column(db.String(32), nullable=False)
    
    # Account security
    failed_login_attempts = db.Column(db.Integer, nullable=False, default=0)
    is_active = db.Column(db.Boolean, nullable=False, default=True)
    
    # Audit fields
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    
    __table_args__ = (
        # Check constraints
        CheckConstraint('length(username) >= 3 AND length(username) <= 50', name='ck_username_length'),
        CheckConstraint('failed_login_attempts >= 0', name='ck_failed_attempts'),
        CheckConstraint("email LIKE '%@%'", name='ck_email_format'),
        
        # Indexes
        Index('ix_user_username', 'username'),
        Index('ix_user_email', 'email'),
        Index('ix_user_active', 'is_active'),
    )
```

---

## Data Integrity Analysis

### CVE-FC-032: Weak Foreign Key Relationships
**File:** [`models/droplet.py`](models/droplet.py:15)  
**Severity:** Medium  
**CVSS Score:** 6.5  
**OWASP Category:** A04 - Insecure Design

**Description:**  
Foreign key relationships lack proper constraints and cascading rules, enabling data integrity issues and potential authorization bypasses.

**Vulnerable Relationships:**
```python
class DropletInstance(db.Model):
    # Weak foreign key - no cascading rules
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    
    # No relationship definition
    # Orphaned records possible when user is deleted
```

**Data Integrity Issues:**
1. **Orphaned Records** - Droplets remain when users are deleted
2. **Referential Integrity** - Invalid user_id values possible
3. **Cascade Behavior** - No defined behavior for related record changes
4. **Authorization Bypass** - Orphaned records may bypass access controls

**Secure Relationships:**
```python
class SecureDropletInstance(db.Model):
    # Secure foreign key with proper constraints
    user_id = db.Column(
        db.Integer,
        db.ForeignKey('user.id', ondelete='CASCADE', onupdate='CASCADE'),
        nullable=False,
        index=True
    )
    
    # Explicit relationship with security considerations
    owner = db.relationship(
        'User',
        backref=db.backref('droplets', lazy='dynamic', cascade='all, delete-orphan'),
        foreign_keys=[user_id]
    )
    
    @validates('user_id')
    def validate_user_id(self, key, user_id):
        """Validate user exists and is active"""
        user = User.query.get(user_id)
        if not user or not user.is_active:
            raise ValueError("Invalid or inactive user")
        return user_id

# Role-based access control with proper relationships
class Role(db.Model):
    __tablename__ = 'roles'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), unique=True, nullable=False)
    description = db.Column(db.String(255))

class UserRole(db.Model):
    __tablename__ = 'user_roles'
    user_id = db.Column(db.Integer, db.ForeignKey('user.id', ondelete='CASCADE'), primary_key=True)
    role_id = db.Column(db.Integer, db.ForeignKey('roles.id', ondelete='CASCADE'), primary_key=True)
    assigned_at = db.Column(db.DateTime, default=datetime.utcnow)
    assigned_by = db.Column(db.Integer, db.ForeignKey('user.id'))
    
    # Relationships
    user = db.relationship('User', foreign_keys=[user_id])
    role = db.relationship('Role')
    assigner = db.relationship('User', foreign_keys=[assigned_by])
```

---

## Audit Trail Implementation

### CVE-FC-033: Missing Audit Trails
**File:** [`models/log.py`](models/log.py:10)  
**Severity:** Medium  
**CVSS Score:** 5.8  
**OWASP Category:** A09 - Security Logging and Monitoring Failures

**Description:**  
The application lacks comprehensive audit trails for data modifications, making it difficult to detect unauthorized changes an