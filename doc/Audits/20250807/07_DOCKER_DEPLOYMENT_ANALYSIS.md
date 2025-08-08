# FlowCase Docker & Deployment Security Analysis

**Document Version:** 1.0  
**Analysis Date:** August 07, 2025  
**Application Version:** develop  
**Analysis Phase:** Docker & Deployment Configuration Security Assessment  

---

## Executive Summary

This report analyzes critical security vulnerabilities in FlowCase Docker configuration and deployment setup. The assessment reveals **extremely critical container security issues** including Docker socket mount container escape risks, containers running as root user, insecure Docker CLI installation, network configuration vulnerabilities, and missing container resource limits that enable complete host system compromise.

### Critical Docker & Deployment Findings
- **Docker Socket Mount Container Escape** - Direct host system compromise vector
- **Root User Container Execution** - Privilege escalation and container escape risks
- **Insecure Docker CLI Installation** - Malicious image execution capabilities
- **Network Configuration Issues** - Insufficient container isolation
- **Missing Container Resource Limits** - DoS and resource exhaustion attacks

### Risk Summary
- **4 Critical Severity** vulnerabilities requiring immediate remediation
- **3 High Severity** vulnerabilities requiring urgent attention
- **2 Medium Severity** vulnerabilities requiring planned remediation

---

## Docker Architecture Analysis

### Current Docker Configuration

The FlowCase application uses Docker Compose with the following architecture:

```
docker-compose.yml          - Main production configuration
docker-compose.dev.yml      - Development environment
web.Dockerfile             - Application container build
.dockerignore              - Build context exclusions
```

### Container Security Architecture Issues

1. **Privileged Container Access** - Containers run with excessive privileges
2. **Host System Exposure** - Docker socket mounted directly into containers
3. **No Security Profiles** - Missing AppArmor/SELinux security constraints
4. **Insecure Network Configuration** - Containers share host network stack
5. **Missing Resource Constraints** - No CPU/memory limits defined

---

## Critical Vulnerabilities

### CVE-FC-007: Docker Socket Mount Container Escape
**File:** [`docker-compose.yml`](docker-compose.yml:25)  
**Severity:** Critical  
**CVSS Score:** 10.0  
**OWASP Category:** A06 - Vulnerable and Outdated Components

**Description:**  
The Docker socket (`/var/run/docker.sock`) is mounted directly into the application container, providing unrestricted access to the Docker daemon and enabling complete host system compromise through container escape techniques.

**Vulnerable Configuration:**
```yaml
# docker-compose.yml
version: '3.8'
services:
  web:
    build:
      context: .
      dockerfile: web.Dockerfile
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock  # CRITICAL VULNERABILITY
      - ./data:/app/data
    ports:
      - "5000:5000"
    environment:
      - FLASK_ENV=production
```

**Attack Scenarios:**

1. **Direct Host System Access:**
```bash
# From within the compromised container
docker run -it --rm -v /:/host ubuntu chroot /host /bin/bash
# Attacker now has root access to host system
```

2. **Privileged Container Creation:**
```bash
# Create privileged container with host access
docker run -it --rm --privileged -v /:/host ubuntu
# Mount host filesystem and escape container boundaries
```

3. **Host Process Manipulation:**
```bash
# Access host processes from container
docker run -it --rm --pid=host ubuntu
# Can kill host processes, access host memory
```

4. **Network Stack Hijacking:**
```bash
# Access host network stack
docker run -it --rm --net=host ubuntu
# Can intercept all network traffic, bind to host ports
```

**Impact:** Complete host system compromise, data exfiltration, malware installation, lateral movement, infrastructure takeover

**Remediation:**
```yaml
# Secure Docker Compose configuration
version: '3.8'

services:
  web:
    build:
      context: .
      dockerfile: web.Dockerfile
    # Remove Docker socket mount - use Docker API proxy instead
    volumes:
      - ./data:/app/data:rw
      - app-logs:/app/logs:rw
    ports:
      - "127.0.0.1:5000:5000"  # Bind to localhost only
    environment:
      - FLASK_ENV=production
      - DOCKER_API_ENDPOINT=http://docker-proxy:2375
    networks:
      - app-network
    # Security constraints
    security_opt:
      - no-new-privileges:true
      - apparmor:docker-default
    cap_drop:
      - ALL
    cap_add:
      - CHOWN
      - SETUID
      - SETGID
    read_only: true
    tmpfs:
      - /tmp:noexec,nosuid,size=100m
    # Resource limits
    deploy:
      resources:
        limits:
          cpus: '1.0'
          memory: 512M
        reservations:
          cpus: '0.5'
          memory: 256M
    # Health check
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:5000/health"]
      interval: 30s
      timeout: 10s
      retries: 3
      start_period: 40s
    # Restart policy
    restart: unless-stopped
    # User specification
    user: "1000:1000"

  # Secure Docker API proxy
  docker-proxy:
    image: tecnativa/docker-socket-proxy:latest
    environment:
      - CONTAINERS=1
      - IMAGES=1
      - NETWORKS=0
      - VOLUMES=0
      - SERVICES=0
      - SWARM=0
      - SYSTEM=0
      - EVENTS=0
      - POST=1  # Allow container creation
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock:ro
    networks:
      - app-network
    security_opt:
      - no-new-privileges:true
    read_only: true
    tmpfs:
      - /tmp:noexec,nosuid,size=10m

networks:
  app-network:
    driver: bridge
    internal: false
    ipam:
      config:
        - subnet: 172.20.0.0/24

volumes:
  app-logs:
    driver: local
```

### CVE-FC-043: Root User Container Execution
**File:** [`web.Dockerfile`](web.Dockerfile:15)  
**Severity:** Critical  
**CVSS Score:** 9.3  
**OWASP Category:** A05 - Security Misconfiguration

**Description:**  
Containers run as the root user by default, providing unnecessary privileges that can be exploited for container escape, privilege escalation, and host system compromise.

**Vulnerable Dockerfile:**
```dockerfile
FROM python:3.9-slim

# Running as root user (default)
WORKDIR /app

# Install system packages as root
RUN apt-get update && apt-get install -y \
    curl \
    docker.io \
    && rm -rf /var/lib/apt/lists/*

# Copy application files
COPY requirements.txt .
RUN pip install -r requirements.txt

COPY . .

# Expose port
EXPOSE 5000

# Run application as root (VULNERABLE)
CMD ["python", "run.py"]
```

**Security Issues:**
1. **Unnecessary Root Privileges** - Application doesn't need root access
2. **Docker CLI Installation** - Enables container manipulation from within container
3. **No User Creation** - Missing non-privileged user account
4. **Writable Root Filesystem** - No read-only filesystem protection
5. **Missing Security Hardening** - No security-focused base image

**Attack Scenarios:**

1. **Container Escape via Root Privileges:**
```bash
# From within root container
mount -t proc proc /proc
echo 1 > /proc/sys/kernel/sysrq
# Can manipulate kernel parameters and escape container
```

2. **Host File System Access:**
```bash
# Root user can access mounted volumes with full permissions
# Can modify host files if volumes are mounted
```

3. **Process Privilege Escalation:**
```bash
# Root container can exploit kernel vulnerabilities
# Can use capabilities to escape container boundaries
```

**Secure Dockerfile:**
```dockerfile
# Use minimal, security-focused base image
FROM python:3.9-slim-bullseye

# Create non-root user early
RUN groupadd -r appuser && useradd -r -g appuser -d /app -s /bin/bash appuser

# Install system dependencies as root (minimal set)
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && apt-get clean

# Create application directory with proper ownership
WORKDIR /app
RUN chown appuser:appuser /app

# Switch to non-root user for application setup
USER appuser

# Install Python dependencies
COPY --chown=appuser:appuser requirements.txt .
RUN pip install --user --no-cache-dir -r requirements.txt

# Copy application code
COPY --chown=appuser:appuser . .

# Create necessary directories
RUN mkdir -p /app/data /app/logs && \
    chmod 755 /app/data /app/logs

# Security hardening
# Remove unnecessary packages and files
USER root
RUN apt-get remove -y --purge \
    && apt-get autoremove -y \
    && rm -rf /var/lib/apt/lists/* \
    && rm -rf /tmp/* /var/tmp/*

# Switch back to non-root user
USER appuser

# Set secure environment variables
ENV PYTHONPATH=/app
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1
ENV PATH="/home/appuser/.local/bin:$PATH"

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:5000/health || exit 1

# Expose port (non-privileged)
EXPOSE 5000

# Run application as non-root user
CMD ["python", "run.py"]
```

### CVE-FC-044: Insecure Container Network Configuration
**File:** [`docker-compose.yml`](docker-compose.yml:35)  
**Severity:** High  
**CVSS Score:** 8.4  
**OWASP Category:** A05 - Security Misconfiguration

**Description:**  
Container network configuration lacks proper isolation, enabling lateral movement, network-based attacks, and unauthorized access to internal services.

**Vulnerable Network Configuration:**
```yaml
# docker-compose.yml
services:
  web:
    # No network specification - uses default bridge
    ports:
      - "5000:5000"  # Exposed to all interfaces
    
  nginx:
    ports:
      - "80:80"      # HTTP exposed
      - "443:443"    # No TLS configuration
    # No network isolation
```

**Security Issues:**
1. **No Network Segmentation** - All containers on same network
2. **Exposed Internal Services** - Services accessible from external networks
3. **No TLS Termination** - Unencrypted communication
4. **Missing Firewall Rules** - No network access controls
5. **Default Bridge Network** - Containers can communicate freely

**Secure Network Configuration:**
```yaml
version: '3.8'

services:
  web:
    build:
      context: .
      dockerfile: web.Dockerfile
    networks:
      - backend
    ports:
      - "127.0.0.1:5000:5000"  # Localhost only
    environment:
      - FLASK_ENV=production
    # Network security
    sysctls:
      - net.ipv4.ip_unprivileged_port_start=0

  nginx:
    image: nginx:1.21-alpine
    ports:
      - "80:80"
      - "443:443"
    volumes:
      - ./nginx/nginx.conf:/etc/nginx/nginx.conf:ro
      - ./ssl:/etc/ssl:ro
    networks:
      - frontend
      - backend
    depends_on:
      - web
    # Security hardening
    security_opt:
      - no-new-privileges:true
    read_only: true
    tmpfs:
      - /var/cache/nginx:noexec,nosuid,size=100m
      - /var/run:noexec,nosuid,size=100m

  database:
    image: postgres:13-alpine
    environment:
      - POSTGRES_DB=flowcase
      - POSTGRES_USER=flowcase
      - POSTGRES_PASSWORD_FILE=/run/secrets/db_password
    volumes:
      - db_data:/var/lib/postgresql/data
    networks:
      - backend  # Backend only - no external access
    secrets:
      - db_password
    # Security constraints
    security_opt:
      - no-new-privileges:true
    user: postgres

networks:
  frontend:
    driver: bridge
    ipam:
      config:
        - subnet: 172.20.0.0/24
          gateway: 172.20.0.1
    driver_opts:
      com.docker.network.bridge.enable_icc: "false"  # Disable inter-container communication
      com.docker.network.bridge.enable_ip_masquerade: "true"
      com.docker.network.bridge.host_binding_ipv4: "127.0.0.1"

  backend:
    driver: bridge
    internal: true  # No external access
    ipam:
      config:
        - subnet: 172.21.0.0/24
          gateway: 172.21.0.1

volumes:
  db_data:
    driver: local

secrets:
  db_password:
    file: ./secrets/db_password.txt
```

### CVE-FC-045: Missing Container Resource Limits
**File:** [`docker-compose.yml`](docker-compose.yml:20)  
**Severity:** High  
**CVSS Score:** 7.8  
**OWASP Category:** A05 - Security Misconfiguration

**Description:**  
Containers lack resource constraints, enabling denial-of-service attacks, resource exhaustion, and potential host system instability through unlimited resource consumption.

**Vulnerable Configuration:**
```yaml
services:
  web:
    build: .
    # No resource limits defined
    # Container can consume unlimited CPU/memory
    # No process limits
    # No file descriptor limits
```

**Attack Scenarios:**

1. **Memory Exhaustion Attack:**
```python
# Malicious code consuming unlimited memory
def memory_bomb():
    data = []
    while True:
        data.append('x' * 1024 * 1024)  # 1MB chunks
        # Will consume all available host memory
```

2. **CPU Exhaustion Attack:**
```python
# CPU-intensive infinite loop
import threading

def cpu_bomb():
    while True:
        pass

# Spawn unlimited threads
for i in range(1000):
    threading.Thread(target=cpu_bomb).start()
```

3. **Fork Bomb Attack:**
```bash
# Process exhaustion
:(){ :|:& };:
# Creates unlimited processes until system crashes
```

**Secure Resource Configuration:**
```yaml
version: '3.8'

services:
  web:
    build:
      context: .
      dockerfile: web.Dockerfile
    # Comprehensive resource limits
    deploy:
      resources:
        limits:
          cpus: '1.0'          # 1 CPU core maximum
          memory: 512M         # 512MB RAM maximum
          pids: 100           # Maximum 100 processes
        reservations:
          cpus: '0.25'        # Guaranteed 0.25 CPU
          memory: 128M        # Guaranteed 128MB RAM
    
    # Additional resource controls
    ulimits:
      nproc: 100              # Process limit
      nofile: 1024            # File descriptor limit
      fsize: 100000000        # File size limit (100MB)
      memlock: 67108864       # Memory lock limit (64MB)
    
    # Memory and swap controls
    mem_limit: 512m
    mem_reservation: 128m
    memswap_limit: 512m       # No swap usage
    oom_kill_disable: false   # Allow OOM killer
    
    # CPU controls
    cpus: 1.0
    cpu_shares: 1024
    cpu_quota: 100000
    cpu_period: 100000
    
    # Block I/O limits
    blkio_config:
      weight: 500
      device_read_bps:
        - path: /dev/sda
          rate: '50mb'
      device_write_bps:
        - path: /dev/sda
          rate: '25mb'
    
    # Security and resource monitoring
    logging:
      driver: "json-file"
      options:
        max-size: "10m"
        max-file: "3"
    
    # Process and capability limits
    security_opt:
      - no-new-privileges:true
    cap_drop:
      - ALL
    cap_add:
      - CHOWN
      - SETUID
      - SETGID
    
    # Restart policy with backoff
    restart: on-failure:3
    
    # Health monitoring
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:5000/health"]
      interval: 30s
      timeout: 10s
      retries: 3
      start_period: 40s

  # Resource monitoring service
  monitoring:
    image: prom/node-exporter:latest
    container_name: node-exporter
    restart: unless-stopped
    volumes:
      - /proc:/host/proc:ro
      - /sys:/host/sys:ro
      - /:/rootfs:ro
    command:
      - '--path.procfs=/host/proc'
      - '--path.rootfs=/rootfs'
      - '--path.sysfs=/host/sys'
      - '--collector.filesystem.mount-points-exclude=^/(sys|proc|dev|host|etc)($$|/)'
    networks:
      - monitoring
    deploy:
      resources:
        limits:
          cpus: '0.2'
          memory: 128M

networks:
  monitoring:
    driver: bridge
    internal: true
```

---

## Container Security Hardening

### Secure Base Image Configuration

```dockerfile
# Multi-stage build for minimal attack surface
FROM python:3.9-slim-bullseye AS builder

# Install build dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

# Create virtual environment
RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

# Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Production stage
FROM python:3.9-slim-bullseye AS production

# Install only runtime dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && apt-get clean

# Create non-root user
RUN groupadd -r appuser && \
    useradd -r -g appuser -d /app -s /sbin/nologin appuser

# Copy virtual environment from builder
COPY --from=builder /opt/venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

# Set up application directory
WORKDIR /app
RUN chown appuser:appuser /app

# Copy application code
COPY --chown=appuser:appuser . .

# Remove unnecessary files
RUN find /app -name "*.pyc" -delete && \
    find /app -name "__pycache__" -type d -exec rm -rf {} + && \
    rm -rf /app/tests /app/.git /app/docs

# Security hardening
RUN chmod -R 755 /app && \
    chmod 644 /app/*.py

# Switch to non-root user
USER appuser

# Security labels
LABEL security.scan="enabled" \
      security.non-root="true" \
      security.readonly="true"

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:5000/health || exit 1

EXPOSE 5000

CMD ["python", "run.py"]
```

### Container Runtime Security

```python
# Container security monitoring
import psutil
import os
import logging
from datetime import datetime

class ContainerSecurityMonitor:
    def __init__(self):
        self.logger = logging.getLogger('security.container')
        self.resource_limits = {
            'cpu_percent': 80.0,
            'memory_percent': 80.0,
            'disk_usage_percent': 85.0,
            'process_count': 50
        }
    
    def monitor_resources(self):
        """Monitor container resource usage"""
        try:
            # CPU usage
            cpu_percent = psutil.cpu_percent(interval=1)
            if cpu_percent > self.resource_limits['cpu_percent']:
                self.logger.warning(f"High CPU usage: {cpu_percent}%")
            
            # Memory usage
            memory = psutil.virtual_memory()
            if memory.percent > self.resource_limits['memory_percent']:
                self.logger.warning(f"High memory usage: {memory.percent}%")
            
            # Disk usage
            disk = psutil.disk_usage('/')
            disk_percent = (disk.used / disk.total) * 100
            if disk_percent > self.resource_limits['disk_usage_percent']:
                self.logger.warning(f"High disk usage: {disk_percent}%")
            
            # Process count
            process_count = len(psutil.pids())
            if process_count > self.resource_limits['process_count']:
                self.logger.warning(f"High process count: {process_count}")
            
            return {
                'cpu_percent': cpu_percent,
                'memory_percent': memory.percent,
                'disk_percent': disk_percent,
                'process_count': process_count,
                'timestamp': datetime.utcnow().isoformat()
            }
            
        except Exception as e:
            self.logger.error(f"Resource monitoring failed: {str(e)}")
            return None
    
    def check_security_violations(self):
        """Check for security violations"""
        violations = []
        
        # Check if running as root
        if os.getuid() == 0:
            violations.append("Container running as root user")
        
        # Check for suspicious processes
        for proc in psutil.process_iter(['pid', 'name', 'cmdline']):
            try:
                if proc.info['name'] in ['nc', 'netcat', 'nmap', 'wget', 'curl']:
                    violations.append(f"Suspicious process: {proc.info['name']}")
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
        
        # Check network connections
        connections = psutil.net_connections()
        for conn in connections:
            if conn.status == 'LISTEN' and conn.laddr.port not in [5000, 8080]:
                violations.append(f"Unexpected listening port: {conn.laddr.port}")
        
        if violations:
            self.logger.error(f"Security violations detected: {violations}")
        
        return violations

# Initialize security monitoring
security_monitor = ContainerSecurityMonitor()
```

---

## Deployment Security Best Practices

### Secure Docker Compose Production Configuration

```yaml
version: '3.8'

x-common-variables: &common-variables
  FLASK_ENV: production
  PYTHONPATH: /app
  PYTHONDONTWRITEBYTECODE: 1
  PYTHONUNBUFFERED: 1

x-security-opts: &security-opts
  security_opt:
    - no-new-privileges:true
    - apparmor:docker-default
  cap_drop:
    - ALL
  read_only: true

x-resource-limits: &resource-limits
  deploy:
    resources:
      limits:
        cpus: '1.0'
        memory: 512M
      reservations:
        cpus: '0.25'
        memory: 128M

services:
  web:
    build:
      context: .
      dockerfile: web.Dockerfile
      args:
        - BUILD_DATE=${BUILD_DATE}
        - VCS_REF=${VCS_REF}
    image: flowcase:${VERSION:-latest}
    container_name: flowcase-web
    <<: *security-opts
    <<: *resource-limits
    environment:
      <<: *common-variables
      - DATABASE_URL=postgresql://flowcase:${DB_PASSWORD}@database:5432/flowcase
      - SECRET_KEY_FILE=/run/secrets/secret_key
      - DOCKER_API_ENDPOINT=http://docker-proxy:2375
    volumes:
      - app-data:/app/data
      - app-logs:/app/logs
    tmpfs:
      - /tmp:noexec,nosuid,size=100m
    networks:
      - backend
    secrets:
      - secret_key
    depends_on:
      database:
        condition: service_healthy
      docker-proxy:
        condition: service_started
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:5000/health"]
      interval: 30s
      timeout: 10s
      retries: 3
      start_period: 40s
    restart: unless-stopped
    user: "1000:1000"
    logging:
      driver: "json-file"
      options:
        max-size: "10m"
        max-file: "3"

  nginx:
    image: nginx:1.21-alpine
    container_name: flowcase-nginx
    <<: *security-opts
    ports:
      - "80:80"
      - "443:443"
    volumes:
      - ./nginx/nginx.conf:/etc/nginx/nginx.conf:ro
      - ./nginx/ssl:/etc/ssl:ro
      - nginx-cache:/var/cache/nginx
    tmpfs:
      - /var/run:noexec,nosuid,size=10m
    networks:
      - frontend
      - backend
    depends_on:
      - web
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost/health"]
      interval: 30s
      timeout: 10s
      retries: 3
    restart: unless-stopped
    deploy:
      resources:
        limits:
          cpus: '0.5'
          memory: 256M

  database:
    image: postgres:13-alpine
    container_name: flowcase-db
    <<: *security-opts
    environment:
      - POSTGRES_DB=flowcase
      - POSTGRES_USER=flowcase
      - POSTGRES_PASSWORD_FILE=/run/secrets/db_password
      - POSTGRES_INITDB_ARGS=--auth-host=scram-sha-256
    volumes:
      - db-data:/var/lib/postgresql/data
      - ./database/init:/docker-entrypoint-initdb.d:ro
    networks:
      - backend
    secrets:
      - db_password
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U flowcase -d flowcase"]
      interval: 30s
      timeout: 10s
      retries: 3
    restart: unless-stopped
    user: postgres
    deploy:
      resources:
        limits:
          cpus: '1.0'
          memory: 1G

  docker-proxy:
    image: tecnativa/docker-socket-proxy:latest
    container_name: flowcase-docker-proxy
    <<: *security-opts
    environment:
      - CONTAINERS=1
      - IMAGES=1
      - NETWORKS=0
      - VOLUMES=0
      - SERVICES=0
      - SWARM=0
      - SYSTEM=0
      - EVENTS=0
      - POST=1
      - DELETE=1
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock:ro
    networks:
      - backend
    restart: unless-stopped
    deploy:
      resources:
        limits:
          cpus: '0.2'
          memory: 128M

networks:
  frontend:
    driver: bridge
    ipam:
      config:
        - subnet: 172.20.0.0/24
  backend:
    driver: bridge
    internal: true
    ipam:
      config:
        - subnet: 172.21.0.0/24

volumes:
  app-data:
    driver: local
    driver_opts:
      type: none
      o: bind
      device: /opt/flowcase/data
  app-logs:
    driver: local
  db-data:
    driver: local
    driver_opts:
      type: none
      o: bind
      device: /opt/flowcase/database
  nginx-cache:
    driver: local

secrets:
  secret_key:
    file: ./secrets/secret_key.txt
  db_password:
    file: ./secrets/db_password.txt
```

---

## Container Image Security Scanning

### Automated Security Scanning

```bash
#!/bin/bash
# Container security scanning script

set -euo pipefail

IMAGE_NAME="flowcase:latest"
SCAN_RESULTS_DIR="./security-scans"

# Create results directory
mkdir -p "$SCAN_RESULTS_DIR"

echo "Starting container security scan for $IMAGE_NAME"

# Trivy vulnerability scanning
echo "Running Trivy vulnerability scan..."
trivy image --format json --output "$SCAN_RESULTS_DIR/trivy-report.json" "$IMAGE_NAME"
trivy image --severity HIGH,CRITICAL "$IMAGE_NAME"

# Docker Bench Security
echo "Running Docker Bench Security..."
docker run --rm --net host --pid host --userns host --cap-add audit_control \
    -e DOCKER_CONTENT_TRUST=$DOCKER_CONTENT_TRUST \
    -v /etc:/etc:ro \
    -v /usr/bin/containerd:/usr/bin/containerd:ro \
    -v /usr/bin/runc:/usr/bin/runc:ro \
    -v /usr/lib/systemd:/usr/lib/systemd:ro \
    -v /var/lib:/var/lib:ro \
    -v /var/run/docker.sock:/var/run/docker.sock:ro \
    --label docker_bench_security \
    docker/docker-bench-security > "$SCAN_RESULTS_DIR/docker-bench-report.txt"

# Hadolint Dockerfile linting
echo "Running Hadolint Dockerfile analysis..."
hadolint web.Dockerfile > "$SCAN_RESULTS_DIR/hadolint-report.txt" || true

# Container structure test
echo "Running container structure tests..."
container-structure-test test --image "$IMAGE_NAME" --config container-test.yaml \
    --output "$SCAN_RESULTS_DIR/structure-test-report.json"

echo "Security scanning completed. Results saved to $SCAN_RESULTS_DIR"

# Check for critical vulnerabilities
CRITICAL_VULNS=$(jq '.Results[].Vulnerabilities[]? | select(.Severity == "CRITICAL") | .VulnerabilityID' \
    "$SCAN_RESULTS_DIR/trivy-report.json" 2>/dev/null | wc -l || echo "0")

if [ "$CRITICAL_VULNS" -gt 0 ]; then
    echo "ERROR: $CRITICAL_VULNS critical vulnerabilities found!"
    exit 1
fi

echo "No critical vulnerabilities found."
```

### Container Structure Tests

```yaml
# container-test.yaml
schemaVersion: 2.0.0

commandTests:
  - name: "Application runs as non-root user"
    command: "whoami"
    expectedOutput: ["appuser"]
  
  - name: "Python application starts correctly"
    command: "python"
    args: ["-c", "import flask; print('Flask available')"]
    expectedOutput: ["Flask available"]

fileExistenceTests:
  - name: "Application files exist"
    path: "/app/run.py"
    shouldExist: true
  
  - name: "No sensitive files in container"
    path: "/etc/