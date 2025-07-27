FROM python:3.11-slim

# Add build arguments
ARG COMMIT_HASH=Unknown

WORKDIR /flowcase
COPY build_scripts /flowcase/build_scripts
COPY config /flowcase/config
COPY models /flowcase/models
COPY nginx /flowcase/nginx
COPY routes /flowcase/routes
COPY static /flowcase/static
COPY templates /flowcase/templates
COPY utils /flowcase/utils
COPY __init__.py run.py run_headers.py wsgi.py wsgi_headers.py /flowcase/
COPY requirements.txt /flowcase

# Make the inject script executable and run it
RUN chmod +x /flowcase/build_scripts/inject_commit.sh && \
    /flowcase/build_scripts/inject_commit.sh ${COMMIT_HASH}

# Install system dependencies including Docker CLI
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    curl \
    apt-transport-https \
    ca-certificates \
    gnupg \
    lsb-release && \
    mkdir -p /etc/apt/keyrings && \
    curl -fsSL https://download.docker.com/linux/debian/gpg | gpg --dearmor -o /etc/apt/keyrings/docker.gpg && \
    echo \
    "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/debian \
    $(lsb_release -cs) stable" | tee /etc/apt/sources.list.d/docker.list > /dev/null && \
    apt-get update && \
    apt-get install -y --no-install-recommends docker-ce-cli && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Install Python dependencies
RUN pip install --trusted-host pypi.python.org -r requirements.txt