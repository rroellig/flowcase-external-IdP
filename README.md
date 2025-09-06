# <div align="center">🌊 **Flowcase with Enterprise Enhancements**</div>

<div align="center">

![Flowcase](https://img.shields.io/badge/Status-Development-yellow)
![License](https://img.shields.io/badge/license-MIT-blue)
![Docker](https://img.shields.io/badge/Docker-Required-blue)
![Fork](https://img.shields.io/badge/Fork-flowcase%2Fflowcase-blue)

**Enhanced container streaming platform with external identity provider support**

</div>

> [!CAUTION]
> This project is still in development and is not yet ready for production use. We do not currently support upgrading from older versions. Please use with caution.

## About This Fork

This is an enhanced fork of [flowcase/flowcase](https://github.com/flowcase/flowcase) extending the original with enterprise-grade authentication and access control features.
All improvements are contributed back to the original project via pull requests.

## What is Flowcase?

**Flowcase** is a free and completely open-source alternative to Kasm Workspaces, enabling secure container streaming for your applications. 

## Features

<div align="center">

| Open-Source | Secure Streaming | User-Friendly | Customizable | Multi-Platform |
|:-------------:|:------------------:|:----------------:|:--------------:|:--------------:|
| Completely free and community-driven | Stream applications securely using Docker | Easy to deploy and manage | Supports customization for various use cases | Supports Windows, Linux, and macOS |

</div>

### Enhanced Features (this fork)

<div align="center">

| External Identity | Advanced Access Control | Container Persistence | Network Flexibility | Registry Management |
|:----------------:|:----------------------:|:--------------------:|:-------------------:|:------------------:|
| Traefik + Authentik integration | Group-based droplet access | Containers survive restarts | Custom Docker network support | Registry URL locking |

</div>

- **🔐 External Identity Provider**: Full integration with Authentik via Traefik forward authentication
- **👥 Group-Based Access Control**: Enhanced user and group management with granular permissions
- **📦 Container Persistence**: Containers persist across application restarts
- **🌐 Network Selection**: Support for custom Docker networks (lan*, vlan*, default)
- **📋 Registry Management**: Registry URL locking and enhanced configuration options to prevent untrusted registries
- **💾 Profile Volume Management**: Improved user profile and volume handling

## Prerequisites

Before getting started, ensure you have:

- Docker and Docker Compose installed on your machine
- A user with sudo/root access or a user in the `docker` group
- Basic knowledge of container management

## Setup Instructions

1. **Clone the repository**
```shell
git clone https://github.com/rroellig/flowcase.git
cd flowcase
git checkout integration
```

2. **Configure environment variables**
```shell
cp .env.example .env
# Edit .env with your domain and authentication settings
```

3. **Build the Flowcase image**
```shell
docker compose build
```

4. **Launch the full stack**
```shell
docker compose up -d
```

5. **Access the services**

- Flowcase: `https://flowcase.${DOMAIN}`
- Authentik: `https://authentik.${DOMAIN}`
- Traefik Dashboard: `https://traefik.${DOMAIN}`

## Configuration Options

The application supports several command line configuration options via `run.py`. When using Docker Compose, these options should be set in the `docker-compose.yml` file under the `web` service's `command` section:

### Authentication Modes

- `--traefik-authentik`: Enable Traefik + Authentik integration mode (reads username from X-Authentik-Username header)
- `--ext-idp-user <username>`: Simulate external identity provider with specified username (for testing)

### Registry Management

- `--registry-lock <registry-url>`: Lock the registry to a fixed URL, preventing users from changing it in the frontend. This security feature prevents users from adding untrusted registries

### Server Configuration

- `--port <port>`: Specify the port to run the application on

### Docker Compose Configuration

In `docker-compose.yml`, modify the web service command:

```yaml
services:
  web:
    # ... other configuration
    command: python run.py --traefik-authentik --registry-lock https://my-registry.com
```

### Direct Usage Examples

```shell
# Enable Traefik + Authentik integration
python run.py --traefik-authentik

# Lock registry to a specific URL
python run.py --registry-lock https://my-private-registry.example.com

# Simulate external user for testing
python run.py --ext-idp-user testuser

# Combine multiple options
python run.py --traefik-authentik --registry-lock https://registry.internal.com --port 8080
```

> [!NOTE]
> The `--traefik-authentik` option takes precedence over `--ext-idp-user` if both are specified.

## Branch Information

This repository was forked from commit [`a59084d`](https://github.com/flowcase/flowcase/commit/a59084d) on main. All feature branches can be merged conflict-free back to this starting point:

- **main**: Upstream main branch
- **integration**: All enhanced features combined
- **feature/network-selection**: Docker network dropdown selection for container deployment  
- **feature/container-persistence**: Makes containers survive application restarts
- **feature/improved-access-control**: Group-based access control and user management enhancements
- **feature/reverse-proxy**: Traefik and Authentik integration for external identity providers
- **feature/registry-lock**: Registry URL locking and configuration management
- **feature/image-download-logs-fix**: Enhanced logging and error handling for image downloads
- **feature/profile-volumes**: Improved user profile volume management and handling

## Contributing

Contributions are welcome! This fork contributes improvements back to the upstream project via pull requests.

For upstream contributions: [flowcase/flowcase](https://github.com/flowcase/flowcase)

## Security

Please refer to [SECURITY.md](SECURITY.md) for more information.

---

Enhanced fork by rroellig | Original project by the Flowcase Team
