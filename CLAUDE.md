# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

devsnek is a Python development web server with automatic LetsEncrypt certificate support and ASGI capabilities. It combines the simplicity of `python -m http.server` with HTTPS support via Let's Encrypt, and can also serve ASGI applications with live reloading.

## Core Components

1. **Certificate Manager (`cert_manager.py`)**: Handles Let's Encrypt certificate acquisition and renewal using the ACME protocol.

2. **Server Core (`server.py`)**: Main server implementation that can run in either static file mode or ASGI application mode.

3. **Config System (`config.py`)**: Handles YAML configuration file loading and CLI argument parsing.

4. **Static File Handler (`static.py`)**: Serves static files from a directory, similar to Python's built-in http.server.

5. **ASGI Support (`asgi.py`)**: Runs ASGI-compatible web applications like Flask and FastAPI.

6. **Live Reloading (`reload.py`)**: Monitors file changes and automatically reloads ASGI applications.

7. **HTTP Redirector (`redirect.py`)**: Redirects HTTP requests to HTTPS.

8. **CLI (`cli.py`)**: Command-line interface for the server.

## Commands

### Installation

```bash
# Install the package in development mode
pip install -e .

# Install with optional dependencies for Flask
pip install -e ".[flask]"

# Install with optional dependencies for FastAPI
pip install -e ".[fastapi]"
```

### Running the Server

```bash
# Run in static file server mode (default)
python -m devsnek --host example.com --port 8443

# Run with an ASGI application
python -m devsnek --host example.com --port 8443 --asgi-app myapp:app

# Use Let's Encrypt staging environment (for testing)
python -m devsnek --host example.com --staging

# Save configuration to a YAML file
python -m devsnek --host example.com --port 8443 --save-config config.yaml

# Load configuration from a YAML file
python -m devsnek --config config.yaml
```

### Running Tests (when implemented)

```bash
# Run pytest
pytest
```

## Development Notes

1. The core server is built using asyncio for concurrency.

2. The ASGI implementation follows the ASGI 3.0 specification.

3. Certificate management uses Let's Encrypt's ACME protocol via the `acme` and `certbot` libraries.

4. Configuration can be provided via CLI arguments or YAML files.

5. Live reloading works by monitoring file changes and reloading the ASGI application when changes are detected.

6. The primary dependencies are:
   - certbot and acme for certificate management
   - cryptography for SSL/TLS
   - pyyaml for configuration
   - Optional Flask or FastAPI for ASGI applications