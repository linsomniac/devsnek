# devsnek

A Python development web server with automatic LetsEncrypt certificate support and ASGI capabilities.

## Features

- Automatic HTTPS with LetsEncrypt certificates
- Option to use LetsEncrypt staging environment for development
- Static file serving (similar to `python -m http.server`)
- ASGI application server with live reloading
- WebSocket support
- YAML configuration
- HTTP to HTTPS redirection

## Installation

```bash
# Install from source
pip install -e .

# Install with Flask support
pip install -e ".[flask]"

# Install with FastAPI support
pip install -e ".[fastapi]"
```

## Quick Start

### Static File Server (like http.server)

```bash
# Serve static files (from ./web directory by default)
devsnek --host example.com --port 8443
```

### ASGI Application Server

```bash
# Run an ASGI application (with live reloading)
devsnek --host example.com --port 8443 --asgi-app myapp:app
```

### With Let's Encrypt Certificates

```bash
# Use Let's Encrypt staging for testing
devsnek --host example.com --port 8443 --staging

# Use production Let's Encrypt with your email
devsnek --host example.com --email admin@example.com
```

## Usage

```
usage: devsnek [-h] [--host HOST] [--port PORT] [--certs-dir CERTS_DIR] [--email EMAIL] [--san SAN] [--staging]
                [--web-root WEB_ROOT] [--asgi-app ASGI_APP] [--no-redirect] [--redirect-port REDIRECT_PORT]
                [--no-reload] [--reload-dir RELOAD_DIRS] [--no-websocket]
                [--log-level {DEBUG,INFO,WARNING,ERROR,CRITICAL}] [--config CONFIG] [--save-config SAVE_CONFIG]

devsnek: Python development web server with LetsEncrypt support

options:
  -h, --help            show this help message and exit
  --host HOST           Host to bind to (default: localhost)
  --port PORT           Port to bind to (default: 8443)
  --certs-dir CERTS_DIR
                        Directory to store certificates (default: certs)
  --email EMAIL         Email address for Let's Encrypt registration
  --san SAN             Subject Alternative Name(s) to include in the certificate
  --staging             Use Let's Encrypt staging environment
  --web-root WEB_ROOT   Directory to serve static files from (default: web)
  --asgi-app ASGI_APP   ASGI application to run (format: module:app)
  --no-redirect         Disable HTTP to HTTPS redirection
  --redirect-port REDIRECT_PORT
                        Port to listen on for HTTP redirection (default: 8080)
  --no-reload           Disable live reloading for ASGI applications
  --reload-dir RELOAD_DIRS
                        Directories to watch for changes (can be specified multiple times)
  --no-websocket        Disable WebSocket support
  --log-level {DEBUG,INFO,WARNING,ERROR,CRITICAL}
                        Logging level (default: INFO)
  --config CONFIG       Path to YAML configuration file
  --save-config SAVE_CONFIG
                        Save configuration to YAML file and exit
```

## Configuration File

You can use a YAML configuration file to specify options:

```yaml
# server.yaml
host: example.com
port: 8443
email: admin@example.com
san_domains:
  - www.example.com
  - api.example.com
web_root: ./public
asgi_app: myapp:app
live_reload: true
reload_dirs:
  - ./src
  - ./templates
```

Then run with:

```bash
devsnek --config server.yaml
```

You can also save your current configuration:

```bash
devsnek --host example.com --port 8443 --save-config server.yaml
```

## Examples

### Flask Example

```python
# app.py
from flask import Flask

app = Flask(__name__)

@app.route('/')
def hello():
    return 'Hello, World!'

# Run with: devsnek --asgi-app app:app
```

### FastAPI Example

```python
# app.py
from fastapi import FastAPI

app = FastAPI()

@app.get('/')
def read_root():
    return {'Hello': 'World'}

# Run with: devsnek --asgi-app app:app
```

## Development

devsnek is in early development. Contributions are welcome!

## License

MIT