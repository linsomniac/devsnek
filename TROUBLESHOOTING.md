# Troubleshooting devsnek

This document provides solutions for common issues you might encounter when using devsnek.

## Certificate Issues

### Falling Back to Self-Signed Certificate

If you're seeing messages like:
```
Error getting Let's Encrypt certificates: [error message]
Falling back to self-signed certificate
```

This means Let's Encrypt certificates could not be obtained automatically. The most common reason is that port 80 is already in use by another application.

### "No start line" Error

If you're seeing an error like:
```
Error starting server: [('PEM routines', '', 'no start line')]
```

This typically means there was an issue with the certificate generation. Try the following:

1. **Use verbose mode to debug certificate issues**:
   ```bash
   devsnek --bind-addr localhost --port 8443 --san example.com --verbose
   ```

2. **Use self-signed certificates for local testing**:
   ```bash
   devsnek --bind-addr localhost --port 8443 --self-signed
   ```

3. **Delete existing certificates and try again**:
   ```bash
   rm -rf certs/
   devsnek --bind-addr example.com --port 8443 --san example.com --staging
   ```

4. **Check port 80 availability (MOST COMMON ISSUE)**:
   The ACME protocol requires port 80 to be available for the HTTP-01 challenge. Make sure no other service is using port 80 on your machine. You can check this with:
   ```bash
   sudo lsof -i :80
   ```
   
   If port 80 is in use, you have several options:
   - Stop the service using port 80 (e.g., `sudo systemctl stop apache2` or `sudo systemctl stop nginx`)
   - Use a reverse proxy to forward requests from port 80 to devsnek
   - Run devsnek as root to bind to port 80 (not recommended for production)
   - Set up port forwarding in your router/firewall to redirect port 80 to another port
   
   If you have port 80 forwarding or a proxy server already set up, use the --skip-port-check option:
   ```bash
   devsnek --bind-addr your.domain.com --san your.domain.com --skip-port-check
   ```
   
   If you can't free up port 80, you'll need to use self-signed certificates:
   ```bash
   devsnek --bind-addr your.domain.com --self-signed
   ```
   
5. **DNS configuration**:
   Ensure your domain is properly configured with DNS records pointing to your server's IP address. Let's Encrypt needs to reach your server at the domain you're requesting a certificate for.

6. **Firewall settings**:
   Make sure your firewall allows incoming connections on port 80, which is required for the HTTP-01 challenge.
   ```bash
   # Check if port 80 is open
   sudo iptables -L -n | grep "dpt:80"
   ```

### Let's Encrypt Rate Limits

If you're hitting Let's Encrypt rate limits, use the staging environment:
```bash
devsnek --host example.com --port 8443 --staging
```

## Network and Port Issues

### Port Already in Use

If you get an error that the port is already in use:
```bash
# Try a different port
devsnek --host example.com --port 8444
```

### Permission Issues with Port 80 or 443

To use standard ports (80 for HTTP, 443 for HTTPS), you'll need root privileges:
```bash
sudo devsnek --host example.com --port 443 --redirect-port 80
```

Alternatively, use higher ports:
```bash
devsnek --host example.com --port 8443 --redirect-port 8080
```

## ASGI Application Issues

### WSGI to ASGI Conversion Error

For Flask applications, make sure you have the `asgiref` package installed:
```bash
pip install "devsnek[flask]"
```

### Module Not Found Error

If your ASGI application module isn't found, check your directory structure or use an absolute import path:
```bash
devsnek --host example.com --port 8443 --asgi-app mypackage.app:app
```

Or run from the directory containing your module:
```bash
cd myproject
devsnek --host example.com --port 8443 --asgi-app app:app
```

## Development Workflow Tips

### Quick Local Development

For the fastest local development experience:
```bash
devsnek --host localhost --port 8443 --self-signed --no-redirect
```

### Testing with Real Domains

To test with a real domain but avoid Let's Encrypt rate limits:
```bash
devsnek --host example.com --port 8443 --staging
```

### Production-Ready Setup

For production or staging environments:
```bash
devsnek --host example.com --port 443 --email admin@example.com --redirect-port 80
```

## Example Configurations

### Basic Static File Server (like http.server but with HTTPS)

```bash
devsnek --host localhost --port 8443 --self-signed --web-root ./public
```

### Flask Development Server

```bash
devsnek --host localhost --port 8443 --self-signed --asgi-app app:app
```

### FastAPI Development Server

```bash
devsnek --host localhost --port 8443 --self-signed --asgi-app app:app
```

### Production-Ready Server with Custom Configuration

```yaml
# config.yaml
host: example.com
port: 443
email: admin@example.com
san_domains:
  - www.example.com
  - api.example.com
web_root: ./public
asgi_app: app:app
redirect_http: true
redirect_port: 80
live_reload: false
```

Run with:
```bash
devsnek --config config.yaml
```