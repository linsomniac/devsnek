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

### Key Authorization Mismatch

If you see errors containing "key authorization did not match", this typically indicates:

1. **DNS Configuration Issues**: Your domain might not be pointing to the correct IP address.
   
   Enable verbose mode to use the built-in DNS validation tool:
   ```bash
   devsnek --bind-addr 0.0.0.0 --port 8443 --san example.com --verbose
   ```
   
   The enhanced DNS validation will:
   - Determine your server's public IP from multiple sources
   - Check if your domain correctly resolves to your server's IP
   - Detect CDNs or proxies like Cloudflare
   - Provide specific troubleshooting guidance
   
   You can also manually check:
   ```bash
   # Check where your domain resolves to
   dig +short example.com
   
   # Compare with your server's public IP
   curl https://api.ipify.org
   ```

2. **CDN or Proxy Issues**: If your domain uses Cloudflare or another CDN/proxy, the HTTP challenge will fail.
   - The verbose output will detect common CDN IP ranges
   - Temporarily disable the CDN/proxy for the domain during certificate issuance
   - Or use the DNS-01 challenge method (not currently supported by devsnek)

3. **Proxy/Firewall Issues**: Something might be intercepting or modifying the challenge responses.
   - Check if your CDN, firewall, or proxy is configured to pass through requests to `/.well-known/acme-challenge/`
   - Temporarily disable any firewall rules that might affect HTTP traffic

### Certificate Verification Failed

If you see "Certificate verification failed" errors:

1. **Check certificate and key file permissions**:
   ```bash
   ls -la certs/
   # Ensure files are readable
   chmod 644 certs/*.crt
   chmod 600 certs/*.key
   ```

2. **Verify the certificate chain is complete**:
   ```bash
   openssl verify -CAfile /etc/ssl/certs/ca-certificates.crt certs/yourdomain.crt
   ```

3. **Ensure the certificate matches the private key**:
   ```bash
   # Get the modulus of the certificate and key
   openssl x509 -noout -modulus -in certs/yourdomain.crt | openssl md5
   openssl rsa -noout -modulus -in certs/yourdomain.key | openssl md5
   # The output should be identical
   ```

## Network and Port Issues

### Port Already in Use

#### HTTPS Port Conflicts

If you get an error that the HTTPS port is already in use:
```bash
# Try a different port
devsnek --host example.com --port 8444
```

Or find and stop the process using the port:
```bash
# Find process using port 8443
sudo lsof -i :8443
# Kill the process
sudo kill <PID>
```

#### HTTP Redirection Port Conflicts

For HTTP redirection port conflicts, devsnek now implements automatic port fallback:

1. If the requested HTTP port (default 8080) is already in use, devsnek will:
   - Automatically search for the next available port
   - Display a message showing which port was chosen
   - Continue operation without requiring manual intervention

2. You can still specify a custom HTTP port if needed:
   ```bash
   devsnek --host example.com --port 8443 --http-port 8081
   ```

3. Or disable HTTP redirection entirely:
   ```bash
   devsnek --host example.com --port 8443 --no-redirect
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

### Binding to Public Interfaces

If you need to make your server accessible from other machines:
```bash
# Use 0.0.0.0 to listen on all interfaces
devsnek --bind-addr 0.0.0.0 --port 8443 --self-signed
```

For a specific interface only:
```bash
# Replace with your network interface's IP
devsnek --bind-addr 192.168.1.10 --port 8443 --self-signed
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

### ASGI Application Errors

If your ASGI application fails to start:

1. **Check for syntax errors in your application**:
   ```bash
   python -m myapp
   ```

2. **Add debugging output**:
   ```bash
   devsnek --host localhost --port 8443 --self-signed --asgi-app app:app --log-level DEBUG
   ```

3. **Test the ASGI app with a standard ASGI server**:
   ```bash
   # For FastAPI/Starlette apps
   uvicorn app:app --reload
   
   # For Django apps
   daphne myproject.asgi:application
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

### Live Reloading Issues

If live reloading isn't working correctly:

1. **Specify directories to watch explicitly**:
   ```bash
   devsnek --host localhost --port 8443 --self-signed --asgi-app app:app --reload-dir ./src --reload-dir ./templates
   ```

2. **Check if your directories are being watched**:
   ```bash
   devsnek --host localhost --port 8443 --self-signed --asgi-app app:app --log-level DEBUG
   ```
   
   Look for log messages about file watching.

3. **Ensure your ASGI application supports reloading**:
   Some frameworks might need additional configuration for reloading to work correctly.

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

## WebSocket Issues

If you're having trouble with WebSocket connections:

1. **Check browser console for WebSocket errors**
   Look for connection errors or protocol issues in your browser's developer tools.

2. **Ensure your ASGI application properly handles WebSocket protocol**
   ```python
   # Example for FastAPI
   @app.websocket("/ws")
   async def websocket_endpoint(websocket: WebSocket):
       await websocket.accept()
       # ...
   ```

3. **Try with WebSocket support explicitly enabled**
   ```bash
   devsnek --host localhost --port 8443 --self-signed --asgi-app app:app
   ```

4. **Debug with verbose logging**
   ```bash
   devsnek --host localhost --port 8443 --self-signed --asgi-app app:app --log-level DEBUG
   ```