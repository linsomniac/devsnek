#!/usr/bin/env python3
"""
Simple script to run devsnek in static file server mode.
"""

import os
import argparse
import asyncio
import logging
from devsnek.server import DevServer
from devsnek.config import ServerConfig
from devsnek.cli import setup_logging

async def main():
    parser = argparse.ArgumentParser(description="Run devsnek static file server")
    parser.add_argument("--bind-addr", default="localhost", help="Address to bind to")
    parser.add_argument("--port", type=int, default=8443, help="Port to bind to")
    parser.add_argument("--http-port", type=int, default=8080, help="Port for HTTP redirector")
    parser.add_argument("--no-redirect", action="store_true", help="Disable HTTP to HTTPS redirection")
    parser.add_argument("--staging", action="store_true", help="Use Let's Encrypt staging")
    parser.add_argument("--self-signed", action="store_true", help="Use self-signed certificate")
    parser.add_argument("--san", action="append", help="Subject Alternative Name(s) for certificate (domain or IP)")
    parser.add_argument("--web-root", default="web", help="Directory to serve files from")
    parser.add_argument("--verbose", action="store_true", help="Enable verbose debug output")
    parser.add_argument("--log-level", choices=["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"], default="INFO", help="Logging level")
    args = parser.parse_args()
    
    # Setup logging
    setup_logging(args.log_level, args.verbose)
    
    # Ensure web root exists
    os.makedirs(args.web_root, exist_ok=True)
    
    # Create a simple HTML file to serve
    with open(os.path.join(args.web_root, "index.html"), "w") as f:
        f.write(f"""<!DOCTYPE html>
<html>
<head>
    <title>devsnek Test Server</title>
</head>
<body>
    <h1>devsnek Test Server</h1>
    <p>This is a test of the devsnek server running on {args.host}:{args.port}.</p>
    <p>Current time: <span id="time"></span></p>
    
    <script>
        function updateTime() {{
            document.getElementById('time').textContent = new Date().toLocaleString();
        }}
        setInterval(updateTime, 1000);
        updateTime();
    </script>
</body>
</html>
""")
    
    # Create server config
    # Set self-signed automatically if no SAN domains are provided
    is_self_signed = args.self_signed or not args.san
    
    config = ServerConfig(
        bind_addr=args.bind_addr,
        port=args.port,
        staging=args.staging,
        self_signed=is_self_signed,
        san_domains=args.san or [],
        web_root=args.web_root,
        redirect_http=not args.no_redirect,
        http_port=args.http_port,
        log_level=args.log_level,
        verbose=args.verbose
    )
    
    # Start server
    server = DevServer(config)
    await server.start()

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\nServer stopped.")