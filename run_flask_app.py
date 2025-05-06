#!/usr/bin/env python3
"""
Simple script to run devsnek with a Flask application.
"""

import os
import argparse
import asyncio
import logging
from devsnek.server import DevServer
from devsnek.config import ServerConfig
from devsnek.cli import setup_logging

# Create a simple Flask app
def create_flask_app():
    # Create app directory if it doesn't exist
    os.makedirs("app", exist_ok=True)
    
    # Create Flask app file
    with open("app/__init__.py", "w") as f:
        f.write("""
from flask import Flask, jsonify

app = Flask(__name__)

@app.route('/')
def index():
    return '<h1>Hello from Flask!</h1><p>This app is running with devsnek.</p>'

@app.route('/api/time')
def time():
    import time
    return jsonify({
        'timestamp': time.time(),
        'formatted': time.strftime('%Y-%m-%d %H:%M:%S')
    })

# WSGI to ASGI conversion for older Flask versions
try:
    from asgiref.wsgi import WsgiToAsgi
    app = WsgiToAsgi(app)
except ImportError:
    # Flask 2.0+ has native ASGI support
    pass
""")
    return "app:app"

async def main():
    parser = argparse.ArgumentParser(description="Run devsnek with Flask app")
    parser.add_argument("--bind-addr", default="localhost", help="Address to bind to")
    parser.add_argument("--port", type=int, default=8443, help="Port to bind to")
    parser.add_argument("--http-port", type=int, default=8080, help="Port for HTTP redirector")
    parser.add_argument("--no-redirect", action="store_true", help="Disable HTTP to HTTPS redirection")
    parser.add_argument("--staging", action="store_true", help="Use Let's Encrypt staging")
    parser.add_argument("--self-signed", action="store_true", help="Use self-signed certificate")
    parser.add_argument("--san", action="append", help="Subject Alternative Name(s) for certificate (domain or IP)")
    parser.add_argument("--verbose", action="store_true", help="Enable verbose debug output")
    parser.add_argument("--log-level", choices=["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"], default="INFO", help="Logging level")
    args = parser.parse_args()
    
    # Setup logging
    setup_logging(args.log_level, args.verbose)
    
    # Create Flask app
    asgi_app = create_flask_app()
    
    # Create server config
    # Set self-signed automatically if no SAN domains are provided
    is_self_signed = args.self_signed or not args.san
    
    config = ServerConfig(
        bind_addr=args.bind_addr,
        port=args.port,
        staging=args.staging,
        self_signed=is_self_signed,
        san_domains=args.san or [],
        asgi_app=asgi_app,
        live_reload=True,
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