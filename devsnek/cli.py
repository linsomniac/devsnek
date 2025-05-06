"""
Command line interface for devsnek.
"""

import os
import sys
import argparse
import asyncio
import logging
from typing import Optional, Dict, Any, List

from .server import DevServer, run_server
from .config import ServerConfig, load_config, save_config


def setup_logging(level: str = "INFO"):
    """
    Setup logging configuration.
    
    Args:
        level: Logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
    """
    numeric_level = getattr(logging, level.upper(), None)
    if not isinstance(numeric_level, int):
        numeric_level = logging.INFO
    
    logging.basicConfig(
        level=numeric_level,
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )


def parse_args():
    """
    Parse command line arguments.
    
    Returns:
        Parsed arguments namespace
    """
    parser = argparse.ArgumentParser(
        description="devsnek: Python development web server with LetsEncrypt support"
    )
    
    # Server configuration options
    parser.add_argument(
        "--host", 
        default="localhost",
        help="Host to bind to (default: localhost)"
    )
    parser.add_argument(
        "--port", 
        type=int, 
        default=8443,
        help="Port to bind to (default: 8443)"
    )
    
    # Certificate options
    parser.add_argument(
        "--certs-dir", 
        default="certs",
        help="Directory to store certificates (default: certs)"
    )
    parser.add_argument(
        "--email",
        help="Email address for Let's Encrypt registration"
    )
    parser.add_argument(
        "--san", 
        action="append", 
        help="Subject Alternative Name(s) to include in the certificate"
    )
    parser.add_argument(
        "--staging", 
        action="store_true",
        help="Use Let's Encrypt staging environment"
    )
    
    # Static file serving options
    parser.add_argument(
        "--web-root", 
        default="web",
        help="Directory to serve static files from (default: web)"
    )
    
    # ASGI options
    parser.add_argument(
        "--asgi-app",
        help="ASGI application to run (format: module:app)"
    )
    
    # Redirection options
    parser.add_argument(
        "--no-redirect", 
        action="store_true",
        help="Disable HTTP to HTTPS redirection"
    )
    parser.add_argument(
        "--redirect-port", 
        type=int, 
        default=8080,
        help="Port to listen on for HTTP redirection (default: 8080)"
    )
    
    # Live reload options
    parser.add_argument(
        "--no-reload", 
        action="store_true",
        help="Disable live reloading for ASGI applications"
    )
    parser.add_argument(
        "--reload-dir", 
        action="append", 
        dest="reload_dirs",
        help="Directories to watch for changes (can be specified multiple times)"
    )
    
    # WebSocket options
    parser.add_argument(
        "--no-websocket", 
        action="store_true",
        help="Disable WebSocket support"
    )
    
    # Logging options
    parser.add_argument(
        "--log-level",
        choices=["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"],
        default="INFO",
        help="Logging level (default: INFO)"
    )
    
    # Configuration file options
    parser.add_argument(
        "--config",
        help="Path to YAML configuration file"
    )
    parser.add_argument(
        "--save-config",
        help="Save configuration to YAML file and exit"
    )
    
    return parser.parse_args()


def create_config_from_args(args) -> ServerConfig:
    """
    Create a ServerConfig object from parsed command line arguments.
    
    Args:
        args: Parsed command line arguments
        
    Returns:
        ServerConfig object
    """
    config = ServerConfig()
    
    # Server configuration
    config.host = args.host
    config.port = args.port
    
    # Certificate configuration
    config.certs_dir = args.certs_dir
    config.email = args.email
    config.san_domains = args.san or []
    config.staging = args.staging
    
    # Static file serving
    config.web_root = args.web_root
    
    # ASGI application
    config.asgi_app = args.asgi_app
    
    # HTTP to HTTPS redirection
    config.redirect_http = not args.no_redirect
    config.redirect_port = args.redirect_port
    
    # Live reload
    config.live_reload = not args.no_reload
    config.reload_dirs = args.reload_dirs or ["."]
    
    # WebSocket support
    config.enable_websocket = not args.no_websocket
    
    # Logging
    config.log_level = args.log_level
    
    return config


def main():
    """Main entry point for the CLI."""
    args = parse_args()
    
    # Setup logging
    setup_logging(args.log_level)
    
    # Load configuration from file if provided
    config = None
    if args.config:
        try:
            config = load_config(args.config)
        except Exception as e:
            print(f"Error loading configuration file: {e}", file=sys.stderr)
            sys.exit(1)
    else:
        # Create configuration from command line arguments
        config = create_config_from_args(args)
    
    # Save configuration if requested
    if args.save_config:
        try:
            save_config(config, args.save_config)
            print(f"Configuration saved to {args.save_config}")
            sys.exit(0)
        except Exception as e:
            print(f"Error saving configuration: {e}", file=sys.stderr)
            sys.exit(1)
    
    # Create and run the server
    try:
        asyncio.run(run_server(config))
    except KeyboardInterrupt:
        print("Server stopped.")
    except Exception as e:
        print(f"Error starting server: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()