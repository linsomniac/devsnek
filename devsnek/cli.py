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


def setup_logging(level: str = "INFO", verbose: bool = False):
    """
    Setup logging configuration.
    
    Args:
        level: Logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
        verbose: Enable verbose output
    """
    # Set log level
    numeric_level = getattr(logging, level.upper(), None)
    if not isinstance(numeric_level, int):
        numeric_level = logging.INFO
    
    # Detailed format when verbose mode is enabled
    if verbose:
        log_format = "%(asctime)s - %(name)s - %(levelname)s - %(filename)s:%(lineno)d - %(message)s"
    else:
        log_format = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
    
    # Configure basic logging
    logging.basicConfig(
        level=numeric_level,
        format=log_format,
        datefmt="%Y-%m-%d %H:%M:%S",
    )
    
    # If verbose mode is enabled, set specific loggers to DEBUG
    if verbose:
        # Set DEBUG level specifically for our modules
        logging.getLogger('devsnek.cert_manager').setLevel(logging.DEBUG)
        logging.getLogger('devsnek.direct_acme').setLevel(logging.DEBUG)
        
        # Also set DEBUG for ACME client
        logging.getLogger('acme.client').setLevel(logging.DEBUG)
        logging.getLogger('urllib3').setLevel(logging.INFO)  # Reduce urllib3 verbosity
        
        # Log some system information that might help with debugging
        import sys
        import platform
        logging.info(f"Python version: {sys.version}")
        logging.info(f"Platform: {platform.platform()}")
        logging.info(f"Current directory: {os.getcwd()}")
        
        # Check for port 80 availability
        import socket
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.bind(('', 80))
            sock.close()
            logging.info("Port 80 is available for ACME challenge")
        except socket.error:
            logging.warning("Port 80 is already in use - Let's Encrypt HTTP challenge will likely fail")


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
        "--bind-addr", 
        default="localhost",
        help="Address to bind to (default: localhost)"
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
    parser.add_argument(
        "--skip-port-check", 
        action="store_true",
        help="Skip port 80 availability check (for setups with proxies/port forwarding)"
    )
    parser.add_argument(
        "--self-signed", 
        action="store_true",
        help="Use self-signed certificates instead of Let's Encrypt"
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
        "--http-port", 
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
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Enable verbose output for debugging"
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
    config.bind_addr = args.bind_addr
    config.port = args.port
    
    # Certificate configuration
    config.certs_dir = args.certs_dir
    config.email = args.email
    config.san_domains = args.san or []
    config.staging = args.staging
    config.skip_port_check = args.skip_port_check
    
    # Set self_signed mode based on CLI arguments or SAN domains
    if args.self_signed:
        config.self_signed = True
    elif not args.san:
        # Default to self-signed if no SAN domains are provided
        config.self_signed = True
    else:
        config.self_signed = False
    
    # Static file serving
    config.web_root = args.web_root
    
    # ASGI application
    config.asgi_app = args.asgi_app
    
    # HTTP to HTTPS redirection
    config.redirect_http = not args.no_redirect
    config.http_port = args.http_port
    
    # Live reload
    config.live_reload = not args.no_reload
    config.reload_dirs = args.reload_dirs or ["."]
    
    # WebSocket support
    config.enable_websocket = not args.no_websocket
    
    # Logging
    config.log_level = args.log_level
    config.verbose = args.verbose
    
    return config


def main():
    """Main entry point for the CLI."""
    args = parse_args()
    
    # Setup logging
    setup_logging(args.log_level, args.verbose)
    
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