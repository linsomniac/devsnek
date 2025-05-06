"""
Core server implementation for devsnek.
"""

import os
import ssl
import logging
import asyncio
from typing import Optional, Dict, Any, Union, List

from .cert_manager import CertificateManager
from .config import ServerConfig, load_config
from .static import StaticFileHandler
from .asgi import ASGIHandler
from .reload import setup_reload_watcher
from .redirect import HTTPToHTTPSRedirector

logger = logging.getLogger(__name__)

class DevServer:
    """
    Development HTTPS server with automatic certificate provisioning.
    
    Supports:
    - Static file serving
    - ASGI application hosting
    - Live reloading
    - WebSockets
    - HTTP to HTTPS redirection
    """
    
    def __init__(
        self, 
        config: Union[ServerConfig, Dict[str, Any], str, None] = None,
    ):
        """
        Initialize the server with the given configuration.
        
        Args:
            config: ServerConfig object, dictionary, path to a YAML file, or None for defaults
        """
        # Load configuration
        if config is None:
            self.config = ServerConfig()
        elif isinstance(config, ServerConfig):
            self.config = config
        elif isinstance(config, dict):
            self.config = ServerConfig(**config)
        elif isinstance(config, str):
            self.config = load_config(config)
        else:
            raise TypeError(f"Unsupported config type: {type(config)}")
        
        # Initialize certificate manager with SAN domains
        # Only include SAN domains in the certificate (not the bind address)
        cert_domains = self.config.san_domains if self.config.san_domains else ["localhost"]
        self.cert_manager = CertificateManager(
            domains=cert_domains,
            email=self.config.email,
            certs_dir=self.config.certs_dir,
            staging=self.config.staging,
            self_signed=self.config.self_signed,
            skip_port_check=self.config.skip_port_check,
        )
        
        # Initialize handlers
        self.reload_task = None
        if self.config.asgi_app:
            self.handler = ASGIHandler(self.config.asgi_app)
        else:
            self.handler = StaticFileHandler(self.config.web_root)
        
        # Redirector for HTTP to HTTPS
        self.redirector = None
        if self.config.redirect_http:
            # Use the primary certificate domain for redirection if available
            # This ensures that redirects go to a domain name in the certificate
            redirect_host = self.cert_manager.primary_domain
            if redirect_host == "localhost" and self.config.bind_addr != "localhost":
                redirect_host = self.config.bind_addr
                
            self.redirector = HTTPToHTTPSRedirector(
                target_host=redirect_host,
                target_port=self.config.port,
                listen_port=self.config.http_port,
            )
    
    async def start(self):
        """Start the server and any background tasks."""
        # Ensure we have valid certificates
        await self.cert_manager.ensure_certificates()
        
        # Setup SSL context
        ssl_context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        ssl_context.load_cert_chain(
            self.cert_manager.cert_path, 
            self.cert_manager.key_path
        )
        
        # Start HTTPS server
        https_server = await asyncio.start_server(
            self.handle_client,
            self.config.bind_addr,
            self.config.port,
            ssl=ssl_context,
        )
        
        # Start HTTP redirector if enabled
        if self.redirector:
            await self.redirector.start()
        
        # Setup live reload if enabled and in ASGI mode
        if self.config.live_reload and self.config.asgi_app:
            self.reload_task = asyncio.create_task(
                setup_reload_watcher(self.handler, self.config.reload_dirs)
            )
        
        # Log server start
        # Use primary domain from certificate if available
        primary_domain = self.cert_manager.primary_domain
        bind_info = f"{self.config.bind_addr}:{self.config.port}"
        domain_info = f"{primary_domain}:{self.config.port}" if primary_domain != "localhost" else bind_info
        
        logger.info(f"Server running at https://{bind_info}")
        if primary_domain != "localhost" and self.config.bind_addr != primary_domain:
            logger.info(f"Certificate issued for: {primary_domain} (access via https://{domain_info})")
        
        try:
            async with https_server:
                await https_server.serve_forever()
        finally:
            # Cleanup
            if self.reload_task:
                self.reload_task.cancel()
            if self.redirector:
                await self.redirector.stop()
    
    async def handle_client(self, reader, writer):
        """Handle an incoming client connection."""
        try:
            await self.handler.handle(reader, writer)
        except Exception as e:
            logger.error(f"Error handling client: {e}")
        finally:
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass


async def run_server(config=None):
    """Run the server with the given configuration."""
    server = DevServer(config)
    await server.start()