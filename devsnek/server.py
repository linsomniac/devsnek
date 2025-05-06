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
        
        # Initialize certificate manager
        self.cert_manager = CertificateManager(
            domains=[self.config.host] + self.config.san_domains,
            email=self.config.email,
            certs_dir=self.config.certs_dir,
            staging=self.config.staging,
        )
        
        # Initialize handlers
        if self.config.asgi_app:
            self.handler = ASGIHandler(self.config.asgi_app)
            self.reload_task = None
        else:
            self.handler = StaticFileHandler(self.config.web_root)
            self.reload_task = None
        
        # Redirector for HTTP to HTTPS
        self.redirector = None
        if self.config.redirect_http:
            self.redirector = HTTPToHTTPSRedirector(
                target_host=self.config.host,
                target_port=self.config.port,
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
            self.config.host,
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
        logger.info(f"Server running at https://{self.config.host}:{self.config.port}")
        
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