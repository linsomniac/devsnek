"""
ASGI application support for devsnek.
"""

import os
import sys
import asyncio
import logging
import importlib
import importlib.util
from typing import Dict, Any, Callable, Optional, Tuple, List, Union
import urllib.parse
import http.client

logger = logging.getLogger(__name__)

# Type aliases
ASGIApp = Callable[[Dict[str, Any], Callable, Callable], None]
ASGIReceive = Callable[[], Dict[str, Any]]
ASGISend = Callable[[Dict[str, Any]], None]


class ASGIHandler:
    """
    Handler for running ASGI applications.
    
    Supports:
    - ASGI 3.0 protocol
    - HTTP connections
    - WebSockets (if enabled)
    """
    
    def __init__(self, asgi_app_path: str):
        """
        Initialize the ASGI handler.
        
        Args:
            asgi_app_path: Import path to the ASGI application (module:app)
        """
        self.asgi_app_path = asgi_app_path
        self.asgi_app = self._load_asgi_app(asgi_app_path)
    
    def _load_asgi_app(self, app_path: str) -> ASGIApp:
        """
        Load the ASGI application from the given path.
        
        Args:
            app_path: Import path to the ASGI application (module:app)
            
        Returns:
            The loaded ASGI application object
        """
        try:
            # Parse the module:app format
            if ":" not in app_path:
                raise ValueError(
                    f"Invalid ASGI application path: {app_path}. "
                    "Expected format: module:app"
                )
            
            module_path, app_name = app_path.rsplit(":", 1)
            
            # Add current directory to path if needed
            if os.getcwd() not in sys.path:
                sys.path.insert(0, os.getcwd())
            
            # Import the module
            module = importlib.import_module(module_path)
            
            # Get the application
            app = getattr(module, app_name)
            if not app:
                raise ValueError(f"Cannot find app '{app_name}' in module '{module_path}'")
            
            return app
        
        except Exception as e:
            logger.error(f"Failed to load ASGI application: {e}")
            raise
    
    def reload_app(self):
        """Reload the ASGI application."""
        logger.info(f"Reloading ASGI application: {self.asgi_app_path}")
        
        # Clear any cached modules
        for module_name in list(sys.modules.keys()):
            if not module_name.startswith('_') and not module_name.startswith('devsnek.'):
                if module_name in sys.modules:
                    del sys.modules[module_name]
        
        # Reload the application
        self.asgi_app = self._load_asgi_app(self.asgi_app_path)
    
    async def handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        """
        Handle an HTTP request by passing it to the ASGI application.
        
        Args:
            reader: StreamReader for the client connection
            writer: StreamWriter for the client connection
        """
        try:
            # Parse the HTTP request
            request_data = await self._parse_http_request(reader)
            if not request_data:
                return
            
            method, path, query_string, headers, body = request_data
            
            # Prepare ASGI scope
            scope = {
                "type": "http",
                "asgi": {
                    "version": "3.0",
                    "spec_version": "2.3",
                },
                "http_version": "1.1",
                "method": method,
                "scheme": "https",
                "path": path,
                "query_string": query_string,
                "root_path": "",
                "headers": [
                    (name.lower().encode("utf-8"), value.encode("utf-8"))
                    for name, value in headers.items()
                ],
                "client": None,
                "server": None,
            }
            
            # Get client and server addresses
            try:
                peer_name = writer.get_extra_info("peername")
                if peer_name:
                    scope["client"] = (peer_name[0], peer_name[1])
                
                sock_name = writer.get_extra_info("sockname")
                if sock_name:
                    scope["server"] = (sock_name[0], sock_name[1])
            except Exception:
                pass
            
            # Create response queue
            response_queue = asyncio.Queue()
            
            # Define receive and send functions
            async def receive():
                if body:
                    return {
                        "type": "http.request",
                        "body": body,
                        "more_body": False,
                    }
                else:
                    return {
                        "type": "http.disconnect",
                    }
            
            async def send(message):
                await response_queue.put(message)
            
            # Run the ASGI application
            app_task = asyncio.create_task(self.asgi_app(scope, receive, send))
            
            # Process responses
            first_response = True
            while True:
                message = await response_queue.get()
                
                if message["type"] == "http.response.start":
                    if first_response:
                        first_response = False
                        
                        # Send HTTP status line and headers
                        status = message.get("status", 200)
                        reason = http.client.responses.get(status, "Unknown")
                        response_line = f"HTTP/1.1 {status} {reason}\r\n"
                        writer.write(response_line.encode("utf-8"))
                        
                        # Send headers
                        for name, value in message.get("headers", []):
                            name = name.decode("utf-8") if isinstance(name, bytes) else name
                            value = value.decode("utf-8") if isinstance(value, bytes) else value
                            header_line = f"{name}: {value}\r\n"
                            writer.write(header_line.encode("utf-8"))
                        
                        # End of headers
                        writer.write(b"\r\n")
                        await writer.drain()
                
                elif message["type"] == "http.response.body":
                    # Send response body chunk
                    body = message.get("body", b"")
                    if body:
                        writer.write(body)
                        await writer.drain()
                    
                    # If no more body, break the loop
                    if not message.get("more_body", False):
                        break
                
                elif message["type"] == "http.disconnect":
                    break
            
            # Wait for the app to complete
            await app_task
        
        except Exception as e:
            logger.error(f"Error in ASGI handler: {e}")
            # Send a basic 500 response if possible
            try:
                if writer and not writer.transport.is_closing():
                    writer.write(b"HTTP/1.1 500 Internal Server Error\r\n")
                    writer.write(b"Content-Type: text/plain\r\n")
                    writer.write(b"Content-Length: 21\r\n")
                    writer.write(b"\r\n")
                    writer.write(b"Internal Server Error")
                    await writer.drain()
            except Exception:
                pass
    
    async def _parse_http_request(
        self, reader: asyncio.StreamReader
    ) -> Optional[Tuple[str, str, bytes, Dict[str, str], bytes]]:
        """
        Parse an HTTP request from the reader.
        
        Args:
            reader: StreamReader for the client connection
            
        Returns:
            Tuple of (method, path, query_string, headers, body) or None if parsing failed
        """
        try:
            # Read request line
            request_line = await reader.readline()
            if not request_line:
                return None
            
            # Parse method and path
            request_line = request_line.decode("utf-8").rstrip()
            words = request_line.split()
            if len(words) < 3:
                return None
            
            method, raw_path, _ = words
            
            # Parse URL and extract path and query string
            url_parts = urllib.parse.urlparse(raw_path)
            path = url_parts.path
            query_string = url_parts.query.encode("utf-8")
            
            # Read headers
            headers = {}
            content_length = 0
            
            while True:
                line = await reader.readline()
                if not line or line == b"\r\n":
                    break
                
                line = line.decode("utf-8").rstrip()
                if ":" in line:
                    name, value = line.split(":", 1)
                    name = name.strip()
                    value = value.strip()
                    headers[name] = value
                    
                    # Check for Content-Length
                    if name.lower() == "content-length":
                        try:
                            content_length = int(value)
                        except ValueError:
                            pass
            
            # Read body if Content-Length is set
            body = b""
            if content_length > 0:
                body = await reader.readexactly(content_length)
            
            return method, path, query_string, headers, body
        
        except Exception as e:
            logger.error(f"Error parsing HTTP request: {e}")
            return None
    
    async def handle_websocket(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        """
        Handle a WebSocket connection by passing it to the ASGI application.
        
        Args:
            reader: StreamReader for the client connection
            writer: StreamWriter for the client connection
        """
        # This would need a full WebSocket protocol implementation
        # For now, we'll leave this as a placeholder
        logger.warning("WebSocket support is not yet implemented")