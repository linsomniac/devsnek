"""
HTTP to HTTPS redirection for devsnek.
"""

import asyncio
import logging
import socket
from typing import Optional, Tuple

logger = logging.getLogger(__name__)


async def find_available_port(start_port: int, max_attempts: int = 10) -> Optional[int]:
    """
    Find an available port starting from start_port.
    
    Args:
        start_port: The port to start trying from
        max_attempts: Maximum number of ports to try
        
    Returns:
        An available port or None if none found
    """
    for offset in range(max_attempts):
        test_port = start_port + offset
        try:
            # Try to bind to the port
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.bind(('', test_port))
            sock.close()
            return test_port
        except OSError:
            continue
    return None


class HTTPToHTTPSRedirector:
    """
    Simple HTTP server that redirects all requests to HTTPS.
    """
    
    def __init__(self, target_host: str, target_port: int, listen_port: int = 8080):
        """
        Initialize the redirector.
        
        Args:
            target_host: Host to redirect to
            target_port: HTTPS port to redirect to
            listen_port: Port to listen on for HTTP requests
        """
        self.target_host = target_host
        self.target_port = target_port
        self.requested_port = listen_port
        self.actual_port = None  # Will be set when server starts
        self.server = None
        self.start_attempts = 0
        self.max_start_attempts = 3
        
        logger.info(f"HTTP redirector will listen on port {self.requested_port} and redirect to https://{self.target_host}:{self.target_port}")
    
    async def start(self):
        """Start the redirector server."""
        self.start_attempts += 1
        
        try:
            # First try the requested port
            try:
                self.server = await asyncio.start_server(
                    self.handle_client, 
                    host='0.0.0.0',  # Listen on all interfaces
                    port=self.requested_port
                )
                self.actual_port = self.requested_port
                logger.info(f"HTTP to HTTPS redirector running on port {self.actual_port}")
            except OSError as e:
                if e.errno == 98:  # Address already in use
                    # Port is already in use, try to find an available port
                    logger.warning(f"Port {self.requested_port} is already in use for HTTP redirection")
                    
                    # Try to find an available port
                    available_port = await find_available_port(self.requested_port + 1)
                    if available_port:
                        logger.info(f"Found available port for HTTP redirection: {available_port}")
                        try:
                            self.server = await asyncio.start_server(
                                self.handle_client,
                                host='0.0.0.0',  # Listen on all interfaces
                                port=available_port
                            )
                            self.actual_port = available_port
                            logger.info(f"HTTP to HTTPS redirector running on port {self.actual_port} (fallback from {self.requested_port})")
                        except Exception as inner_e:
                            logger.error(f"Error starting HTTP redirector on fallback port {available_port}: {inner_e}")
                            logger.warning("HTTP-to-HTTPS redirection is disabled")
                            return
                    else:
                        logger.error("Could not find an available port for HTTP redirection")
                        logger.error("Use --no-redirect to disable HTTP redirection if this is intentional")
                        logger.warning("HTTP-to-HTTPS redirection is disabled")
                        return
                else:
                    logger.error(f"Failed to start HTTP redirector: {e}")
                    logger.warning("HTTP-to-HTTPS redirection is disabled")
                    return
            
            # Start serving in the background
            asyncio.create_task(self.server.serve_forever())
            
        except Exception as e:
            logger.error(f"Failed to start HTTP redirector: {e}")
            logger.error("Use --no-redirect to disable HTTP redirection if this is intentional")
            logger.warning("HTTP-to-HTTPS redirection is disabled")
            
            # If serious error, try again with a delay
            if self.start_attempts <= self.max_start_attempts:
                logger.info(f"Retrying HTTP redirector start in 2 seconds (attempt {self.start_attempts}/{self.max_start_attempts})")
                await asyncio.sleep(2)
                await self.start()
    
    async def stop(self):
        """Stop the redirector server."""
        if self.server:
            self.server.close()
            await self.server.wait_closed()
            self.server = None
            logger.info(f"HTTP to HTTPS redirector stopped (was using port {self.actual_port})")
    
    def get_port(self) -> int:
        """Get the actual port being used for redirection."""
        return self.actual_port or self.requested_port
    
    async def handle_client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        """
        Handle a client connection.
        
        Args:
            reader: StreamReader for the client connection
            writer: StreamWriter for the client connection
        """
        try:
            # Parse the request to get the path
            request_info = await self._parse_request(reader)
            if not request_info:
                writer.close()
                return
            
            path = request_info[1]
            
            # Create the redirect URL
            redirect_url = f"https://{self.target_host}"
            if self.target_port != 443:
                redirect_url += f":{self.target_port}"
            redirect_url += path
            
            # Send the redirect response
            response = "\r\n".join([
                "HTTP/1.1 301 Moved Permanently",
                f"Location: {redirect_url}",
                "Connection: close",
                "Content-Length: 0",
                "\r\n"
            ]).encode('utf-8')
            
            writer.write(response)
            await writer.drain()
        
        except Exception as e:
            logger.error(f"Error in HTTP redirector: {e}")
        
        finally:
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass
    
    async def _parse_request(self, reader: asyncio.StreamReader) -> Optional[Tuple[str, str]]:
        """
        Parse the HTTP request to extract method and path.
        
        Args:
            reader: StreamReader for the client connection
            
        Returns:
            Tuple of (method, path) or None if parsing failed
        """
        try:
            # Read the request line
            request_line = await reader.readline()
            if not request_line:
                return None
            
            # Parse the request line
            request_line = request_line.decode('utf-8').rstrip()
            words = request_line.split()
            if len(words) < 2:
                return None
            
            method, path = words[0], words[1]
            return method, path
        
        except Exception as e:
            logger.error(f"Error parsing redirect request: {e}")
            return None