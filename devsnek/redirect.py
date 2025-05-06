"""
HTTP to HTTPS redirection for devsnek.
"""

import asyncio
import logging
from typing import Optional, Tuple

logger = logging.getLogger(__name__)


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
        self.listen_port = listen_port
        self.server = None
    
    async def start(self):
        """Start the redirector server."""
        try:
            self.server = await asyncio.start_server(
                self.handle_client, 
                host='0.0.0.0',  # Listen on all interfaces
                port=self.listen_port
            )
            
            logger.info(f"HTTP to HTTPS redirector running on port {self.listen_port}")
            
            # Start serving in the background
            asyncio.create_task(self.server.serve_forever())
        
        except Exception as e:
            logger.error(f"Failed to start HTTP redirector: {e}")
    
    async def stop(self):
        """Stop the redirector server."""
        if self.server:
            self.server.close()
            await self.server.wait_closed()
            self.server = None
    
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