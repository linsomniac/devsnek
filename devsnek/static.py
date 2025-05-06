"""
Static file serving handler for devsnek.

Similar to Python's built-in http.server but with added features.
"""

import os
import stat
import html
import time
import mimetypes
import urllib.parse
from typing import Optional, Tuple, Dict, Any
import asyncio
import logging

logger = logging.getLogger(__name__)

# Ensure mimetypes are initialized
mimetypes.init()


class StaticFileHandler:
    """
    Handler for serving static files from a directory.
    Mimics the behavior of python -m http.server but with async support.
    """
    
    def __init__(self, web_root: str = "web"):
        """
        Initialize the static file handler.
        
        Args:
            web_root: Directory to serve files from
        """
        self.web_root = os.path.abspath(web_root)
        
        # Ensure the web root exists
        os.makedirs(self.web_root, exist_ok=True)
    
    async def handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        """
        Handle an HTTP request.
        
        Args:
            reader: StreamReader for the client connection
            writer: StreamWriter for the client connection
        """
        try:
            # Parse the request
            request = await self._parse_request(reader)
            if not request:
                return
            
            method, path, _ = request
            
            # Validate and normalize the path
            fs_path = self._get_fs_path(path)
            if not fs_path:
                await self._send_error(writer, 404, "Not Found")
                return
            
            # Handle different request methods
            if method == "GET":
                await self._handle_get(writer, fs_path)
            elif method == "HEAD":
                await self._handle_head(writer, fs_path)
            else:
                await self._send_error(writer, 405, "Method Not Allowed")
        
        except Exception as e:
            logger.error(f"Error in static file handler: {e}")
            try:
                await self._send_error(writer, 500, "Internal Server Error")
            except Exception:
                pass
    
    async def _parse_request(self, reader: asyncio.StreamReader) -> Optional[Tuple[str, str, Dict[str, str]]]:
        """
        Parse an HTTP request.
        
        Args:
            reader: StreamReader for the client connection
            
        Returns:
            Tuple of (method, path, headers) or None if parsing failed
        """
        # Read the request line
        try:
            request_line = await reader.readline()
            if not request_line:
                return None
            
            request_line = request_line.decode('utf-8').rstrip()
            words = request_line.split()
            
            if len(words) < 3:
                return None
            
            method, path, _ = words
            
            # Parse headers
            headers = {}
            while True:
                line = await reader.readline()
                if not line or line == b'\r\n':
                    break
                
                line = line.decode('utf-8').rstrip()
                if ':' in line:
                    key, value = line.split(':', 1)
                    headers[key.strip().lower()] = value.strip()
            
            return method, path, headers
        
        except Exception as e:
            logger.error(f"Error parsing request: {e}")
            return None
    
    def _get_fs_path(self, path: str) -> Optional[str]:
        """
        Validate and normalize a request path to a filesystem path.
        
        Args:
            path: Request path
            
        Returns:
            Filesystem path or None if invalid
        """
        # Parse the path
        path = urllib.parse.unquote(path)
        if path.startswith('/'):
            path = path[1:]
        
        # Normalize and check for path traversal
        path = os.path.normpath(path)
        if path.startswith('..') or '/../' in path or path.endswith('/..'):
            return None
        
        # Combine with web root
        fs_path = os.path.join(self.web_root, path)
        
        # Check if the path is within the web root
        if not os.path.abspath(fs_path).startswith(self.web_root):
            return None
        
        return fs_path
    
    async def _handle_get(self, writer: asyncio.StreamWriter, fs_path: str):
        """
        Handle a GET request.
        
        Args:
            writer: StreamWriter for the client connection
            fs_path: Filesystem path to serve
        """
        # Check if the path exists
        if not os.path.exists(fs_path):
            await self._send_error(writer, 404, "Not Found")
            return
        
        # If it's a directory, serve a directory listing
        if os.path.isdir(fs_path):
            await self._send_directory_listing(writer, fs_path)
            return
        
        # Serve the file
        try:
            # Get file size and modification time
            stat_result = os.stat(fs_path)
            file_size = stat_result.st_size
            mtime = stat_result.st_mtime
            
            # Get content type
            content_type, encoding = mimetypes.guess_type(fs_path)
            if content_type is None:
                content_type = "application/octet-stream"
            
            # Send headers
            headers = [
                "HTTP/1.1 200 OK",
                f"Content-Length: {file_size}",
                f"Content-Type: {content_type}",
                f"Last-Modified: {self._format_date(mtime)}",
                "Connection: close",
                "\r\n"
            ]
            writer.write("\r\n".join(headers).encode('utf-8'))
            
            # Send file in chunks
            with open(fs_path, 'rb') as f:
                chunk_size = 64 * 1024  # 64 KB chunks
                while True:
                    chunk = f.read(chunk_size)
                    if not chunk:
                        break
                    writer.write(chunk)
                    await writer.drain()
        
        except Exception as e:
            logger.error(f"Error serving file {fs_path}: {e}")
            await self._send_error(writer, 500, "Internal Server Error")
    
    async def _handle_head(self, writer: asyncio.StreamWriter, fs_path: str):
        """
        Handle a HEAD request.
        
        Args:
            writer: StreamWriter for the client connection
            fs_path: Filesystem path to check
        """
        # Check if the path exists
        if not os.path.exists(fs_path):
            await self._send_error(writer, 404, "Not Found", include_body=False)
            return
        
        # If it's a directory, send directory info
        if os.path.isdir(fs_path):
            await self._send_directory_info(writer, fs_path)
            return
        
        # Send file info
        try:
            # Get file size and modification time
            stat_result = os.stat(fs_path)
            file_size = stat_result.st_size
            mtime = stat_result.st_mtime
            
            # Get content type
            content_type, encoding = mimetypes.guess_type(fs_path)
            if content_type is None:
                content_type = "application/octet-stream"
            
            # Send headers
            headers = [
                "HTTP/1.1 200 OK",
                f"Content-Length: {file_size}",
                f"Content-Type: {content_type}",
                f"Last-Modified: {self._format_date(mtime)}",
                "Connection: close",
                "\r\n"
            ]
            writer.write("\r\n".join(headers).encode('utf-8'))
        
        except Exception as e:
            logger.error(f"Error processing HEAD for {fs_path}: {e}")
            await self._send_error(writer, 500, "Internal Server Error", include_body=False)
    
    async def _send_directory_listing(self, writer: asyncio.StreamWriter, fs_path: str):
        """
        Send a directory listing.
        
        Args:
            writer: StreamWriter for the client connection
            fs_path: Filesystem path to list
        """
        try:
            # Get the relative path for display
            rel_path = os.path.relpath(fs_path, self.web_root)
            if rel_path == '.':
                display_path = '/'
            else:
                display_path = '/' + rel_path.replace('\\', '/')
            
            # Prepare the HTML listing
            listing = []
            listing.append('<!DOCTYPE HTML>')
            listing.append('<html lang="en">')
            listing.append('<head>')
            listing.append(f'<title>Directory listing for {html.escape(display_path)}</title>')
            listing.append('<meta charset="utf-8">')
            listing.append('<meta name="viewport" content="width=device-width, initial-scale=1">')
            listing.append('<style>')
            listing.append('body { font-family: Arial, sans-serif; margin: 2em; }')
            listing.append('h1 { margin-bottom: 1em; }')
            listing.append('ul { list-style-type: none; padding: 0; }')
            listing.append('li { margin: 0.5em 0; }')
            listing.append('a { text-decoration: none; color: #0366d6; }')
            listing.append('a:hover { text-decoration: underline; }')
            listing.append('.directory { font-weight: bold; }')
            listing.append('.back { margin-bottom: 1em; }')
            listing.append('</style>')
            listing.append('</head>')
            listing.append('<body>')
            listing.append(f'<h1>Directory listing for {html.escape(display_path)}</h1>')
            
            # Add parent directory link if not at root
            if display_path != '/':
                parent_path = os.path.dirname(display_path.rstrip('/'))
                if not parent_path:
                    parent_path = '/'
                listing.append('<div class="back">')
                listing.append(f'<a href="{html.escape(parent_path)}">&laquo; Parent Directory</a>')
                listing.append('</div>')
            
            # List entries
            listing.append('<ul>')
            
            try:
                entries = os.listdir(fs_path)
                entries.sort(key=lambda x: (not os.path.isdir(os.path.join(fs_path, x)), x.lower()))
                
                for name in entries:
                    full_path = os.path.join(fs_path, name)
                    link_path = urllib.parse.quote(
                        os.path.join(display_path, name).lstrip('/')
                    )
                    
                    # Skip hidden files
                    if name.startswith('.'):
                        continue
                    
                    # Get file info
                    stat_result = os.stat(full_path)
                    size = stat_result.st_size
                    mtime = stat_result.st_mtime
                    
                    # Format modification time
                    mod_time = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(mtime))
                    
                    # Add directory indicator
                    if os.path.isdir(full_path):
                        name = name + '/'
                        size = ''
                        css_class = ' class="directory"'
                    else:
                        size = self._format_size(size)
                        css_class = ''
                    
                    listing.append(f'<li><a href="/{link_path}"{css_class}>{html.escape(name)}</a> {mod_time} {size}</li>')
            
            except Exception as e:
                listing.append(f'<li>Error reading directory: {html.escape(str(e))}</li>')
            
            listing.append('</ul>')
            listing.append('</body>')
            listing.append('</html>')
            
            # Send the listing
            content = '\n'.join(listing).encode('utf-8')
            headers = [
                "HTTP/1.1 200 OK",
                f"Content-Length: {len(content)}",
                "Content-Type: text/html; charset=utf-8",
                "Connection: close",
                "\r\n"
            ]
            writer.write("\r\n".join(headers).encode('utf-8'))
            writer.write(content)
            await writer.drain()
        
        except Exception as e:
            logger.error(f"Error generating directory listing for {fs_path}: {e}")
            await self._send_error(writer, 500, "Internal Server Error")
    
    async def _send_directory_info(self, writer: asyncio.StreamWriter, fs_path: str):
        """
        Send directory info for HEAD requests.
        
        Args:
            writer: StreamWriter for the client connection
            fs_path: Filesystem path to the directory
        """
        try:
            # Send headers for directory
            headers = [
                "HTTP/1.1 200 OK",
                "Content-Type: text/html; charset=utf-8",
                "Connection: close",
                "\r\n"
            ]
            writer.write("\r\n".join(headers).encode('utf-8'))
        except Exception as e:
            logger.error(f"Error sending directory info for {fs_path}: {e}")
            await self._send_error(writer, 500, "Internal Server Error", include_body=False)
    
    async def _send_error(self, writer: asyncio.StreamWriter, code: int, message: str, include_body: bool = True):
        """
        Send an HTTP error response.
        
        Args:
            writer: StreamWriter for the client connection
            code: HTTP status code
            message: Error message
            include_body: Whether to include a response body
        """
        try:
            # Create the error HTML
            error_content = f"<html><head><title>{code} {message}</title></head><body><h1>{code} {message}</h1></body></html>"
            error_bytes = error_content.encode('utf-8')
            
            # Send headers
            headers = [
                f"HTTP/1.1 {code} {message}",
                "Content-Type: text/html; charset=utf-8",
                f"Content-Length: {len(error_bytes)}",
                "Connection: close",
                "\r\n"
            ]
            writer.write("\r\n".join(headers).encode('utf-8'))
            
            # Send body if requested
            if include_body:
                writer.write(error_bytes)
            
            await writer.drain()
        except Exception as e:
            logger.error(f"Error sending HTTP error response: {e}")
    
    @staticmethod
    def _format_date(timestamp):
        """Format a timestamp for HTTP headers."""
        return time.strftime("%a, %d %b %Y %H:%M:%S GMT", time.gmtime(timestamp))
    
    @staticmethod
    def _format_size(size):
        """Format a file size for display."""
        for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
            if size < 1024:
                return f"{size:.1f} {unit}" if size % 1 else f"{int(size)} {unit}"
            size /= 1024
        return f"{size:.1f} PB"