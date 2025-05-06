"""
Live reloading support for devsnek.
"""

import os
import sys
import time
import asyncio
import logging
from typing import List, Set, Dict, Any, Optional
import fnmatch

logger = logging.getLogger(__name__)


class FileWatcher:
    """
    Watches directories for file changes to trigger reloads.
    """
    
    def __init__(self, dirs: List[str], exclude_patterns: Optional[List[str]] = None):
        """
        Initialize the file watcher.
        
        Args:
            dirs: List of directories to watch
            exclude_patterns: Optional glob patterns to exclude
        """
        self.dirs = [os.path.abspath(d) for d in dirs]
        self.exclude_patterns = exclude_patterns or [
            "*/__pycache__/*", "*/\.*", "*.pyc", "*.pyo", 
            "*.swp", "*.swx", "*.~*"
        ]
        self.mtimes: Dict[str, float] = {}
        self.last_reload_time = time.time()
    
    def _is_excluded(self, path: str) -> bool:
        """
        Check if a path matches any exclusion pattern.
        
        Args:
            path: Path to check
            
        Returns:
            True if the path should be excluded, False otherwise
        """
        path = os.path.normpath(path)
        return any(fnmatch.fnmatch(path, pattern) for pattern in self.exclude_patterns)
    
    def _scan_dir(self, directory: str) -> Dict[str, float]:
        """
        Scan a directory for files and get their modification times.
        
        Args:
            directory: Directory to scan
            
        Returns:
            Dictionary mapping file paths to modification times
        """
        mtimes: Dict[str, float] = {}
        
        try:
            for root, dirs, files in os.walk(directory):
                # Skip excluded directories
                dirs[:] = [d for d in dirs if not self._is_excluded(os.path.join(root, d))]
                
                # Check files
                for filename in files:
                    file_path = os.path.join(root, filename)
                    
                    # Skip excluded files
                    if self._is_excluded(file_path):
                        continue
                    
                    # Only watch Python files for now
                    if not file_path.endswith('.py'):
                        continue
                    
                    try:
                        mtime = os.stat(file_path).st_mtime
                        mtimes[file_path] = mtime
                    except (OSError, IOError):
                        # Skip files that can't be accessed
                        pass
        
        except Exception as e:
            logger.error(f"Error scanning directory {directory}: {e}")
        
        return mtimes
    
    def check_for_changes(self) -> bool:
        """
        Check if any files have changed since the last scan.
        
        Returns:
            True if changes were detected, False otherwise
        """
        # Don't reload too frequently
        if time.time() - self.last_reload_time < 1.0:
            return False
        
        # Scan all directories
        current_mtimes: Dict[str, float] = {}
        for directory in self.dirs:
            current_mtimes.update(self._scan_dir(directory))
        
        # Check for changes
        if not self.mtimes:
            # First run, just store the mtimes
            self.mtimes = current_mtimes
            return False
        
        # Look for added/modified files
        for file_path, mtime in current_mtimes.items():
            if file_path not in self.mtimes or self.mtimes[file_path] < mtime:
                self.mtimes = current_mtimes
                self.last_reload_time = time.time()
                return True
        
        # Look for deleted files
        if set(self.mtimes.keys()) - set(current_mtimes.keys()):
            self.mtimes = current_mtimes
            self.last_reload_time = time.time()
            return True
        
        return False


async def setup_reload_watcher(handler, dirs: List[str]) -> None:
    """
    Setup a watcher to reload the ASGI application when files change.
    
    Args:
        handler: The ASGI handler with a reload_app method
        dirs: List of directories to watch
    """
    watcher = FileWatcher(dirs)
    
    while True:
        if watcher.check_for_changes():
            try:
                logger.info("Changes detected, reloading application")
                handler.reload_app()
            except Exception as e:
                logger.error(f"Error reloading application: {e}")
        
        # Wait before checking again
        await asyncio.sleep(1)