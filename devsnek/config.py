"""
Configuration handling for devsnek.
"""

import os
import yaml
from dataclasses import dataclass, field
from typing import List, Optional, Dict, Any, Union

@dataclass
class ServerConfig:
    """Configuration for the development server."""
    
    # Server basics
    host: str = "localhost"
    port: int = 8443
    
    # Certificate configuration
    certs_dir: str = "certs"
    email: Optional[str] = None
    san_domains: List[str] = field(default_factory=list)
    staging: bool = False
    
    # Static file serving
    web_root: str = "web"
    
    # ASGI application
    asgi_app: Optional[str] = None
    
    # HTTP to HTTPS redirection
    redirect_http: bool = True
    redirect_port: int = 8080
    
    # Live reload
    live_reload: bool = True
    reload_dirs: List[str] = field(default_factory=lambda: ["."])
    
    # WebSocket support
    enable_websocket: bool = True
    
    # Logging
    log_level: str = "INFO"
    

def load_config(config_path: str) -> ServerConfig:
    """
    Load configuration from a YAML file.
    
    Args:
        config_path: Path to YAML configuration file
        
    Returns:
        ServerConfig object with values from the YAML file
    """
    if not os.path.exists(config_path):
        raise FileNotFoundError(f"Configuration file not found: {config_path}")
    
    with open(config_path, 'r') as f:
        config_data = yaml.safe_load(f)
    
    if not isinstance(config_data, dict):
        raise ValueError("Invalid configuration format. Expected a YAML dictionary.")
    
    return ServerConfig(**config_data)


def save_config(config: ServerConfig, config_path: str):
    """
    Save configuration to a YAML file.
    
    Args:
        config: ServerConfig object to save
        config_path: Path to save the YAML configuration
    """
    # Convert dataclass to dictionary
    config_dict = {
        key: getattr(config, key) 
        for key in config.__dataclass_fields__ 
        if getattr(config, key) is not None
    }
    
    # Ensure directory exists
    os.makedirs(os.path.dirname(os.path.abspath(config_path)), exist_ok=True)
    
    # Write to YAML file
    with open(config_path, 'w') as f:
        yaml.dump(config_dict, f, default_flow_style=False)