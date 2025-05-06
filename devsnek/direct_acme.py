"""
Direct ACME client implementation for certificate generation.

This module provides a simplified, direct implementation of the ACME protocol
for Let's Encrypt certificate issuance.
"""

import os
import json
import time
import logging
import hashlib
import base64
import binascii
import subprocess
from typing import List, Dict, Any, Optional, Tuple
import http.server
import threading
import requests
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from cryptography.x509.oid import NameOID

logger = logging.getLogger(__name__)

# Constants
LE_STAGING_URL = "https://acme-staging-v02.api.letsencrypt.org/directory"
LE_PRODUCTION_URL = "https://acme-v02.api.letsencrypt.org/directory"


def b64(data: bytes) -> str:
    """Base64 encode data for JWS."""
    return base64.urlsafe_b64encode(data).decode('utf8').rstrip('=')


class ACMEChallenger(http.server.BaseHTTPRequestHandler):
    """Simple HTTP server to respond to ACME HTTP-01 challenges."""

    def __init__(self, *args, **kwargs):
        self.token_responses = kwargs.pop('token_responses', {})
        super().__init__(*args, **kwargs)

    def do_GET(self):
        if self.path.startswith('/.well-known/acme-challenge/'):
            token = self.path.split('/')[-1]
            if token in self.token_responses:
                self.send_response(200)
                self.send_header('Content-Type', 'text/plain')
                self.end_headers()
                self.wfile.write(self.token_responses[token].encode('utf-8'))
                return

        self.send_response(404)
        self.end_headers()
        self.wfile.write(b'Not Found')

    def log_message(self, format, *args):
        """Silence HTTP server logs."""
        return


class ACMEClient:
    """
    Simple ACME client for Let's Encrypt certificate issuance.
    
    This implementation focuses on reliability and simplicity rather than 
    covering all features of the ACME protocol.
    """

    def __init__(self, 
                 domains: List[str], 
                 email: Optional[str] = None,
                 staging: bool = False,
                 cert_dir: str = 'certs'):
        """
        Initialize the ACME client.
        
        Args:
            domains: List of domain names (first is primary)
            email: Optional contact email for Let's Encrypt
            staging: Whether to use Let's Encrypt staging environment
            cert_dir: Directory to store certificates and keys
        """
        self.domains = domains
        self.primary_domain = domains[0] if domains else "localhost"
        self.email = email
        self.staging = staging
        self.cert_dir = cert_dir
        self.directory_url = LE_STAGING_URL if staging else LE_PRODUCTION_URL
        
        # Ensure cert dir exists
        os.makedirs(cert_dir, exist_ok=True)
        
        # Define key and cert paths
        self.account_key_path = os.path.join(cert_dir, "account.key")
        self.domain_key_path = os.path.join(cert_dir, f"{self.primary_domain}.key")
        self.cert_path = os.path.join(cert_dir, f"{self.primary_domain}.crt")
        
        # Session for HTTP requests
        self.session = requests.Session()
        self.session.verify = True
        
        # Server for HTTP challenges
        self.http_server = None
        self.http_server_thread = None
        self.token_responses = {}
        
        # Directory cache
        self.directory = None
        self.account_url = None

    def generate_private_key(self, key_path: str) -> None:
        """Generate a new private key."""
        if os.path.exists(key_path):
            logger.info(f"Using existing private key: {key_path}")
            return

        logger.info(f"Generating new private key: {key_path}")
        key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
        )
        
        with open(key_path, 'wb') as f:
            f.write(key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption()
            ))

    def load_private_key(self, key_path: str):
        """Load a private key from file."""
        with open(key_path, 'rb') as f:
            key_data = f.read()
        return load_pem_private_key(key_data, password=None)

    def jws_sign(self, key, url: str, payload: Dict[str, Any], nonce: str, post_as_get: bool = False) -> Dict[str, Any]:
        """
        Create a JWS signed request.
        
        Args:
            key: The private key to sign with
            url: The URL for the request
            payload: The payload (or empty dict for POST-as-GET)
            nonce: The nonce to use
            post_as_get: Whether this is a POST-as-GET request
            
        Returns:
            A JWS signed request
        """
        # For POST-as-GET requests, we need to use an empty string payload, not an empty JSON object
        if post_as_get:
            payload_str = ""
            payload_bytes = b""
        elif not isinstance(payload, bytes):
            payload_str = json.dumps(payload)
            payload_bytes = payload_str.encode('utf8')
        else:
            payload_bytes = payload
            payload_str = payload.decode('utf8')
            
        protected = {
            "alg": "RS256",
            "nonce": nonce,
            "url": url,
        }
            
        # Add JWK or KID depending on whether this is for account creation or not
        if url.endswith('new-acct'):
            # For new-acct, include the JWK (public key)
            jwk = {
                "kty": "RSA",
                "n": b64(key.public_key().public_numbers().n.to_bytes((key.public_key().public_numbers().n.bit_length() + 7) // 8, byteorder='big').lstrip(b'\x00')),
                "e": b64(key.public_key().public_numbers().e.to_bytes(3, 'big').lstrip(b'\x00')),
            }
            protected["jwk"] = jwk
        else:
            # For all other requests, include the KID (account URL)
            protected["kid"] = self.account_url
        
        protected_b64 = b64(json.dumps(protected).encode('utf8'))
        
        # For POST-as-GET requests, use an empty string for the payload
        if post_as_get:
            payload_b64 = ""
            signature_input = f"{protected_b64}.".encode('utf8')
        else:
            payload_b64 = b64(payload_bytes)
            signature_input = f"{protected_b64}.{payload_b64}".encode('utf8')
        
        # Create the signature
        signature_bytes = key.sign(
            signature_input,
            padding.PKCS1v15(),
            hashes.SHA256()
        )
        
        return {
            "protected": protected_b64,
            "payload": payload_b64,
            "signature": b64(signature_bytes),
        }

    def get_directory(self) -> Dict[str, str]:
        """Get the ACME directory."""
        logger.info(f"Getting ACME directory from {self.directory_url}")
        response = self.session.get(self.directory_url)
        return response.json()

    def get_nonce(self, directory: Dict[str, str]) -> str:
        """Get a fresh nonce from the ACME server."""
        logger.info("Getting fresh nonce")
        response = self.session.head(directory["newNonce"])
        return response.headers["Replay-Nonce"]

    def register_account(self, directory: Dict[str, str], key, nonce: str) -> Tuple[str, str]:
        """Register an ACME account."""
        logger.info("Registering ACME account")
        
        payload = {
            "termsOfServiceAgreed": True,
        }
        
        if self.email:
            payload["contact"] = [f"mailto:{self.email}"]
        
        response = self.session.post(
            directory["newAccount"],
            json=self.jws_sign(key, directory["newAccount"], payload, nonce),
            headers={"Content-Type": "application/jose+json"}
        )
        
        if response.status_code not in (201, 200):
            logger.error(f"Account registration failed: {response.status_code}")
            logger.error(response.text)
            raise ValueError(f"Account registration failed: {response.status_code}")
        
        # Get the new nonce and account URL
        new_nonce = response.headers["Replay-Nonce"]
        account_url = response.headers["Location"]
        
        logger.info(f"Account registered: {account_url}")
        return new_nonce, account_url

    def create_order(self, directory: Dict[str, str], key, nonce: str) -> Tuple[str, Dict[str, Any]]:
        """Create a new certificate order."""
        logger.info(f"Creating order for domains: {self.domains}")
        
        payload = {
            "identifiers": [
                {"type": "dns", "value": domain} for domain in self.domains
            ]
        }
        
        response = self.session.post(
            directory["newOrder"],
            json=self.jws_sign(key, directory["newOrder"], payload, nonce),
            headers={"Content-Type": "application/jose+json"}
        )
        
        if response.status_code != 201:
            logger.error(f"Order creation failed: {response.status_code}")
            logger.error(response.text)
            raise ValueError(f"Order creation failed: {response.status_code}")
        
        order = response.json()
        new_nonce = response.headers["Replay-Nonce"]
        order_url = response.headers["Location"]
        order["url"] = order_url
        
        # Store the order location for future reference
        self.order_location = order_url
        
        logger.info(f"Order created: {order_url}")
        logger.debug(f"Order details: {json.dumps(order, indent=2)}")
        return new_nonce, order

    def get_authorization(self, key, auth_url: str, nonce: str) -> Tuple[str, Dict[str, Any]]:
        """Get authorization details."""
        logger.info(f"Getting authorization: {auth_url}")
        
        # For ACME v2, the preferred way to get authorization is with a GET request
        try:
            # First try with a simple GET request (may work depending on the server)
            response = self.session.get(auth_url)
            
            if response.status_code == 200:
                logger.info("Successfully retrieved authorization with GET request")
                auth = response.json()
                
                # We need a nonce for future requests, so get one
                head_response = self.session.head(self.directory["newNonce"])
                new_nonce = head_response.headers["Replay-Nonce"]
                
                logger.debug(f"Authorization details: {json.dumps(auth, indent=2)}")
                return new_nonce, auth
            else:
                logger.info(f"GET request failed with status {response.status_code}, trying POST")
        except Exception as e:
            logger.info(f"GET request failed: {e}, trying POST")
        
        # Fall back to POST-as-GET request
        response = self.session.post(
            auth_url,
            json=self.jws_sign(key, auth_url, {}, nonce, post_as_get=True),
            headers={"Content-Type": "application/jose+json"}
        )
        
        if response.status_code != 200:
            logger.error(f"Authorization retrieval failed: {response.status_code}")
            logger.error(response.text)
            
            # If we get a specific error about invalid status, try with a GET request
            if "Invalid status value" in response.text:
                logger.info("Detected 'Invalid status value' error, trying direct GET request")
                try:
                    direct_response = requests.get(auth_url)
                    if direct_response.status_code == 200:
                        auth = direct_response.json()
                        # Get a fresh nonce
                        head_response = self.session.head(self.directory["newNonce"])
                        new_nonce = head_response.headers["Replay-Nonce"]
                        return new_nonce, auth
                except Exception as e:
                    logger.error(f"Direct GET request also failed: {e}")
            
            raise ValueError(f"Authorization retrieval failed: {response.status_code}")
        
        auth = response.json()
        new_nonce = response.headers["Replay-Nonce"]
        
        logger.debug(f"Authorization details: {json.dumps(auth, indent=2)}")
        return new_nonce, auth

    def start_http_server(self) -> None:
        """Start the HTTP server for ACME challenges."""
        if self.http_server_thread and self.http_server_thread.is_alive():
            logger.info("HTTP server already running")
            return
        
        def create_handler(*args, **kwargs):
            return ACMEChallenger(*args, token_responses=self.token_responses, **kwargs)
        
        try:
            # Check if port 80 is available
            import socket
            import subprocess
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            try:
                sock.bind(('', 80))
                sock.close()
            except socket.error:
                # Port is not available
                logger.error("❌ PORT 80 IS IN USE - CERTIFICATE ISSUANCE WILL FAIL")
                logger.error("Port 80 is already in use. Cannot start HTTP challenge server.")
                logger.error("The ACME protocol requires port 80 to be available for verification.")
                
                # Try to find what's using port 80
                try:
                    # On Linux systems, try to identify the process using port 80
                    if os.name == 'posix':
                        process = subprocess.run(['lsof', '-i', ':80'], capture_output=True, text=True, timeout=2)
                        if process.returncode == 0:
                            logger.error(f"Process using port 80:\n{process.stdout}")
                        else:
                            # Try netstat if lsof fails
                            netstat = subprocess.run(['netstat', '-tlnp'], capture_output=True, text=True, timeout=2)
                            if netstat.returncode == 0:
                                logger.error(f"Network connections (look for :80):\n{netstat.stdout}")
                except Exception:
                    pass
                
                logger.error("Please stop any services using port 80 (like Apache, Nginx, or other web servers).")
                logger.error("Options:")
                logger.error("1. Stop the web server: sudo systemctl stop apache2 (or nginx)")
                logger.error("2. Configure the web server to forward /.well-known/acme-challenge/ to port 80")
                logger.error("3. Use self-signed certificates instead (--self-signed)")
                
                raise ValueError("Port 80 is already in use - Let's Encrypt requires this port for domain validation")
            
            self.http_server = http.server.HTTPServer(('', 80), create_handler)
            self.http_server_thread = threading.Thread(target=self.http_server.serve_forever)
            self.http_server_thread.daemon = True
            self.http_server_thread.start()
            logger.info("HTTP challenge server started on port 80")
            
            # Verify the server can be accessed
            import requests
            for token in self.token_responses:
                test_url = f"http://localhost/.well-known/acme-challenge/{token}"
                try:
                    response = requests.get(test_url, timeout=2)
                    if response.status_code == 200:
                        logger.info(f"Successfully verified local challenge response for {token}")
                    else:
                        logger.warning(f"Local challenge verification failed: HTTP {response.status_code}")
                except Exception as e:
                    logger.warning(f"Could not verify local challenge response: {e}")
            
        except Exception as e:
            logger.error(f"Failed to start HTTP challenge server: {e}")
            raise

    def stop_http_server(self) -> None:
        """Stop the HTTP server."""
        if self.http_server:
            self.http_server.shutdown()
            self.http_server.server_close()
            self.http_server = None
            self.http_server_thread = None
            logger.info("HTTP challenge server stopped")

    def handle_challenges(self, key, auth_list: List[Dict[str, Any]], nonce: str) -> str:
        """Handle all authorization challenges."""
        new_nonce = nonce
        
        # Create responses for all HTTP-01 challenges
        for auth in auth_list:
            for challenge in auth["challenges"]:
                if challenge["type"] == "http-01":
                    token = challenge["token"]
                    
                    # Calculate the correct key authorization
                    # First, we need to get the JWK thumbprint, which is standardized in RFC 7638
                    jwk = {
                        "kty": "RSA", 
                        "n": b64(key.public_key().public_numbers().n.to_bytes((key.public_key().public_numbers().n.bit_length() + 7) // 8, byteorder="big").lstrip(b'\x00')),
                        "e": b64(key.public_key().public_numbers().e.to_bytes(3, byteorder="big").lstrip(b'\x00'))
                    }
                    
                    # JSON encode with sorted keys, no whitespace
                    jwk_json = json.dumps(jwk, sort_keys=True, separators=(',', ':'))
                    
                    # Calculate SHA-256 hash and base64url encode
                    jwk_thumbprint = b64(hashlib.sha256(jwk_json.encode('utf-8')).digest())
                    
                    # Construct key authorization
                    key_authorization = f"{token}.{jwk_thumbprint}"
                    
                    # Log the key authorization for debugging
                    logger.info(f"Token: {token}")
                    logger.info(f"JWK JSON: {jwk_json}")
                    logger.info(f"JWK Thumbprint: {jwk_thumbprint}")
                    logger.info(f"Key Authorization: {key_authorization}")
                    
                    # Store the response
                    self.token_responses[token] = key_authorization
                    logger.info(f"Prepared HTTP challenge response for token: {token}")
                    
                    # Start the HTTP server
                    self.start_http_server()
                    
                    # Tell the server we're ready for validation
                    challenge_url = challenge["url"]
                    response = self.session.post(
                        challenge_url,
                        json=self.jws_sign(key, challenge_url, {}, new_nonce, post_as_get=False),  # Regular POST
                        headers={"Content-Type": "application/jose+json"}
                    )
                    
                    if response.status_code != 200:
                        logger.error(f"Challenge registration failed: {response.status_code}")
                        logger.error(response.text)
                        raise ValueError(f"Challenge registration failed: {response.status_code}")
                    
                    new_nonce = response.headers["Replay-Nonce"]
                    logger.info(f"Registered for challenge verification: {token}")
        
        return new_nonce

    def check_domain_dns(self, domain: str) -> bool:
        """
        Perform comprehensive DNS checks for a domain.
        
        Args:
            domain: The domain name to check
            
        Returns:
            True if DNS appears to be correctly configured, False otherwise
        """
        try:
            import socket
            logger.info(f"Performing DNS checks for {domain}...")
            
            # Step 1: Get local IP addresses
            local_ips = []
            hostname = socket.gethostname()
            try:
                local_ips.append(socket.gethostbyname(hostname))
                logger.info(f"Local hostname {hostname} resolves to: {local_ips[-1]}")
            except Exception as e:
                logger.warning(f"Could not resolve local hostname: {e}")
            
            # Step 2: Try to get public IP using multiple services for redundancy
            public_ip = None
            ip_services = [
                'https://api.ipify.org',
                'https://ifconfig.me/ip',
                'https://icanhazip.com',
                'https://ipecho.net/plain'
            ]
            
            for service in ip_services:
                try:
                    with requests.get(service, timeout=3) as response:
                        if response.status_code == 200:
                            potential_ip = response.text.strip()
                            # Validate this looks like an IP address
                            try:
                                socket.inet_aton(potential_ip)
                                public_ip = potential_ip
                                local_ips.append(public_ip)
                                logger.info(f"Public IP detected: {public_ip} (via {service})")
                                break
                            except Exception:
                                logger.warning(f"Invalid IP format received from {service}: {potential_ip}")
                except Exception as e:
                    logger.debug(f"Could not get public IP from {service}: {e}")
            
            if not public_ip:
                logger.warning("Could not determine public IP address")
            
            # Step 3: Check DNS resolution for the domain
            try:
                logger.info(f"Looking up DNS records for {domain}...")
                
                # Try A record resolution
                try:
                    domain_ips = socket.gethostbyname_ex(domain)[2]
                    logger.info(f"Domain {domain} resolves to: {domain_ips}")
                    
                    # Check if any local IPs match the domain IPs
                    matches = set(local_ips).intersection(set(domain_ips))
                    if matches:
                        logger.info(f"✓ Domain correctly points to this server ({matches})")
                        return True
                    elif public_ip:
                        logger.warning(f"✗ Domain does not point to this server's public IP")
                        logger.warning(f"  Your public IP: {public_ip}")
                        logger.warning(f"  Domain IPs: {domain_ips}")
                        logger.warning(f"  The Let's Encrypt validation will likely fail!")
                        
                        # Check if the domain might be behind a proxy/CDN
                        if any(ip.startswith(('104.16.', '104.17.', '104.18.', '172.64.', '104.21.', '104.22.')) for ip in domain_ips):
                            logger.warning("⚠️ Your domain appears to be behind Cloudflare or another CDN/proxy")
                            logger.warning("For Let's Encrypt validation to work with a CDN, you need to either:")
                            logger.warning("1. Temporarily disable the CDN/proxy for this domain during certificate issuance")
                            logger.warning("2. Use DNS-01 validation instead of HTTP-01 (not supported by this client yet)")
                        
                        return False
                    else:
                        logger.warning(f"? Cannot determine if domain points to this server (public IP unknown)")
                        logger.warning(f"  Domain IPs: {domain_ips}")
                        logger.warning(f"  Local IPs: {local_ips}")
                        logger.warning(f"  The Let's Encrypt validation may fail unless this server is accessible via these IPs")
                        return False
                        
                except Exception as e:
                    logger.warning(f"Could not resolve A records for {domain}: {e}")
                    return False
                
            except Exception as e:
                logger.warning(f"Error checking DNS records: {e}")
                return False
                
        except Exception as e:
            logger.warning(f"Error during DNS check: {e}")
            return False

    def wait_for_authorizations(self, key, auth_url_list: List[str], nonce: str) -> str:
        """Wait for all authorizations to be valid."""
        new_nonce = nonce
        
        for auth_url in auth_url_list:
            max_attempts = 10
            attempt = 0
            while attempt < max_attempts:
                attempt += 1
                new_nonce, auth = self.get_authorization(key, auth_url, new_nonce)
                
                if auth["status"] == "valid":
                    logger.info(f"Authorization valid: {auth_url}")
                    break
                elif auth["status"] == "pending":
                    logger.info(f"Authorization pending (attempt {attempt}/{max_attempts}), waiting 5 seconds: {auth_url}")
                    time.sleep(5)
                elif auth["status"] == "invalid":
                    logger.error(f"Authorization invalid. Checking challenges for errors...")
                    
                    # Check for common issues and provide helpful messages
                    domain = auth.get('identifier', {}).get('value', 'unknown')
                    challenge_errors = []
                    
                    for challenge in auth.get("challenges", []):
                        if challenge.get("status") == "invalid":
                            error_detail = challenge.get('error', {}).get('detail', 'Unknown error')
                            challenge_errors.append(error_detail)
                            logger.error(f"Challenge failed: {error_detail}")
                            
                            # Extract validation records for debugging
                            records = challenge.get('validationRecord', [])
                            if records:
                                for record in records:
                                    if 'hostname' in record and 'addressesResolved' in record:
                                        logger.error(f"DNS lookup: {record['hostname']} → {record['addressesResolved']}")
                            
                            # Check for key authorization mismatch
                            if "key authorization" in error_detail and "did not match" in error_detail:
                                logger.error("ERROR: Key authorization mismatch - this could indicate:")
                                logger.error("1. Port 80 is being used by another service")
                                logger.error("2. A proxy or firewall is interfering with the HTTP challenge")
                                logger.error("3. DNS is not correctly configured for this domain")
                                
                                # Perform comprehensive DNS checks
                                self.check_domain_dns(domain)
                                
                                # Also check if we can access our own HTTP challenge server
                                for token in self.token_responses:
                                    url = f"http://localhost/.well-known/acme-challenge/{token}"
                                    try:
                                        response = requests.get(url, timeout=2)
                                        if response.status_code == 200:
                                            logger.info(f"Local HTTP challenge server is accessible: {url}")
                                            logger.info(f"Response: {response.text}")
                                        else:
                                            logger.error(f"Local HTTP challenge server returned status {response.status_code}: {url}")
                                    except Exception as e:
                                        logger.error(f"Could not access local HTTP challenge server: {e}")
                                
                            # Check for connection issues
                            elif "connection" in error_detail.lower() or "timeout" in error_detail.lower():
                                logger.error("ERROR: Connection issues - please check:")
                                logger.error("1. Your domain's DNS is correctly pointing to this server's IP address")
                                logger.error("2. Port 80 is open and accessible from the internet")
                                logger.error("3. No firewalls are blocking incoming connections on port 80")
                                
                                # Perform comprehensive DNS checks
                                self.check_domain_dns(domain)
                                
                                # Check port 80 accessibility
                                logger.error("Checking if port 80 is open locally...")
                                try:
                                    import socket
                                    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                                    s.settimeout(1)
                                    result = s.connect_ex(('127.0.0.1', 80))
                                    if result == 0:
                                        logger.error("✓ Port 80 is open locally")
                                    else:
                                        logger.error(f"✗ Port 80 is not open locally (error code: {result})")
                                    s.close()
                                except Exception as e:
                                    logger.error(f"Error checking port 80: {e}")
                    
                    # Provide final error message
                    if challenge_errors:
                        error_msg = f"Authorization for domain {domain} failed: {'; '.join(challenge_errors)}"
                    else:
                        error_msg = f"Authorization invalid: {auth_url}"
                    
                    raise ValueError(error_msg)
                else:
                    logger.error(f"Authorization failed: {auth['status']}")
                    logger.error(json.dumps(auth, indent=2))
                    raise ValueError(f"Authorization failed: {auth['status']}")
            
            if attempt >= max_attempts:
                logger.error(f"Authorization did not become valid after {max_attempts} attempts")
                raise ValueError(f"Authorization timeout: {auth_url}")
        
        return new_nonce

    def finalize_order(self, key, order: Dict[str, Any], nonce: str) -> str:
        """Finalize the certificate order."""
        logger.info("Finalizing certificate order")
        
        # Create a CSR
        csr_key = self.load_private_key(self.domain_key_path)
        csr = x509.CertificateSigningRequestBuilder().subject_name(x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, self.primary_domain),
        ])).add_extension(
            x509.SubjectAlternativeName([x509.DNSName(domain) for domain in self.domains]),
            critical=False,
        ).sign(csr_key, hashes.SHA256())
        
        csr_der = csr.public_bytes(serialization.Encoding.DER)
        
        # Send the CSR to finalize the order
        finalize_url = order["finalize"]
        response = self.session.post(
            finalize_url,
            json=self.jws_sign(key, finalize_url, {"csr": b64(csr_der)}, nonce),
            headers={"Content-Type": "application/jose+json"}
        )
        
        if response.status_code != 200:
            logger.error(f"Order finalization failed: {response.status_code}")
            logger.error(response.text)
            raise ValueError(f"Order finalization failed: {response.status_code}")
        
        new_nonce = response.headers["Replay-Nonce"]
        finalized_order = response.json()
        logger.info("Order finalized successfully")
        logger.debug(f"Finalized order: {json.dumps(finalized_order, indent=2)}")
        
        return new_nonce, finalized_order

    def wait_for_certificate(self, key, order: Dict[str, Any], nonce: str) -> Tuple[str, str]:
        """Wait for the certificate to be issued and download it."""
        new_nonce = nonce
        max_attempts = 20  # More attempts for certificate processing
        attempt = 0
        certificate_url = None
        
        # Get order URL - either from the order object or by constructing a proper order URL
        if "url" in order:
            order_url = order["url"]
        elif "finalize" in order:
            # IMPORTANT: We can't just truncate the finalize URL, as the order URL has a different structure
            # Instead, remember the location header from the original order creation
            if hasattr(self, 'order_location') and self.order_location:
                order_url = self.order_location
                logger.info(f"Order URL not found, using stored order location: {order_url}")
            else:
                # Try to construct a proper order URL based on the finalize URL pattern
                # For Let's Encrypt, the pattern is typically:
                # finalize: https://acme-v02.api.letsencrypt.org/acme/finalize/account_id/order_id
                # order: https://acme-v02.api.letsencrypt.org/acme/order/account_id/order_id
                try:
                    if "/finalize/" in order["finalize"]:
                        parts = order["finalize"].split("/finalize/")
                        if len(parts) == 2:
                            base_url = parts[0]
                            ids = parts[1]
                            order_url = f"{base_url}/order/{ids}"
                            logger.info(f"Order URL not found, constructed from finalize URL: {order_url}")
                        else:
                            raise ValueError("Cannot parse finalize URL correctly")
                    else:
                        raise ValueError("Finalize URL does not have expected format")
                except Exception as e:
                    logger.error(f"Error constructing order URL: {e}")
                    raise ValueError(f"Cannot determine order URL from finalize URL: {order['finalize']}")
        else:
            raise ValueError("Cannot determine order URL - missing both 'url' and 'finalize' fields")
        
        # Poll the order URL until the status is 'valid'
        while attempt < max_attempts:
            attempt += 1
            try:
                response = self.session.post(
                    order_url,
                    json=self.jws_sign(key, order_url, {}, new_nonce, post_as_get=True),
                    headers={"Content-Type": "application/jose+json"}
                )
                
                if response.status_code != 200:
                    logger.error(f"Order polling failed: {response.status_code}")
                    logger.error(response.text)
                    
                    # Check for badNonce error
                    try:
                        error_data = response.json()
                        if error_data.get("type") == "urn:ietf:params:acme:error:badNonce":
                            logger.warning("Received badNonce error, getting fresh nonce")
                            # Get a fresh nonce
                            head_response = self.session.head(self.directory["newNonce"])
                            new_nonce = head_response.headers["Replay-Nonce"]
                            logger.info(f"Got fresh nonce: {new_nonce}")
                            continue  # Retry immediately with new nonce
                    except Exception:
                        pass  # Fall through to standard retry logic
                    
                    # Let's Encrypt server might be having issues, retry with exponential backoff
                    if attempt < max_attempts:
                        sleep_time = min(5 * attempt, 30)  # Gradually increase wait time
                        logger.info(f"Retrying in {sleep_time} seconds (attempt {attempt}/{max_attempts})")
                        time.sleep(sleep_time)
                        continue
                    else:
                        raise ValueError(f"Order polling failed after {max_attempts} attempts: {response.status_code}")
                
                new_nonce = response.headers["Replay-Nonce"]
                order = response.json()
                
                # Print full order details to aid in debugging
                logger.debug(f"Order details (attempt {attempt}): {json.dumps(order, indent=2)}")
                
                if order["status"] == "valid":
                    if "certificate" in order:
                        certificate_url = order["certificate"]
                        logger.info(f"Certificate ready: {certificate_url}")
                        break
                    else:
                        logger.warning(f"Order is valid but missing certificate URL in attempt {attempt}")
                        # Some ACME servers might need an extra polling cycle to add the certificate URL
                        time.sleep(2)
                        continue
                elif order["status"] == "processing":
                    logger.info(f"Certificate processing, waiting (attempt {attempt}/{max_attempts})")
                    time.sleep(5)
                else:
                    logger.error(f"Unexpected order status: {order['status']}")
                    logger.error(json.dumps(order, indent=2))
                    raise ValueError(f"Unexpected order status: {order['status']}")
            
            except Exception as e:
                logger.error(f"Error polling order (attempt {attempt}/{max_attempts}): {e}")
                if attempt < max_attempts:
                    sleep_time = min(5 * attempt, 30)
                    logger.info(f"Retrying in {sleep_time} seconds")
                    time.sleep(sleep_time)
                else:
                    raise
        
        if certificate_url is None:
            # Special case: some ACME servers don't include certificate URL in the order
            # Instead of constructing the certificate URL which is unreliable,
            # we'll simply continue polling the order until it has a certificate URL
            logger.warning("Certificate URL not found in order, continuing to poll order status")
            # Continue polling until we get a certificate URL or reach max attempts
            for retry in range(10):
                logger.info(f"Polling for certificate URL (attempt {retry+1}/10)")
                time.sleep(5 * (retry + 1))  # Gradually increasing wait time
                
                # Get a fresh nonce if needed
                try:
                    head_response = self.session.head(self.directory["newNonce"])
                    new_nonce = head_response.headers["Replay-Nonce"]
                except Exception:
                    logger.warning("Failed to get fresh nonce, continuing with existing one")
                
                # Try polling the order again
                try:
                    poll_resp = self.session.post(
                        order_url,
                        json=self.jws_sign(key, order_url, {}, new_nonce, post_as_get=True),
                        headers={"Content-Type": "application/jose+json"}
                    )
                    
                    if poll_resp.status_code != 200:
                        logger.warning(f"Order polling failed with status {poll_resp.status_code}")
                        continue
                        
                    new_nonce = poll_resp.headers["Replay-Nonce"]
                    updated_order = poll_resp.json()
                    
                    if "certificate" in updated_order:
                        certificate_url = updated_order["certificate"]
                        logger.info(f"Found certificate URL: {certificate_url}")
                        break
                except Exception as e:
                    logger.warning(f"Error polling order: {e}")
            
            # If we still don't have a certificate URL, try to use the 'Location' header from the finalize response
            if certificate_url is None and "finalize" in order:
                logger.warning("Still no certificate URL, waiting for certificate to be ready")
                time.sleep(10)  # Give the server some more time
                
                # Try a final alternative approach using the Order ID
                try:
                    # Extract order ID from finalize URL
                    if "/finalize/" in order["finalize"]:
                        # Order ID is usually after /finalize/ in the URL
                        parts = order["finalize"].split("/finalize/")
                        if len(parts) >= 2:
                            order_id = parts[1].split("/")[0]
                            # Try to get the order directly using the order ID
                            directory_url = self.directory_url.rstrip("/")
                            direct_order_url = f"{directory_url}/order/{order_id}"
                            logger.info(f"Attempting to get order directly: {direct_order_url}")
                            
                            # Get a fresh nonce
                            head_response = self.session.head(self.directory["newNonce"])
                            new_nonce = head_response.headers["Replay-Nonce"]
                            
                            # Get order
                            order_resp = self.session.post(
                                direct_order_url,
                                json=self.jws_sign(key, direct_order_url, {}, new_nonce, post_as_get=True),
                                headers={"Content-Type": "application/jose+json"}
                            )
                            
                            if order_resp.status_code == 200:
                                new_nonce = order_resp.headers["Replay-Nonce"]
                                direct_order = order_resp.json()
                                if "certificate" in direct_order:
                                    certificate_url = direct_order["certificate"]
                                    logger.info(f"Found certificate URL through direct order: {certificate_url}")
                except Exception as e:
                    logger.warning(f"Error getting direct order: {e}")
                
            # Last resort: use a constructed URL based on the finalize URL pattern
            if certificate_url is None and "finalize" in order:
                try:
                    # Extract account ID and order ID from finalize URL
                    # Format is typically: .../finalize/account_id/order_id
                    finalize_parts = order["finalize"].split('/')
                    if len(finalize_parts) >= 2:
                        # Try to construct certificate URL based on ACME server patterns
                        # For Let's Encrypt, it's often: .../cert/account_id/order_id
                        account_id = finalize_parts[-2]
                        order_id = finalize_parts[-1]
                        base_url = '/'.join(finalize_parts[:-3])  # Remove finalize, account_id, and order_id
                        possible_cert_url = f"{base_url}/cert/{account_id}/{order_id}"
                        logger.warning(f"Last resort: Using constructed certificate URL: {possible_cert_url}")
                        certificate_url = possible_cert_url
                except Exception as e:
                    logger.error(f"Failed to construct certificate URL: {e}")
            
            if certificate_url is None:
                raise ValueError("Certificate URL not found in order and could not be determined")
        
        # Download the certificate
        for dl_attempt in range(3):  # Multiple download attempts
            try:
                logger.info(f"Downloading certificate from: {certificate_url} (attempt {dl_attempt+1}/3)")
                response = self.session.post(
                    certificate_url,
                    json=self.jws_sign(key, certificate_url, {}, new_nonce, post_as_get=True),
                    headers={"Content-Type": "application/jose+json"}
                )
                
                if response.status_code != 200:
                    logger.error(f"Certificate download failed: {response.status_code}")
                    logger.error(response.text)
                    
                    # Check for badNonce error
                    try:
                        error_data = response.json()
                        if error_data.get("type") == "urn:ietf:params:acme:error:badNonce":
                            logger.warning("Received badNonce error during certificate download, getting fresh nonce")
                            # Get a fresh nonce
                            head_response = self.session.head(self.directory["newNonce"])
                            new_nonce = head_response.headers["Replay-Nonce"]
                            logger.info(f"Got fresh nonce for certificate download: {new_nonce}")
                            continue  # Retry immediately with new nonce
                    except Exception:
                        pass  # Fall through to standard retry logic
                    
                    if dl_attempt < 2:  # Try again if not the last attempt
                        time.sleep(5)
                        continue
                    else:
                        raise ValueError(f"Certificate download failed: {response.status_code}")
                
                new_nonce = response.headers["Replay-Nonce"]
                certificate_pem = response.text
                
                # Validate the certificate has the correct format
                if not certificate_pem or not certificate_pem.strip().startswith("-----BEGIN CERTIFICATE-----"):
                    logger.warning(f"Downloaded certificate doesn't have expected format (attempt {dl_attempt+1}/3)")
                    if dl_attempt < 2:  # Try again if not the last attempt
                        time.sleep(5)
                        continue
                    else:
                        raise ValueError("Invalid certificate format received")
                
                logger.info("Certificate downloaded successfully")
                return new_nonce, certificate_pem
            
            except Exception as e:
                logger.error(f"Error downloading certificate (attempt {dl_attempt+1}/3): {e}")
                if dl_attempt < 2:  # Try again if not the last attempt
                    time.sleep(5)
                else:
                    raise
        
        # Should not reach here, but just in case
        raise ValueError("Failed to download certificate after multiple attempts")

    def get_certificate(self) -> bool:
        """
        Get a certificate using the ACME protocol.
        
        Returns:
            True if successful, False otherwise
        """
        try:
            logger.info(f"Getting certificate for domains: {self.domains}")
            
            # Generate keys if needed
            self.generate_private_key(self.account_key_path)
            self.generate_private_key(self.domain_key_path)
            
            # Load the account key
            account_key = self.load_private_key(self.account_key_path)
            
            # Get the ACME directory
            self.directory = self.get_directory()  # Store it as an instance variable
            
            # Get initial nonce
            nonce = self.get_nonce(self.directory)
            
            # Register account
            nonce, self.account_url = self.register_account(self.directory, account_key, nonce)
            
            # Create certificate order
            nonce, order = self.create_order(self.directory, account_key, nonce)
            
            # Get all authorizations
            auth_list = []
            for auth_url in order["authorizations"]:
                nonce, auth = self.get_authorization(account_key, auth_url, nonce)
                auth_list.append(auth)
            
            # Handle all challenges
            nonce = self.handle_challenges(account_key, auth_list, nonce)
            
            try:
                # Wait for authorizations to be valid
                nonce = self.wait_for_authorizations(account_key, order["authorizations"], nonce)
                
                # Finalize the order
                nonce, finalized_order = self.finalize_order(account_key, order, nonce)
                
                try:
                    # Wait for and download the certificate
                    nonce, certificate_pem = self.wait_for_certificate(account_key, finalized_order, nonce)
                    
                    # Verify the certificate has valid content
                    if not certificate_pem or not certificate_pem.strip().startswith("-----BEGIN CERTIFICATE-----"):
                        logger.error("Invalid certificate received - does not start with BEGIN CERTIFICATE")
                        logger.debug(f"Certificate content (first 100 chars): {certificate_pem[:100] if certificate_pem else 'None'}")
                        raise ValueError("Invalid certificate format received from ACME server")
                    
                    # Save the certificate
                    with open(self.cert_path, 'w') as f:
                        f.write(certificate_pem)
                    
                    # Verify that the certificate is valid
                    try:
                        import ssl
                        context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
                        context.load_cert_chain(self.cert_path, self.domain_key_path)
                        logger.info("Successfully loaded certificate")
                    except Exception as e:
                        logger.error(f"Certificate verification failed: {e}")
                        # If it failed verification, try to provide better error info
                        if "no start line" in str(e).lower():
                            with open(self.cert_path, 'r') as f:
                                cert_content = f.read(200)  # Just read the first part to check
                            logger.error(f"Certificate appears to be in wrong format. First 200 chars: {cert_content}")
                        os.remove(self.cert_path)  # Remove invalid certificate
                        raise
                except Exception as cert_e:
                    logger.error(f"Error obtaining or verifying certificate: {cert_e}")
                    # Clean up any bad certificate files to prevent "no start line" errors
                    if os.path.exists(self.cert_path):
                        os.remove(self.cert_path)
                    raise
                
                logger.info(f"Certificate saved to {self.cert_path}")
                return True
            
            finally:
                # Stop the HTTP server
                self.stop_http_server()
        
        except Exception as e:
            import traceback
            logger.error(f"Certificate issuance failed: {e}")
            logger.error(traceback.format_exc())
            return False
        
        return False


def issue_certificate(domains: List[str], email: Optional[str] = None, 
                      staging: bool = False, cert_dir: str = 'certs', 
                      skip_port_check: bool = False) -> Tuple[str, str]:
    """
    Issue a certificate for the given domains.
    
    Args:
        domains: List of domain names (first is primary)
        email: Optional contact email for Let's Encrypt
        staging: Whether to use Let's Encrypt staging environment
        cert_dir: Directory to store certificates and keys
        skip_port_check: Whether to skip checking if port 80 is available
    
    Returns:
        Tuple of (cert_path, key_path)
    """
    # If not skipping port check, verify port 80 is available
    if not skip_port_check:
        import socket
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.bind(('', 80))
            sock.close()
        except socket.error:
            logger.error("Port 80 is already in use - Let's Encrypt requires this port for domain validation")
            raise ValueError("Port 80 is already in use")
    
    client = ACMEClient(domains, email, staging, cert_dir)
    success = client.get_certificate()
    
    if success:
        return client.cert_path, client.domain_key_path
    else:
        raise ValueError("Certificate issuance failed")