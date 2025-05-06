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

    def jws_sign(self, key, url: str, payload: Dict[str, Any], nonce: str) -> Dict[str, Any]:
        """Create a JWS signed request."""
        if not isinstance(payload, bytes):
            payload = json.dumps(payload).encode('utf8')
            
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
                "n": b64(key.public_key().public_numbers().n.to_bytes(256, 'big').lstrip(b'\x00')),
                "e": b64(key.public_key().public_numbers().e.to_bytes(3, 'big').lstrip(b'\x00')),
            }
            protected["jwk"] = jwk
        else:
            # For all other requests, include the KID (account URL)
            protected["kid"] = self.account_url
        
        protected_b64 = b64(json.dumps(protected).encode('utf8'))
        payload_b64 = b64(payload)
        
        # Create the signature
        signature_bytes = key.sign(
            f"{protected_b64}.{payload_b64}".encode('utf8'),
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
        
        # Fall back to POST request with empty payload
        response = self.session.post(
            auth_url,
            json=self.jws_sign(key, auth_url, {}, nonce),
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
                    key_authorization = f"{token}.{b64(hashlib.sha256(key.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.PKCS1)).digest())}"
                    
                    # Store the response
                    self.token_responses[token] = key_authorization
                    logger.info(f"Prepared HTTP challenge response for token: {token}")
                    
                    # Start the HTTP server
                    self.start_http_server()
                    
                    # Tell the server we're ready for validation
                    challenge_url = challenge["url"]
                    response = self.session.post(
                        challenge_url,
                        json=self.jws_sign(key, challenge_url, {}, new_nonce),
                        headers={"Content-Type": "application/jose+json"}
                    )
                    
                    if response.status_code != 200:
                        logger.error(f"Challenge registration failed: {response.status_code}")
                        logger.error(response.text)
                        raise ValueError(f"Challenge registration failed: {response.status_code}")
                    
                    new_nonce = response.headers["Replay-Nonce"]
                    logger.info(f"Registered for challenge verification: {token}")
        
        return new_nonce

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
                    for challenge in auth.get("challenges", []):
                        if challenge.get("status") == "invalid":
                            logger.error(f"Challenge failed: {challenge.get('error', {}).get('detail', 'Unknown error')}")
                    raise ValueError(f"Authorization invalid: {auth_url}")
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
        order_url = order["url"]
        
        # Poll the order URL until the status is 'valid'
        while True:
            response = self.session.post(
                order_url,
                json=self.jws_sign(key, order_url, {}, new_nonce),
                headers={"Content-Type": "application/jose+json"}
            )
            
            if response.status_code != 200:
                logger.error(f"Order polling failed: {response.status_code}")
                logger.error(response.text)
                raise ValueError(f"Order polling failed: {response.status_code}")
            
            new_nonce = response.headers["Replay-Nonce"]
            order = response.json()
            
            if order["status"] == "valid" and "certificate" in order:
                certificate_url = order["certificate"]
                logger.info(f"Certificate ready: {certificate_url}")
                break
            elif order["status"] == "processing":
                logger.info("Certificate processing, waiting 5 seconds")
                time.sleep(5)
            else:
                logger.error(f"Unexpected order status: {order['status']}")
                logger.error(json.dumps(order, indent=2))
                raise ValueError(f"Unexpected order status: {order['status']}")
        
        # Download the certificate
        response = self.session.post(
            certificate_url,
            json=self.jws_sign(key, certificate_url, {}, new_nonce),
            headers={"Content-Type": "application/jose+json"}
        )
        
        if response.status_code != 200:
            logger.error(f"Certificate download failed: {response.status_code}")
            logger.error(response.text)
            raise ValueError(f"Certificate download failed: {response.status_code}")
        
        new_nonce = response.headers["Replay-Nonce"]
        certificate_pem = response.text
        
        logger.info("Certificate downloaded successfully")
        return new_nonce, certificate_pem

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
                
                # Wait for and download the certificate
                nonce, certificate_pem = self.wait_for_certificate(account_key, finalized_order, nonce)
                
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