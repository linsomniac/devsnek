"""
Certificate management for devsnek using Let's Encrypt and ACME.
"""

import os
import sys
import logging
import datetime
import concurrent.futures
import ipaddress
import socket
from typing import List, Optional, Tuple, Any, Callable, Dict
import asyncio
from contextlib import asynccontextmanager

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
import josepy as jose
from acme import client, messages, challenges
from acme import errors as acme_errors
from acme import standalone

from .direct_acme import issue_certificate


# For Python versions that don't have asyncio.to_thread
if not hasattr(asyncio, "to_thread"):
    _executor = concurrent.futures.ThreadPoolExecutor()
    
    async def _to_thread(func, *args, **kwargs):
        """Run a function in a separate thread."""
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(
            _executor, lambda: func(*args, **kwargs)
        )
    
    # Add to the asyncio module
    asyncio.to_thread = _to_thread

logger = logging.getLogger(__name__)

# Let's Encrypt directory URLs
LETSENCRYPT_DIRECTORY_URL = 'https://acme-v02.api.letsencrypt.org/directory'
LETSENCRYPT_STAGING_DIRECTORY_URL = 'https://acme-staging-v02.api.letsencrypt.org/directory'

# Certificate expiry threshold (days)
CERT_EXPIRY_THRESHOLD_DAYS = 30


def is_ip_address(domain: str) -> bool:
    """Check if a string is an IP address."""
    try:
        ipaddress.ip_address(domain)
        return True
    except ValueError:
        return False


def split_domains_and_ips(domains: List[str]) -> Tuple[List[str], List[str]]:
    """
    Split a list of domains into domain names and IP addresses.
    
    Args:
        domains: List of domain names or IP addresses
        
    Returns:
        Tuple of (domain_names, ip_addresses)
    """
    domain_names = []
    ip_addresses = []
    
    for domain in domains:
        if is_ip_address(domain):
            ip_addresses.append(domain)
        else:
            domain_names.append(domain)
    
    return domain_names, ip_addresses


class CertificateManager:
    """
    Manager for Let's Encrypt certificates.
    
    Handles:
    - Certificate generation
    - Certificate renewal
    - HTTP-01 challenge response
    """
    
    def __init__(
        self,
        domains: List[str],
        email: Optional[str] = None,
        certs_dir: str = "certs",
        staging: bool = False,
        self_signed: bool = False,
        skip_port_check: bool = False,
    ):
        """
        Initialize the certificate manager.
        
        Args:
            domains: List of domain names and/or IP addresses (the first one is the primary)
            email: Optional email for Let's Encrypt registration
            certs_dir: Directory to store certificates and keys
            staging: Whether to use Let's Encrypt staging environment
            self_signed: Whether to use self-signed certificates
        """
        # Split domains into domain names and IP addresses
        self.domain_names, self.ip_addresses = split_domains_and_ips(domains)
        
        # Combine all identifiers
        self.domains = domains
        
        # Set primary domain (prefer a domain name over an IP)
        if self.domain_names:
            self.primary_domain = self.domain_names[0]
        elif self.ip_addresses:
            self.primary_domain = self.ip_addresses[0]
        else:
            self.primary_domain = "localhost"
            
        self.email = email
        self.certs_dir = certs_dir
        self.staging = staging
        self.self_signed = self_signed
        self.skip_port_check = skip_port_check
        
        # Certificate paths
        self.cert_path = os.path.join(self.certs_dir, f"{self.primary_domain}.crt")
        self.key_path = os.path.join(self.certs_dir, f"{self.primary_domain}.key")
        self.account_key_path = os.path.join(self.certs_dir, "account.key")
        
        # ACME directory URL
        self.directory_url = (
            LETSENCRYPT_STAGING_DIRECTORY_URL if staging else LETSENCRYPT_DIRECTORY_URL
        )
    
    async def ensure_certificates(self) -> Tuple[str, str]:
        """
        Ensure that valid certificates exist, requesting new ones if needed.
        
        Returns:
            Tuple containing paths to certificate and key files
        """
        # Check if certificate directory exists
        os.makedirs(self.certs_dir, exist_ok=True)
        
        # Check if existing certificates are valid
        if await self._check_existing_certificates():
            logger.info(f"Using existing certificates for {self.primary_domain}")
            return self.cert_path, self.key_path
        
        # Check if self-signed is requested explicitly
        if self.self_signed:
            logger.info("Using self-signed certificate as requested")
            await self._generate_self_signed_cert()
            return self.cert_path, self.key_path
            
        # Check if port 80 is available (required for Let's Encrypt)
        if not self.skip_port_check:
            import socket
            port_80_available = False
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.bind(('', 80))
                sock.close()
                port_80_available = True
            except socket.error:
                logger.error("Port 80 is not available - Let's Encrypt requires this port for domain validation")
                logger.error("Automatically falling back to self-signed certificate")
                logger.error("To silence this warning, use --self-signed or free up port 80")
                logger.error("If you have port forwarding or a proxy server, use --skip-port-check")
                await self._generate_self_signed_cert()
                return self.cert_path, self.key_path
        else:
            logger.info("Skipping port 80 availability check as requested (--skip-port-check)")
            logger.warning("Let's Encrypt will still need port 80 accessible from the Internet")
            logger.warning("Make sure you have port forwarding or a proxy server configured properly")
            
        try:
            # Generate new certificates from Let's Encrypt
            logger.info(f"Requesting new certificates for {self.primary_domain} and {len(self.domains) - 1} SANs")
            
            # First try the standard ACME client
            try:
                logger.info("Attempting to get certificate using standard ACME client")
                await self._generate_certificates()
            except Exception as e:
                logger.error(f"Standard ACME client failed: {e}")
                
                # Try the direct ACME implementation as a fallback
                if self.domain_names:
                    logger.info("Attempting to get certificate using direct ACME implementation")
                    try:
                        # This runs synchronously, so we need to run it in a thread
                        cert_path, key_path = await asyncio.to_thread(
                            issue_certificate,
                            self.domain_names,
                            self.email,
                            self.staging,
                            self.certs_dir,
                            self.skip_port_check
                        )
                        logger.info(f"Direct ACME implementation succeeded: {cert_path}")
                    except Exception as direct_e:
                        logger.error(f"Direct ACME implementation failed: {direct_e}")
                        raise e  # Re-raise the original exception
                else:
                    raise
            
            # Verify certificates were created successfully
            if not (os.path.exists(self.cert_path) and os.path.exists(self.key_path)):
                raise Exception("Certificates were not created properly")
                
            # Verify certificates can be loaded
            try:
                import ssl
                context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
                context.load_cert_chain(self.cert_path, self.key_path)
                logger.info("Successfully loaded certificates")
            except Exception as e:
                logger.error(f"Error loading certificates: {e}")
                raise
                
        except Exception as e:
            # Check for port 80 availability explicitly
            import socket
            port_80_available = False
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.bind(('', 80))
                sock.close()
                port_80_available = True
            except socket.error:
                pass
            
            if not port_80_available:
                logger.error("Could not bind to port 80, which is required for Let's Encrypt HTTP challenge.")
                logger.error("The ACME protocol requires port 80 to be available for verification.")
                logger.error("Please stop any services using port 80 (like a web server or another instance of devsnek).")
            
            logger.error(f"Error getting Let's Encrypt certificates: {e}")
            logger.info("Falling back to self-signed certificate")
            await self._generate_self_signed_cert()
            
        return self.cert_path, self.key_path
        
    async def _generate_self_signed_cert(self):
        """Generate a self-signed certificate for development use."""
        logger.info(f"Generating self-signed certificate for {self.primary_domain}")
        
        # Generate key
        key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
        )
        
        # Write key
        with open(self.key_path, 'wb') as f:
            f.write(key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption()
            ))
        
        # Generate names list including both DNS names and IP addresses
        names = []
        
        # Add DNS names
        for name in self.domain_names:
            names.append(x509.DNSName(name))
        
        # Add IP addresses
        for ip in self.ip_addresses:
            try:
                ip_obj = ipaddress.ip_address(ip)
                names.append(x509.IPAddress(ip_obj))
            except ValueError:
                logger.warning(f"Invalid IP address in certificate: {ip}")
        
        # If no valid names were provided, add localhost
        if not names:
            names.append(x509.DNSName("localhost"))
        
        # Create certificate
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "California"),
            x509.NameAttribute(NameOID.LOCALITY_NAME, "San Francisco"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Development"),
            x509.NameAttribute(NameOID.COMMON_NAME, self.primary_domain),
        ])
        
        cert = x509.CertificateBuilder().subject_name(
            subject
        ).issuer_name(
            issuer
        ).public_key(
            key.public_key()
        ).serial_number(
            x509.random_serial_number()
        ).not_valid_before(
            datetime.datetime.utcnow()
        ).not_valid_after(
            # Valid for 30 days
            datetime.datetime.utcnow() + datetime.timedelta(days=30)
        ).add_extension(
            x509.SubjectAlternativeName(names),
            critical=False,
        ).add_extension(
            x509.BasicConstraints(ca=False, path_length=None), 
            critical=True,
        ).sign(key, hashes.SHA256())
        
        # Write certificate
        with open(self.cert_path, 'wb') as f:
            f.write(cert.public_bytes(serialization.Encoding.PEM))
    
    async def _check_existing_certificates(self) -> bool:
        """
        Check if existing certificates are valid and not near expiry.
        
        Returns:
            True if valid certificates exist, False otherwise
        """
        if not (os.path.exists(self.cert_path) and os.path.exists(self.key_path)):
            return False
        
        try:
            with open(self.cert_path, 'rb') as f:
                cert_data = f.read()
            cert = x509.load_pem_x509_certificate(cert_data)
            
            # Check certificate expiry
            now = datetime.datetime.now()
            if cert.not_valid_after < now:
                logger.info("Certificate has expired")
                return False
            
            # Check if certificate will expire soon
            remaining_days = (cert.not_valid_after - now).days
            if remaining_days <= CERT_EXPIRY_THRESHOLD_DAYS:
                logger.info(f"Certificate will expire in {remaining_days} days, renewing")
                return False
            
            # Check domains
            cert_domains = self._get_domains_from_cert(cert)
            if not all(domain in cert_domains for domain in self.domains):
                logger.info("Certificate doesn't cover all required domains")
                return False
            
            return True
        except Exception as e:
            logger.error(f"Error checking existing certificates: {e}")
            return False
    
    def _get_domains_from_cert(self, cert) -> List[str]:
        """Extract domain names from a certificate."""
        domains = []
        
        # Get common name
        for attr in cert.subject:
            if attr.oid == NameOID.COMMON_NAME:
                domains.append(attr.value)
        
        # Get SANs
        try:
            san_ext = cert.extensions.get_extension_for_oid(
                x509.ExtensionOID.SUBJECT_ALTERNATIVE_NAME
            )
            domains.extend(san.value for san in san_ext.value)
        except x509.ExtensionNotFound:
            pass
        
        return domains
    
    async def _generate_certificates(self):
        """Generate new certificates using ACME protocol."""
        # Generate/load account key
        acct_key = await self._get_account_key()
        
        # Initialize ACME client
        net = client.ClientNetwork(jose.JWKRSA(key=acct_key), user_agent="devsnek")
        
        # Get directory data synchronously using to_thread
        directory_response = await asyncio.to_thread(
            net.get, self.directory_url
        )
        directory_data = directory_response.json()
        directory = messages.Directory.from_json(directory_data)
        acme_client = client.ClientV2(directory, net)
        
        # Register account if needed
        registration = await asyncio.to_thread(
            self._register_account, acme_client, self.email
        )
        
        # Generate domain key
        priv_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        with open(self.key_path, 'wb') as f:
            f.write(priv_key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.TraditionalOpenSSL,
                serialization.NoEncryption()
            ))
        
        # Create CSR (Let's Encrypt only supports DNS names, not IP addresses)
        if not self.domain_names:
            # If no domain names, force self-signed mode
            logger.info("No valid domain names provided for Let's Encrypt, using self-signed certificate")
            raise ValueError("Let's Encrypt requires at least one valid domain name")
            
        name_list = [x509.DNSName(domain) for domain in self.domain_names]
        csr = x509.CertificateSigningRequestBuilder().subject_name(x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, self.primary_domain)
        ])).add_extension(
            x509.SubjectAlternativeName(name_list), critical=False
        ).sign(priv_key, hashes.SHA256())
        
        # Request certificate
        order = await asyncio.to_thread(
            acme_client.new_order, csr.public_bytes(serialization.Encoding.DER)
        )
        
        # Handle HTTP-01 challenges
        async with self._handle_http01_challenges(acme_client, order) as authorizations:
            for auth, chal in authorizations:
                await asyncio.to_thread(
                    acme_client.answer_challenge,
                    chal,
                    chal.response(acme_client.net.key)
                )
            
            # Finalize the order to get the certificate
            try:
                logger.info("Finalizing ACME order to obtain certificate")
                # Dump order object for debugging
                logger.info(f"Order details: {order}")
                logger.info(f"Order authorizations: {[auth.uri for auth in order.authorizations]}")
                
                try:
                    finalized = await asyncio.to_thread(acme_client.poll_and_finalize, order)
                    logger.info("Order finalized successfully")
                except Exception as e:
                    logger.error(f"Failed to finalize order: {e}")
                    # Try to get the certificate directly
                    if hasattr(order, 'certificate_uri') and order.certificate_uri:
                        logger.info(f"Attempting to get certificate directly from {order.certificate_uri}")
                        cert_response = await asyncio.to_thread(net.get, order.certificate_uri)
                        if cert_response.status_code == 200:
                            finalized = object()  # Create a dummy object
                            finalized.fullchain_pem = cert_response.text
                        else:
                            raise ValueError(f"Failed to get certificate: HTTP {cert_response.status_code}")
                    else:
                        raise
                
                # Debug logging of finalized order
                logger.info(f"Certificate finalized, certificate type: {type(finalized.fullchain_pem)}")
                
                # Print first 100 chars if string to help debug
                if isinstance(finalized.fullchain_pem, str) and finalized.fullchain_pem:
                    logger.info(f"Certificate preview: {finalized.fullchain_pem[:100]}...")
                elif isinstance(finalized.fullchain_pem, bytes) and finalized.fullchain_pem:
                    logger.info(f"Certificate preview (bytes): {finalized.fullchain_pem[:100]}...")
                
                # Check if we have a valid certificate
                if not finalized.fullchain_pem:
                    raise ValueError("No certificate data received from Let's Encrypt")
                
                # Ensure the certificate is properly encoded and in PEM format
                if not isinstance(finalized.fullchain_pem, (str, bytes)):
                    raise ValueError(f"Certificate data is not a string or bytes: {type(finalized.fullchain_pem)}")
                
                # Convert to string if it's bytes
                cert_pem = finalized.fullchain_pem
                if isinstance(cert_pem, bytes):
                    cert_pem = cert_pem.decode('utf-8')
                
                # Make sure it's a valid PEM certificate
                if not cert_pem.startswith('-----BEGIN CERTIFICATE-----'):
                    # Try to extract certificate from order certificate resource
                    if hasattr(finalized, 'certificate') and finalized.certificate:
                        logger.info("Using certificate resource instead of fullchain_pem")
                        # Fetch the certificate resource
                        cert_response = await asyncio.to_thread(
                            net.get, finalized.certificate
                        )
                        cert_pem = cert_response.text
                    else:
                        raise ValueError("Certificate data is not in PEM format and no certificate resource available")
                
                # Now we should have a valid PEM certificate as a string
                if not cert_pem.startswith('-----BEGIN CERTIFICATE-----'):
                    raise ValueError("Could not obtain valid PEM certificate")
                
                # Write the certificate to file
                logger.info(f"Writing certificate to {self.cert_path}")
                with open(self.cert_path, 'w') as f:
                    f.write(cert_pem)
                
                # Verify the certificate can be loaded
                try:
                    import ssl
                    context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
                    context.load_cert_chain(self.cert_path, self.key_path)
                    logger.info("Successfully loaded certificate")
                except Exception as e:
                    logger.error(f"Failed to load certificate: {e}")
                    raise ValueError(f"Certificate verification failed: {e}")
                
            except Exception as e:
                import traceback
                logger.error(f"Error obtaining or saving certificate: {e}")
                logger.error(f"Detailed traceback: {traceback.format_exc()}")
                raise ValueError(f"Failed to obtain certificate: {e}")
    
    async def _get_account_key(self):
        """Get or generate ACME account key."""
        if os.path.exists(self.account_key_path):
            with open(self.account_key_path, 'rb') as f:
                return serialization.load_pem_private_key(f.read(), password=None)
        else:
            # Generate new key
            acct_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
            with open(self.account_key_path, 'wb') as f:
                f.write(acct_key.private_bytes(
                    serialization.Encoding.PEM,
                    serialization.PrivateFormat.TraditionalOpenSSL,
                    serialization.NoEncryption()
                ))
            return acct_key
    
    def _register_account(self, acme_client, email=None):
        """Register ACME account."""
        try:
            regr = acme_client.net.account
            if regr:
                return regr
        except acme_errors.Error:
            pass
        
        new_reg = messages.NewRegistration.from_data(
            email=email, 
            terms_of_service_agreed=True
        )
        return acme_client.new_account(new_reg)
    
    @asynccontextmanager
    async def _handle_http01_challenges(self, acme_client, order):
        """Context manager to handle HTTP-01 challenges."""
        http_challenges = []
        chall_mapping = {}
        
        for authz in order.authorizations:
            http_chall = next(
                (c for c in authz.body.challenges 
                 if isinstance(c.chall, challenges.HTTP01)), 
                None
            )
            
            if http_chall:
                chall_response, validation = http_chall.response_and_validation(acme_client.net.key)
                chall_mapping[validation.path] = validation.json_dumps()
                http_challenges.append((authz, http_chall))
        
        # Start challenge server in a separate thread
        logger.info(f"Starting HTTP challenge server on port 80")
        try:
            servers = standalone.HTTP01DualNetworkedServers(('', 80), chall_mapping)
            server_thread = concurrent.futures.ThreadPoolExecutor(max_workers=1)
            server_future = server_thread.submit(servers.serve_forever)
            
            # Wait a moment for the server to start
            await asyncio.sleep(0.5)
            yield http_challenges
            
        except OSError as e:
            if e.errno == 98:  # Address already in use
                logger.error(f"Failed to start HTTP challenge server: Port 80 is already in use. "
                           f"Port 80 is required for Let's Encrypt HTTP challenge.")
            else:
                logger.error(f"Failed to start HTTP challenge server: {e}")
            raise
        except Exception as e:
            logger.error(f"Error in HTTP challenge server: {e}")
            raise
        finally:
            # Stop the server
            try:
                servers.shutdown_and_server_close()
                server_thread.shutdown(wait=True)
            except Exception as e:
                logger.warning(f"Error stopping HTTP challenge server: {e}")