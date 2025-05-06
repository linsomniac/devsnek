"""
Certificate management for devsnek using Let's Encrypt and ACME.
"""

import os
import logging
import datetime
from typing import List, Optional, Tuple
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

logger = logging.getLogger(__name__)

# Let's Encrypt directory URLs
LETSENCRYPT_DIRECTORY_URL = 'https://acme-v02.api.letsencrypt.org/directory'
LETSENCRYPT_STAGING_DIRECTORY_URL = 'https://acme-staging-v02.api.letsencrypt.org/directory'

# Certificate expiry threshold (days)
CERT_EXPIRY_THRESHOLD_DAYS = 30


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
    ):
        """
        Initialize the certificate manager.
        
        Args:
            domains: List of domain names (the first one is the primary domain)
            email: Optional email for Let's Encrypt registration
            certs_dir: Directory to store certificates and keys
            staging: Whether to use Let's Encrypt staging environment
        """
        self.domains = domains
        self.primary_domain = domains[0] if domains else "localhost"
        self.email = email
        self.certs_dir = certs_dir
        self.staging = staging
        
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
        
        # Generate new certificates
        logger.info(f"Requesting new certificates for {self.primary_domain} and {len(self.domains) - 1} SANs")
        await self._generate_certificates()
        return self.cert_path, self.key_path
    
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
        directory = messages.Directory.from_json(
            (await net.get(self.directory_url)).json()
        )
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
        
        # Create CSR
        name_list = [x509.DNSName(domain) for domain in self.domains]
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
            
            finalized = await asyncio.to_thread(acme_client.poll_and_finalize, order)
            
            with open(self.cert_path, 'wb') as f:
                f.write(finalized.fullchain_pem.encode('utf-8'))
    
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
        
        # Start challenge server
        servers = standalone.HTTP01DualNetworkedServers(('', 80), chall_mapping)
        await asyncio.to_thread(servers.serve_forever)
        
        try:
            yield http_challenges
        finally:
            await asyncio.to_thread(servers.shutdown_and_server_close)