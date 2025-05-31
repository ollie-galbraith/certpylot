import re
import ssl
import socket
import logging
from acme import crypto_util
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.hashes import HashAlgorithm
from datetime import datetime, timedelta, timezone
from zoneinfo import ZoneInfo
from urllib.parse import urlparse
from typing import overload, Optional

class Certificate():
    CERTIFICATE_TYPES = [
        'pem',
        'der'
    ]

    @overload
    def __init__(
        self,
        *,
        path: str,
        url: None = None,
        port: int = 443,
        certificate_type: str = 'pem',
        debug: bool = False,
        allow_unverified: bool = False
    ): ...

    @overload
    def __init__(
        self,
        *,
        path: None = None,
        url: str,
        port: int = 443,
        certificate_type: str = 'pem',
        debug: bool = False,
        allow_unverified: bool = False
    ): ...

    def __init__(
        self,
        *,
        path: Optional[str] = None,
        url: Optional[str] = None,
        port: int = 443,
        certificate_type: str = 'pem',
        debug: bool = False,
        allow_unverified: bool = False
    ):

        log_level = logging.DEBUG if debug else logging.WARNING
        logging.basicConfig(level=log_level, format='%(asctime)s | %(levelname)s | %(message)s')

        self.allow_unverified = allow_unverified
        if path is not None or url is not None:
            self.load(path=path, url=url, port=port, certificate_type=certificate_type)

    def _check_certificate_loaded(self):
        return hasattr(self, 'certificate')

    def _convert_timezone(self, datetime_obj, from_timezone, to_timezone):
        if from_timezone == to_timezone:
            return datetime_obj
        return datetime_obj.replace(tzinfo=from_timezone).astimezone(ZoneInfo(to_timezone))

    def _get_cert_from_url(self, url, port=443, certificate_type='pem', verify=True):
        def extract_cert(sock, certificate_type):
            der_cert = sock.getpeercert(binary_form=True)
            if certificate_type == 'pem':
                return ssl.DER_cert_to_PEM_cert(der_cert)
            elif certificate_type == 'der':
                return der_cert
            else:
                raise ValueError(f"Unsupported certificate type: {certificate_type}")
        # Fetch the certificate from the server

        def run_unverified(url, port, certificate_type):
            logging.warning(f"SSL certificate verification failed for {hostname}:{port}")
            logging.warning(f"Rerunning certificate retrieval with SSL certificate verification disabled")
            return self._get_cert_from_url(url, port, certificate_type=certificate_type, verify=False)

        if re.match(r'^\w*:\/\/.*$', url):
            hostname = urlparse(url).hostname
        else:
            hostname = url
        logging.debug(f"Connecting to {hostname}:{port} to fetch the certificate")

        # Establish a socket connection and get the certificate
        context = ssl.create_default_context() if verify else ssl._create_unverified_context()
        if port == 587:
            import smtplib
            with smtplib.SMTP(hostname, port) as server:
                try:
                    server.starttls(context=context)
                    return extract_cert(server.sock, certificate_type)
                except ssl.SSLCertVerificationError as e:
                    if self.allow_unverified:
                        return run_unverified(url, port, certificate_type)

                    raise e
        else:
            with socket.create_connection((hostname, port)) as sock:
                try:
                    with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                        return extract_cert(ssock, certificate_type)
                except ssl.SSLCertVerificationError as e:
                    if self.allow_unverified:
                        return run_unverified(url, port, certificate_type)

                    raise e

    def expiring_in(self, days=20):
        logging.debug(f"Checking if certificate is expiring within {days} days")
        return self.not_valid_after() <= (datetime.now(timezone.utc) + timedelta(days=days))

    def export(self, path):
        if self._check_certificate_loaded() is False:
            raise Exception('Need to load a certificate first')

        logging.debug(f'Exporting certificate object to path {path}')
        encoding_type = serialization.Encoding.PEM
        if self.certificate_type == 'der':
            encoding_type = serialization.Encoding.DER
        with open(path, "wb") as file:
            file.write(self.certificate.public_bytes(encoding=encoding_type))
            file.close()

    def extension(self, extension_oid):
        logging.debug(f"Fetching certificate extension with OID: {extension_oid}")
        return self.certificate.extensions.get_extension_for_oid(extension_oid)

    def extensions(self):
        logging.debug("Fetching certificate extensions")
        return self.certificate.extensions

    def extension_critical(self, extension_oid):
        logging.debug(f"Fetching certificate extension critical status with OID: {extension_oid}")
        return self.certificate.extensions.get_extension_for_oid(extension_oid).critical

    def extension_data(self, extension_oid):
        logging.debug(f"Fetching certificate extension data with OID: {extension_oid}")
        return self.certificate.extensions.get_extension_for_oid(extension_oid).value

    def fingerprint(self):
        logging.debug("Fetching certificate fingerprint")
        hash_algorithm = self.signature_hash_algorithm()
        if hash_algorithm is None:
            raise ValueError("Certificate does not have a signature hash algorithm")
        return self.certificate.fingerprint(hash_algorithm).hex()

    def get(self, path=None, url=None, port=443, certificate_type='pem'):
        if self._check_certificate_loaded() is False:
            if path is not None:
                self.load(path=path, certificate_type=certificate_type)
            elif url is not None:
                self.load(url=url, port=port, certificate_type=certificate_type)
            else:
                raise Exception('Need to load a certificate first')

        return dict(
            subject = self.subject().rfc4514_string(),
            issuer = self.issuer().rfc4514_string(),
            serial_number = self.serial_number(),
            fingerprint = self.fingerprint(),
            thumbprint = self.thumbprint(),
            not_valid_before = self.not_valid_before().strftime('%Y-%m-%d %H:%M:%S %Z'),
            not_valid_after = self.not_valid_after().strftime('%Y-%m-%d %H:%M:%S %Z')
        )

    def issuer(self):
        logging.debug("Fetching certificate issuer")
        return self.certificate.issuer

    def load(self, path=None, url=None, port=443, certificate_type='pem'):
        if certificate_type not in self.CERTIFICATE_TYPES:
            raise ValueError(f'certificate_type: {certificate_type} is not a supported type')

        if path:
            with open(path, 'rb') as f:
                cert_data = f.read()
            logging.debug(f"Certificate path: {path}")

        if url:
            raw_cert_data = self._get_cert_from_url(url, port, certificate_type=certificate_type)

            if certificate_type == 'pem' and isinstance(raw_cert_data, str):
                cert_data = str.encode(raw_cert_data)
            elif certificate_type == 'der' and isinstance(raw_cert_data, bytes):
                cert_data = raw_cert_data

        if certificate_type == 'pem':
            cert_obj = x509.load_pem_x509_certificate(cert_data, default_backend())
            self.certificate_type = 'pem'
        if certificate_type == 'der':
            cert_obj = x509.load_der_x509_certificate(cert_data, default_backend())
            self.certificate_type = 'der'

        self.certificate = cert_obj

    def not_valid_after(self, convert_to_timezone=timezone.utc):
        logging.debug("Fetching certificate not valid after time")
        aware_datetime = self.certificate.not_valid_after_utc.replace(tzinfo=timezone.utc)
        logging.debug(f"Certificate not valid after {aware_datetime} - UTC")
        if convert_to_timezone == timezone.utc:
            return aware_datetime
        logging.debug(f"Converting datetime from UTC to {convert_to_timezone}")
        return self._convert_timezone(aware_datetime, timezone.utc, convert_to_timezone)

    def not_valid_before(self, convert_to_timezone=timezone.utc):
        logging.debug("Fetching certificate not valid before time")
        aware_datetime = self.certificate.not_valid_before_utc.replace(tzinfo=timezone.utc)
        logging.debug(f"Certificate not valid before {aware_datetime} - UTC")
        if convert_to_timezone == timezone.utc:
            return aware_datetime
        logging.debug(f"Converting datetime from UTC to {convert_to_timezone}")
        return self._convert_timezone(aware_datetime, timezone.utc, convert_to_timezone)

    def public_key(self):
        logging.debug("Fetching certificate public key")
        return self.certificate.public_key()

    def serial_number(self):
        logging.debug("Fetching certificate serial number")
        return self.certificate.serial_number

    def signature_hash_algorithm(self) -> Optional[HashAlgorithm]:
        logging.debug("Fetching certificate signature hash algorithm")
        return self.certificate.signature_hash_algorithm

    def subject(self):
        logging.debug("Fetching certificate subject")
        return self.certificate.subject

    def thumbprint(self):
        logging.debug("Fetching certificate thumbprint")
        return self.certificate.fingerprint(hashes.SHA1()).hex()


class PrivateKey():
    def __init__(self, path=None, password=None):
        if path is not None:
            self.load(path, password)

    def export(self, path):
        if hasattr(self, 'serialized_key') is False:
            self.serialize()
        logging.debug(f"Saving private key to {path}")
        with open(path, "wb") as f:
            f.write(self.serialized_key)
            f.close()

    def generate(self, key_size=4096):
        logging.debug(f"Generating new private key with {key_size=}")
        key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=key_size,
            backend=default_backend()
        )

        self.private_key = key
        return key

    def load(self, path, password=None):
        with open(path, 'rb') as file:
            private_key = serialization.load_pem_private_key(
                file.read(),
                password=password.encode() if password is not None else None,  # Use a password if the key is encrypted
                backend=default_backend()
            )

        self.private_key = private_key

    def serialize(self):
        if hasattr(self, 'private_key') is False:
            raise Exception('Need to load private key first')

        logging.debug(f"Serializing private key")
        serialized_key = self.private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        )

        self.serialized_key = serialized_key
        return serialized_key


class Csr():
    def __init__(self):
        pass

    def export(self, path):
        logging.debug(f"Exporting CSR to path {path}")
        with open(path, "wb") as file:
            file.write(self.csr)
            file.close()

    def generate(self, domains, serialized_private_key):
        logging.debug(f"Generating new CSR")
        csr = crypto_util.make_csr(serialized_private_key, domains)
        self.csr = csr
        return csr
