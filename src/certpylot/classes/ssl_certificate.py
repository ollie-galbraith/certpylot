import re
import ssl
import socket
import logging
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.serialization import pkcs12
from datetime import datetime, timezone
from zoneinfo import ZoneInfo
from urllib.parse import urlparse
from typing import overload

from .private_key import PrivateKey
from .enums import CertificateType, KeyType


class SSLCertificate():
    @overload
    def __init__(path: str, url: None = None):
        ...

    @overload
    def __init__(url: str, path: None = None):
        ...

    def __init__(self, path: str = None, url: str = None, port: int = 443, certificate_type: CertificateType = CertificateType.PEM, debug: bool = False, allow_unverified: bool = False):
        log_level = logging.DEBUG if debug else logging.WARNING
        logging.basicConfig(level = log_level, format = '%(asctime)s | %(levelname)s | %(message)s')

        self.allow_unverified = allow_unverified
        if path is not None or url is not None:
            self.load(path = path, url = url, port = port, certificate_type = certificate_type)

    """ Internal methods """
    def _check_certificate_loaded(self) -> bool:
        """
        Check if the certificate is loaded.
        """
        return hasattr(self, 'certificate')

    def _convert_timezone(self, datetime_obj, from_timezone, to_timezone) -> datetime:
        """
        Convert a timezone-aware datetime object from one timezone to another.

        :param datetime_obj: The datetime object to convert
        :param from_timezone: The original timezone of the datetime object
        :param to_timezone: The target timezone to convert to
        :return: A timezone-aware datetime object in the target timezone
        """
        if from_timezone == to_timezone:
            return datetime_obj
        return datetime_obj.replace(tzinfo = from_timezone).astimezone(ZoneInfo(to_timezone))

    def _get_cert_from_url(self, url: str, port: int = 443, certificate_type: CertificateType = CertificateType.PEM, verify: bool = True) -> str:
        """
        Fetch a certificate from a URL.

        :param url: The URL to fetch the certificate from
        :param port: The port to connect to (default: 443)
        :param certificate_type: The type of certificate to fetch (default: PEM)
        :param verify: Whether to verify the SSL certificate (default: True)
        :return: The certificate in the specified format
        """

        def extract_cert(sock: socket, certificate_type: CertificateType):
            der_cert = sock.getpeercert(binary_form = True)
            if certificate_type == CertificateType.PEM:
                return ssl.DER_cert_to_PEM_cert(der_cert)
            elif certificate_type == CertificateType.DER:
                return der_cert
            else:
                raise ValueError(f"Unsupported certificate type: {certificate_type}")
        # Fetch the certificate from the server

        def run_unverified(url: str, port: int, certificate_type: CertificateType) -> str:
            logging.warning(f"SSL certificate verification failed for {hostname}:{port}")
            logging.warning("Rerunning certificate retrieval with SSL certificate verification disabled")
            return self._get_cert_from_url(url, port, certificate_type = certificate_type, verify = False)

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
                    server.starttls(context = context)
                    return extract_cert(server.sock, certificate_type)
                except ssl.SSLCertVerificationError as e:
                    if self.allow_unverified:
                        return run_unverified(url, port, certificate_type)

                    raise e
        else:
            with socket.create_connection((hostname, port)) as sock:
                try:
                    with context.wrap_socket(sock, server_hostname = hostname) as ssock:
                        return extract_cert(ssock, certificate_type)
                except ssl.SSLCertVerificationError as e:
                    if self.allow_unverified:
                        return run_unverified(url, port, certificate_type)

                    raise e
    """ Internal methods """

    """ Properties """
    @property
    def expiring_in(self) -> int:
        """
        Get the number of days until the certificate expires.

        :return: The number of days until the certificate expires
        """
        not_valid_after = self.certificate.not_valid_after_utc.replace(tzinfo = timezone.utc)
        now = datetime.now(timezone.utc)
        return (not_valid_after - now).days

    @property
    def extensions(self):
        """
        Get the extensions of the certificate.

        :return: The extensions of the certificate
        """
        return self.certificate.extensions

    @property
    def fingerprint(self) -> str:
        """
        Get the fingerprint of the certificate.

        :return: The fingerprint of the certificate
        """
        return self.certificate.fingerprint(self.certificate.signature_hash_algorithm).hex()

    @property
    def issuer(self) -> str:
        """
        Get the issuer of the certificate.

        :return: The issuer of the certificate
        """
        return self.certificate.issuer.rfc4514_string()

    @property
    def public_key(self) -> bytes:
        """
        Get the public key of the certificate.

        :return: The public key of the certificate
        """
        return self.certificate.public_key()

    @property
    def serial_number(self) -> str:
        """
        Get the serial number of the certificate.

        :return: The serial number of the certificate
        """
        return format(self.certificate.serial_number, 'x')

    @property
    def signature_hash_algorithm(self):
        """
        Get the name of the hash algorithm used in the certificate's signature.

        :return: The name of the hash algorithm used in the certificate's signature
        """
        return self.certificate.signature_hash_algorithm.name

    @property
    def subject(self):
        """
        Get the subject of the certificate.

        :return: The subject of the certificate
        """
        return self.certificate.subject.rfc4514_string()

    @property
    def thumbprint(self):
        """
        Get the thumbprint of the certificate (SHA-1 fingerprint).

        :return: The thumbprint of the certificate
        """
        return self.certificate.fingerprint(hashes.SHA1()).hex()

    """ Properties """

    def convert(self, path: str, output_type: CertificateType) -> None:
        """
        Convert the certificate to a different type.

        :param path: The path to save the converted certificate to.
        :param output_type: The type to convert the certificate to.
        """

        if self._check_certificate_loaded() is False:
            raise Exception('Need to load a certificate first')

        if self.certificate_type == output_type:
            logging.debug(f'Certificate is already type {output_type}')
            return

        logging.debug(f'Converting certificate from {self.certificate_type.label} to {output_type}')
        with open(path, "wb") as file:
            file.write(self.certificate.public_bytes(encoding = output_type.encoding))
            file.close()

    def export(self, path: str) -> None:
        """
        Save the certificate to a file in its current format.

        :param path: The path to save the certificate to.
        """

        if self._check_certificate_loaded() is False:
            raise Exception('Need to load a certificate first')

        logging.debug(f'Exporting certificate object to path {path}')
        with open(path, "wb") as file:
            file.write(self.certificate.public_bytes(encoding = self.certificate_type.encoding))
            file.close()

    def export_pfx(self, path: str, private_key: str, friendly_name: str, pfx_password: str = None, private_key_passphrase: str = None) -> None:
        """
        Export the certificate and private key to a PKCS#12 (PFX) file.

        :param path: The path to save the PFX file to.
        :param private_key: The path to the private key file.
        :param friendly_name: A friendly name for the certificate in the PFX file.
        :param pfx_password: An optional password to encrypt the PFX file.
        :param private_key_passphrase: An optional passphrase for the private key if it is encrypted.
        """

        if self._check_certificate_loaded() is False:
            raise Exception('Need to load a certificate first')

        private_key = PrivateKey(key_type = KeyType.RSA, path = private_key, passphrase = private_key_passphrase)

        serialize_args = dict(
            name = friendly_name.encode(),
            key = private_key.private_key,
            cert = self.certificate,
            cas = self.chain,
            encryption_algorithm = serialization.NoEncryption()
        )

        if pfx_password is not None:
            serialize_args['encryption_algorithm'] = serialization.BestAvailableEncryption(pfx_password.encode())
        pfx_data = pkcs12.serialize_key_and_certificates(**serialize_args)
        with open(path, "wb") as pfx_file:
            pfx_file.write(pfx_data)

    def get(self, path: str = None, url: str = None, port: int = 443, certificate_type: CertificateType = CertificateType.PEM) -> dict[str]:
        """
        Load a certificate (if not already loaded) and return its details as a dictionary.

        :param path: The path to load the certificate from (if not already loaded).
        :param url: The URL to load the certificate from (if not already loaded).
        :param port: The port to connect to when loading from a URL (default: 443).
        :param certificate_type: The type of certificate to load (default: PEM).
        :return: A dictionary containing the certificate details.
        """

        if self._check_certificate_loaded() is False:
            if path is not None:
                self.load(path = path, certificate_type = certificate_type)
            elif url is not None:
                self.load(url = url, port = port, certificate_type = certificate_type)
            else:
                raise Exception('Need to load a certificate first')

        return dict(
            subject = self.subject,
            issuer = self.issuer,
            serial_number = self.serial_number,
            fingerprint = self.fingerprint,
            thumbprint = self.thumbprint,
            not_valid_before = self.not_valid_before().strftime('%Y-%m-%d %H:%M:%S %Z'),
            not_valid_after = self.not_valid_after().strftime('%Y-%m-%d %H:%M:%S %Z')
        )

    def load(self, path: str = None, url: str = None, port: str = 443, certificate_type: CertificateType = CertificateType.PEM) -> x509.Certificate:
        """
        Load a certificate from a file or URL.

        :param path: The path to load the certificate from.
        :param url: The URL to load the certificate from.
        :param port: The port to connect to when loading from a URL (default: 443).
        :param certificate_type: The type of certificate to load (default: PEM).
        :return: The loaded certificate object.
        """

        self.certificate_type = certificate_type
        self.chain = []
        if path:
            with open(path, 'rb') as f:
                cert_data = f.read()
            logging.debug(f"Certificate path: {path}")

            if certificate_type == CertificateType.PEM:
                # Split into individual certs
                certs = cert_data.split(b'-----END CERTIFICATE-----')
                certs = [c + b'-----END CERTIFICATE-----\n' for c in certs if b'-----BEGIN CERTIFICATE-----' in c]
                # Load the first as the main certificate, the rest as the chain
                cert_obj = certificate_type.load(certs[0], default_backend())
                if len(certs) > 1:
                    self.chain = [certificate_type.load(c, default_backend()) for c in certs[1:]]
            elif certificate_type == CertificateType.DER:
                cert_obj = certificate_type.load(cert_data, default_backend())

        elif url:
            raw_cert_data = self._get_cert_from_url(url, port, certificate_type = certificate_type)

            cert_data = raw_cert_data
            if certificate_type == CertificateType.PEM:
                cert_data = str.encode(raw_cert_data)

            cert_obj = certificate_type.load(cert_data, default_backend())

        self.certificate = cert_obj

    def not_valid_after(self, convert_to_timezone = timezone.utc) -> datetime:
        """
        Get the date and time after which the certificate is not valid.

        :param convert_to_timezone: The timezone to convert the datetime to (default: UTC).
        :return: A timezone-aware datetime object representing the not valid after time.
        """

        logging.debug("Fetching certificate not valid after time")
        aware_datetime = self.certificate.not_valid_after_utc.replace(tzinfo = timezone.utc)
        logging.debug(f"Certificate not valid after {aware_datetime} - UTC")
        if convert_to_timezone == timezone.utc:
            return aware_datetime
        logging.debug(f"Converting datetime from UTC to {convert_to_timezone}")
        return self._convert_timezone(aware_datetime, timezone.utc, convert_to_timezone)

    def not_valid_before(self, convert_to_timezone = timezone.utc) -> datetime:
        """
        Get the date and time before which the certificate is not valid.

        :param convert_to_timezone: The timezone to convert the datetime to (default: UTC).
        :return: A timezone-aware datetime object representing the not valid before time.
        """

        logging.debug("Fetching certificate not valid before time")
        aware_datetime = self.certificate.not_valid_before_utc.replace(tzinfo = timezone.utc)
        logging.debug(f"Certificate not valid before {aware_datetime} - UTC")
        if convert_to_timezone == timezone.utc:
            return aware_datetime
        logging.debug(f"Converting datetime from UTC to {convert_to_timezone}")
        return self._convert_timezone(aware_datetime, timezone.utc, convert_to_timezone)
