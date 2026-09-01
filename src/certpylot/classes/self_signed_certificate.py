import datetime
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes

from .private_key import PrivateKey
from .enums import Encoding, KeyType

class SelfSignedCertificate:
    def __init__(self, key_type: KeyType = KeyType.RSA, key_size: int = 2048, private_key: PrivateKey = None):
        self.type = key_type
        self.key_size = key_size
        if private_key is not None:
            self.private_key = private_key.private_key
            self.type        = private_key.type

    def generate(
        self,
        country             : str | None = None,
        state               : str | None = None,
        locality            : str | None = None,
        organization        : str | None = None,
        organizational_unit : str | None = None,
        common_name         : str | None = None,
        sans                : list[str]  = ['localhost'],
        valid_days          : int        = 365,
    ):
        if not hasattr(self, "private_key"):
            self.private_key_class = PrivateKey(self.type)
            self.private_key = self.private_key_class._generate(self.key_size)

        x509_Names = []
        for name, value in [
            (NameOID.COUNTRY_NAME, country),
            (NameOID.STATE_OR_PROVINCE_NAME, state),
            (NameOID.LOCALITY_NAME, locality),
            (NameOID.ORGANIZATION_NAME, organization),
            (NameOID.ORGANIZATIONAL_UNIT_NAME, organizational_unit),
            (NameOID.COMMON_NAME, common_name)
        ]:
            if value is not None:
                x509_Names.append(x509.NameAttribute(name, value))

        subject = issuer = x509.Name(x509_Names)

        cert_builder = x509.CertificateBuilder(
            subject_name     = subject,
            issuer_name      = issuer,
            public_key       = self.private_key.public_key(),
            serial_number    = x509.random_serial_number(),
            not_valid_before = datetime.datetime.now(datetime.timezone.utc),
            not_valid_after  = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=valid_days),
        )

        cert_builder = cert_builder.add_extension(
            x509.SubjectAlternativeName([x509.DNSName(san) for san in sans]) if sans is not None else x509.SubjectAlternativeName([]),
            critical=False
        )

        sign_kwargs = dict(
            private_key = self.private_key
        )

        if self.type in [KeyType.RSA, KeyType.ECDSA]:
            sign_kwargs['algorithm'] = hashes.SHA256()
        elif self.type == KeyType.ED25519:
            sign_kwargs['algorithm'] = None

        self.certificate = cert_builder.sign(**sign_kwargs)
        return self.certificate

    def serialize(self, cert_type: Encoding = Encoding.PEM) -> bytes:
        self.serialized_certificate = self.certificate.public_bytes(cert_type.encoding)
        return self.serialized_certificate