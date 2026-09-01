from enum import Enum
from typing import Any
from cryptography import x509
from cryptography.hazmat.primitives import serialization


class KeyType(Enum):
    RSA = "rsa"
    ED25519 = "ed25519"
    ECDSA = "ecdsa"


class Encoding(Enum):
    PEM = (
        "pem",
        serialization.Encoding.PEM,
        x509.load_pem_x509_certificate
    )
    DER = (
        "der",
        serialization.Encoding.DER,
        x509.load_der_x509_certificate
    )
    OPENSSH = (
        "openssh",
        serialization.Encoding.OpenSSH,
        None
    )

    def __init__(self, label, encoding, loader):
        self.label = label
        self.encoding = encoding
        self._loader = loader

    def load(self, data: bytes, backend: Any):
        return self._loader(data, backend)

class PrivateKeyFormat(Enum):
    TRADITIONAL_OPENSSL = (
        "traditional_openssl",
        serialization.PrivateFormat.TraditionalOpenSSL
    )
    PKCS8 = (
        "pkcs8",
        serialization.PrivateFormat.PKCS8
    )
    OPENSSH = (
        "openssh",
        serialization.PrivateFormat.OpenSSH
    )

    def __init__(self, label, format):
        self.label = label
        self.format = format