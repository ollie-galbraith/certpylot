from enum import Enum
from typing import Any
from cryptography import x509
from cryptography.hazmat.primitives import serialization


class KeyType(Enum):
    RSA = "rsa"
    ED25519 = "ed25519"
    ECDSA = "ecdsa"


class CertificateType(Enum):
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

    def __init__(self, label, encoding, loader):
        self.label = label
        self.encoding = encoding
        self._loader = loader

    def load(self, data: bytes, backend: Any):
        return self._loader(data, backend)
