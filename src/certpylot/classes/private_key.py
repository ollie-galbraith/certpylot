import os
import logging
from cryptography.hazmat.primitives.asymmetric import rsa, ed25519, ec
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from typing import Union

from .enums import KeyType


class PrivateKey():
    def __init__(self, key_type: KeyType, path = None, passphrase = None):
        self.type = key_type
        if path is not None:
            self.load(path, passphrase)

    def _export(self, path) -> None:
        """
        Exports the private key to the specified path. If the key is encrypted, it will be saved in PKCS8 format, otherwise it will be saved in TraditionalOpenSSL format. The private key is saved with permissions set to 600 (read/write for owner only) to ensure security.

        :param path: The file path where the private key will be saved.
        """

        if hasattr(self, 'serialized_key') is False:
            self._serialize()
        logging.debug(f"Saving private key to {path}")
        with open(path, "wb") as f:
            f.write(self.serialized_key)
            f.close()

        os.chmod(path, 0o600)

    def _generate(self, key_size = 4096) -> Union[rsa.RSAPrivateKey, ed25519.Ed25519PrivateKey, ec.EllipticCurvePrivateKey]:
        """
        Generates a new private key based on the specified key type. For RSA keys, the key size can be specified (default is 4096 bits). For ED25519 and ECDSA keys, the appropriate generation method is used.

        :param key_size: The size of the RSA key to generate (ignored for ED25519 and ECDSA).
        :return: The generated private key object.
        """

        logging.debug(f"Generating new {self.type} private key")
        if self.type == KeyType.RSA:
            self.private_key = rsa.generate_private_key(
                public_exponent = 65537,
                key_size = key_size,
                backend = default_backend()
            )
        if self.type == KeyType.ED25519:
            self.private_key = ed25519.Ed25519PrivateKey.generate()

        if self.type == KeyType.ECDSA:
            self.private_key = ec.generate_private_key(ec.SECP256R1())

        return self.private_key

    def load(self, path, passphrase = None) -> Union[rsa.RSAPrivateKey, ed25519.Ed25519PrivateKey, ec.EllipticCurvePrivateKey]:
        """
        Loads a private key from the specified file path. If the key is encrypted, a passphrase must be provided to decrypt it. The method reads the key file in binary mode and uses the appropriate deserialization method based on the key type.

        :param path: The file path from which to load the private key.
        :param passphrase: The passphrase to decrypt the private key (if it is encrypted).
        :return: The loaded private key object.
        """

        with open(path, 'rb') as file:
            self.private_key = serialization.load_pem_private_key(
                file.read(),
                password = passphrase.encode() if passphrase is not None else None,  # Use a passphrase if the key is encrypted
                backend = default_backend()
            )

        return self.private_key

    def new(self, path: str, passphrase: str = None) -> None:
        """
        Generates a new private key and exports it to the specified path.

        :param path: The file path where the new private key will be saved.
        :param passphrase: The passphrase to encrypt the private key (optional).
        """

        if passphrase is not None:
            self.passphrase = passphrase
        self._generate()
        self.serialize()
        self._export(path)

    def serialize(self) -> bytes:
        """
        Serializes the private key into a byte string. If the key is encrypted, it will be serialized in PKCS8 format with encryption. If the key is not encrypted, it will be serialized in TraditionalOpenSSL format without encryption. For ED25519 keys, the OpenSSH format is used for serialization.

        :return: The serialized private key as a byte string.
        """

        if hasattr(self, 'private_key') is False:
            raise Exception('Need to load private key first')

        logging.debug("Serializing private key")

        serialization_args = dict(
            encoding             = serialization.Encoding.PEM,
            format               = serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm = serialization.NoEncryption()
        )

        if self.type == KeyType.ED25519:
            serialization_args['format'] = serialization.PrivateFormat.OpenSSH

        if hasattr(self, 'passphrase') is True:
            serialization_args['encryption_algorithm'] = serialization.BestAvailableEncryption(self.passphrase.encode("utf-8"))
            serialization_args['format'] = serialization.PrivateFormat.PKCS8

        self.serialized_key = self.private_key.private_bytes(**serialization_args)

        return self.serialized_key
