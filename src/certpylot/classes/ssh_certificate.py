import os
import re
import logging
from cryptography.hazmat.primitives import serialization
from .enums import KeyType, Encoding
from .private_key import PrivateKey


class SSHKeyPair():
    def __init__(self, key_type: KeyType, path: str = None, private_key: PrivateKey = None):
        self.type = key_type
        if private_key is not None:
            self.private_key = private_key

    def _export(self, path: str) -> None:
        """
        Exports the public key to the specified path. If the path does not end with '.pub', it will be appended automatically. The method checks if the public key is loaded before attempting to export it. If a key comment is set, it will be included in the exported public key file.

        :param path: The file path where the public key will be saved.
        """

        if hasattr(self, 'public_key') is False:
            raise Exception("Need to load public key")

        if re.match(r'^.*\.pub$', path) is None:
            path = f'{path}.pub'
        logging.debug(f"Saving public key to {path}")

        with open(path, "w", encoding = "utf-8") as f:
            public_key = self.public_key.decode()

            if hasattr(self, 'key_comment'):
                public_key = f'{public_key} {self.key_comment}'

            f.write(public_key)
            f.close()

    def _generate(self, comment: str = None) -> None:
        """
        Generates the public key from the private key and optionally adds a comment. The public key is serialized in OpenSSH format. If a comment is provided, it is stored as an attribute and can be included in the exported public key file.

        :param comment: An optional comment to associate with the public key.
        """
        self.public_key = self.private_key.public_key().public_bytes(
            encoding = Encoding.OPENSSH.encoding,
            format = serialization.PublicFormat.OpenSSH
        )

        if comment is not None:
            self.key_comment = comment

    def new(self, path: str, passphrase: str = None, comment: str = None) -> None:
        """
        Generates a new SSH key pair and exports them to the specified path.

        :param path: The file path where the key pair will be saved (the public key will be saved with a '.pub' extension).
        :param passphrase: The passphrase to encrypt the private key (optional).
        :param comment: An optional comment to associate with the public key.
        """

        if hasattr(self, "private_key") is False:
            logging.debug("Generating new private key")

            path, ext = os.path.splitext(path)
            PrivateKey(self.type).new(path, passphrase)
            self.private_key = PrivateKey(key_type = self.type).load(path = path, passphrase = passphrase)

        if hasattr(self, 'public_key') is False:
            self._generate(comment)
        else:
            if hasattr(self, 'key_comment') is False:
                self.key_comment = comment

        self._export(path)
