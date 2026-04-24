import logging
from acme import crypto_util


class Csr():
    def __init__(self):
        pass

    def export(self, path: str):
        """
        Exports the CSR to the specified path. The method writes the CSR data to a file in binary mode. If the CSR has not been generated yet, an exception will be raised.

        :param path: The file path where the CSR will be saved.
        """

        if hasattr(self, 'csr') is False:
            raise Exception("Need to generate CSR first")

        logging.debug(f"Exporting CSR to path {path}")
        with open(path, "wb") as file:
            file.write(self.csr)
            file.close()

    def generate(self, domains: list[str], private_key: bytes) -> bytes:
        """
        Generates a new CSR with the specified domains and private key.

        :param domains: A list of domain names to include in the CSR.
        :param private_key: The private key to use for generating the CSR, provided as a byte string.
        """

        logging.debug("Generating new CSR")
        csr = crypto_util.make_csr(private_key, domains)
        self.csr = csr
        return csr
