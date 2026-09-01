import unittest
import sys
import os

from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey

# Add the parent directory to the sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from src.certpylot import SSLCertificate, SSHKeyPair, PrivateKey, Csr, KeyType

class TestCertificate(unittest.TestCase):
    def setUp(self):
        self.url = "https://jsonplaceholder.typicode.com"
        self.cert = SSLCertificate(url=self.url)
        
    def test_certificate_initialization(self):
        certificate = self.cert.get()
        self.assertIsNotNone(certificate)
        self.assertIsInstance(certificate, dict)
        self.assertIn('subject', certificate)
        self.assertIn('issuer', certificate)
        self.assertIn('serial_number', certificate)
        self.assertIn('fingerprint', certificate)
        self.assertIn('thumbprint', certificate)
        self.assertIn('not_valid_before', certificate)
        self.assertIn('not_valid_after', certificate)

class TestPrivateKey(unittest.TestCase):
    def setUp(self):
        self.private_key_path = "./test_private_key.pem"
        self.private_key = PrivateKey(key_type=KeyType.RSA)
        
    def test_generate_private_key(self):
        self.private_key._generate()
        self.assertIsNotNone(self.private_key.private_key)
        self.assertIsInstance(self.private_key.private_key, RSAPrivateKey)
        
    def test_export_private_key(self):
        self.private_key.new(self.private_key_path)
        self.assertIsNotNone(self.private_key.serialized_key)
        self.assertTrue(os.path.exists(self.private_key_path))
        
    def test_load_private_key(self):
        self.private_key.load(self.private_key_path)
        self.assertIsNotNone(self.private_key.private_key)
        self.assertIsInstance(self.private_key.private_key, RSAPrivateKey)
        
        if os.path.exists(self.private_key_path):
            os.remove(self.private_key_path)

class TestCsr(unittest.TestCase):
    def setUp(self):
        self.csr = Csr()
        self.private_key = PrivateKey(key_type=KeyType.RSA)
        self.private_key._generate()
        self.private_key.serialize()
        
    def test_generate_csr(self):
        self.csr.generate(['Test CSR'], self.private_key.serialized_key)
        self.assertIsNotNone(self.csr.csr)
        self.assertIsInstance(self.csr.csr, bytes)
        
    def test_export_csr(self):
        self.csr.generate(['Test CSR'], self.private_key.serialized_key)
        csr_path = "./test_csr.pem"
        self.csr.export(csr_path)
        self.assertTrue(os.path.exists(csr_path))
        
        if os.path.exists(csr_path):
            os.remove(csr_path)

class TestSSHKeyPair(unittest.TestCase):
    def setUp(self):
        self.ssh_key_pair = SSHKeyPair(key_type=KeyType.RSA)
        self.ssh_key_path = "./test_ssh_key"

    def test_generate_ssh_key_pair(self):
        self.ssh_key_pair.new(self.ssh_key_path)
        self.assertTrue(os.path.exists(self.ssh_key_path))
        self.assertTrue(os.path.exists(f"{self.ssh_key_path}.pub"))
        os.remove(self.ssh_key_path)
        os.remove(f"{self.ssh_key_path}.pub")

if __name__ == '__main__':
    unittest.main()