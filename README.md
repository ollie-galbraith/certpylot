# certpylot

[![Python package](https://github.com/ollie-galbraith/certpylot/actions/workflows/python-package.yml/badge.svg)](https://github.com/ollie-galbraith/certpylot/actions/workflows/python-package.yml)

**certpylot** is a Python library for managing SSL/TLS certificates with a focus on security and ease of use. It provides tools to fetch, inspect, and manipulate certificates, as well as generate and manage private keys and CSRs (Certificate Signing Requests).

## Features

- Fetch and inspect SSL/TLS certificates from files or remote servers
- View certificate details: subject, issuer, validity, fingerprint, and more
- Generate and export private keys
- Create and export CSRs (Certificate Signing Requests)
- Extension and fingerprint utilities
- Simple, object-oriented API

## Installation

Install via [PyPI](https://pypi.org/project/certpylot/) (if published):

```bash
pip install certpylot
```

Or install from source:

```bash
git clone https://github.com/ollie-galbraith/certpylot.git
cd certpylot
poetry install
```

## Usage

### Fetch and Inspect a Certificate from a URL

```python
from certpylot import SSLCertificate

cert = SSLCertificate(url="https://jsonplaceholder.typicode.com")
info = cert.get()
print(info)
```

### Load a Certificate from a File

```python
from certpylot import SSLCertificate

cert = SSLCertificate(path="path/to/cert.pem")
info = cert.get()
print(info)
```

### Generate a Private Key

```python
from certpylot import PrivateKey, KeyType

key = PrivateKey(KeyType.RSA)
key._generate()
key._export("private_key.pem")
```

### Generate a CSR

```python
from certpylot import Csr, PrivateKey, KeyType

key = PrivateKey(KeyType.RSA)
key._generate()
csr = Csr()
csr.generate(["example.com"], key.serialized_key)
csr.export("csr.pem")
```

### Generate a Self-Signed Certificate

```python
from certpylot import SelfSignedCertificate, KeyType

cert = SelfSignedCertificate(key_type=KeyType.RSA)
cert.generate(
    common_name="example.com",
    organization="My Organization",
    sans=["example.com", "*.example.com"],
    valid_days=365
)
cert.serialize()
```

### Generate SSH Key Pair

```python
from certpylot import SSHKeyPair, KeyType

ssh_keys = SSHKeyPair(KeyType.ED25519)
ssh_keys.new(path="/path/to/key", passphrase="optional_passphrase", comment="user@host")
```

## API Reference

### SSLCertificate

- `SSLCertificate(path=..., url=..., port=443, certificate_type=Encoding.PEM, debug=False, allow_unverified=False)`
- `get(path=None, url=None, port=443, certificate_type=Encoding.PEM)` - Get certificate info as dictionary
- `load(path=None, url=None, port=443, certificate_type=Encoding.PEM)` - Load a certificate
- `export(path)` - Export certificate to file
- `export_pfx(path, private_key, friendly_name, pfx_password=None, private_key_passphrase=None)` - Export as PKCS12/PFX
- `convert(path, output_type)` - Convert certificate to different encoding

**Properties:**

- `subject` - Certificate subject (RFC4514 format)
- `issuer` - Certificate issuer (RFC4514 format)
- `serial_number` - Serial number in hex format
- `fingerprint` - SHA-256 fingerprint
- `thumbprint` - SHA-1 fingerprint
- `public_key` - Public key object
- `signature_hash_algorithm` - Hash algorithm name
- `extensions` - Certificate extensions
- `not_valid_before(convert_to_timezone=utc)` - Validity start datetime
- `not_valid_after(convert_to_timezone=utc)` - Validity end datetime
- `expiring_in` - Days until expiration

### PrivateKey

- `PrivateKey(key_type, path=None, passphrase=None)` - Create private key instance
  - `key_type` should be `KeyType.RSA`, `KeyType.ED25519`, or `KeyType.ECDSA`
- `_generate(key_size=4096)` - Generate a new private key
- `_export(path)` - Export private key to file (permissions: 600)
- `_serialize()` - Serialize the private key to bytes
- `load(path, passphrase=None)` - Load private key from file
- `new(path, passphrase=None)` - Generate and save a new key

### Csr

- `Csr()` - Create CSR instance
- `generate(domains, private_key)` - Generate CSR
  - `domains`: list of domain names
  - `private_key`: private key as bytes
- `export(path)` - Export CSR to file

### SelfSignedCertificate

- `SelfSignedCertificate(key_type=KeyType.RSA, key_size=2048, private_key=None)`
- `generate(country=None, state=None, locality=None, organization=None, organizational_unit=None, common_name=None, sans=['localhost'], valid_days=365)` - Generate self-signed certificate
- `serialize(cert_type=Encoding.PEM)` - Serialize certificate to bytes

### SSHKeyPair

- `SSHKeyPair(key_type, path=None, private_key=None)` - Create SSH key pair instance
- `new(path, passphrase=None, comment=None)` - Generate and export SSH key pair
- `_generate(comment=None)` - Generate public key from private key
- `_export(path)` - Export public key to file

### Enums

**KeyType:**
- `KeyType.RSA` - RSA key type
- `KeyType.ED25519` - ED25519 key type
- `KeyType.ECDSA` - ECDSA key type

**Encoding:**
- `Encoding.PEM` - PEM encoding
- `Encoding.DER` - DER encoding

**PrivateKeyFormat:**
- `PrivateKeyFormat.TRADITIONAL_OPENSSL` - Traditional OpenSSL format
- `PrivateKeyFormat.PKCS8` - PKCS8 format
- `PrivateKeyFormat.OPENSSH` - OpenSSH format

## Testing

Run the unit tests with:

```bash
pytest
```

## License

This project is licensed under the GPL-3.0 License.

## Contributing

Contributions are welcome! Please open issues or pull requests on [GitHub](https://github.com/ollie-galbraith/certpylot).

---

**Author:** Oliver Galbraith  
**Project Home:** [https://github.com/ollie-galbraith/certpylot](https://github.com/ollie-galbraith/certpylot)