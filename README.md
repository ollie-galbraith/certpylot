# certpylot

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
from certpylot import Certificate

cert = Certificate(url="https://jsonplaceholder.typicode.com")
info = cert.get()
print(info)
```

### Load a Certificate from a File

```python
cert = Certificate(path="path/to/cert.pem")
info = cert.get()
print(info)
```

### Generate a Private Key

```python
from certpylot import PrivateKey

key = PrivateKey()
key.generate()
key.export("private_key.pem")
```

### Generate a CSR

```python
from certpylot import Csr, PrivateKey

key = PrivateKey()
key.generate()
key.serialize()
csr = Csr()
csr.generate("example.com", key.serialized_key)
csr.export("csr.pem")
```

## API Reference

### Certificate

- `Certificate(path=..., url=..., port=443, certificate_type='pem')`
- `get(path=None, url=None, port=443, certificate_type='pem')`
- `subject()`
- `issuer()`
- `serial_number()`
- `fingerprint()`
- `thumbprint()`
- `not_valid_before()`
- `not_valid_after()`
- `public_key()`
- `extensions()`
- `extension(extension_oid)`
- `export(path)`

### PrivateKey

- `PrivateKey()`
- `generate(key_size=4096)`
- `export(path)`
- `serialize()`
- `load(path, password=None)`

### Csr

- `Csr()`
- `generate(domains, serialized_private_key)`
- `export(path)`

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