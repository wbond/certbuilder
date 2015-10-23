# certbuilder

A Python library for creating and signing X.509 certificates.

*certbuilder* is part of the modularcrypto family of Python packages:

 - [asn1crypto](https://github.com/wbond/asn1crypto)
 - [oscrypto](https://github.com/wbond/oscrypto)
 - [certbuilder](https://github.com/wbond/certbuilder)
 - [crlbuilder](https://github.com/wbond/crlbuilder)

## License

*certbuilder* is licensed under the terms of the MIT license. See the
[LICENSE](LICENSE) file for the exact license text.

## Dependencies

 - [*asn1crypto*](https://github.com/wbond/asn1crypto)
 - [*oscrypto*](https://github.com/wbond/oscrypto)
 - Python 2.6, 2.7, 3.2, 3.3, 3.4, 3.5, pypy or pypy3

## Version

0.9.0 - [changelog](changelog.md)

## Installation

```bash
pip install git+git://github.com/wbond/asn1crypto.git
pip install git+git://github.com/wbond/oscrypto.git
pip install git+git://github.com/wbond/certbuilder.git
```

## Documentation

[*certbuilder* documentation](docs/readme.md)

## Development

To install required development dependencies, execute:

```bash
pip install -r dev-requirements.txt
```

The following commands will run the test suite, linter and test coverage:

```bash
python run.py tests
python run.py lint
python run.py coverage
```

To run only some tests, pass a regular expression as a parameter to `tests`.

```bash
python run.py tests build
```

To regenerate the markdown API documentation, execute:

```bash
python run.py api_docs
```
