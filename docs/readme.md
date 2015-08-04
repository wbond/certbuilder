# certbuilder Documentation

*certbuilder* is a Python library for constructing X.509 certificates. It
provides a high-level interface with knowledge of RFC5280 to produce, valid,
correct certificates without terrible APIs or hunting through RFCs.

Since its only dependencies are the
[*asn1crypto*](https://github.com/wbond/asn1crypto#readme) and
[*oscrypto*](https://github.com/wbond/oscrypto#readme) libraries, it is
easy to install and use on Windows, OS X, Linux and the BSDs.

The documentation consists of the following topics:

 - [Basic Usage](#basic-usage)
 - [CA and End-Entity Certificates](#ca-and-end-entity-certificates)
 - [API Documentation](docs/api.md)

## Basic Usage

A simple, self-signed certificate can be created by generating a public/private
key pair using *oscrypto* and then passing a dictionary of name information to
the `CertificateBuilder()` constructor:

```python
from oscrypto import asymmetric
from certbuilder import CertificateBuilder


public_key, private_key = asymmetric.generate_pair('rsa', bit_size=2048)

with open('/path/to/my/env/will_bond.key', 'wb') as f:
    f.write(asymmetric.dump_private_key(private_key, 'password'))

builder = CertificateBuilder(
    {
        'country_name': 'US',
        'state_or_province_name': 'Massachusetts',
        'locality_name': 'Newbury',
        'organization_name': 'Codex Non Sufficit LC',
        'common_name': 'Will Bond',
    },
    public_key
)
builder.self_signed = True
certificate = builder.build(private_key)

with open('/path/to/my/env/will_bond.crt', 'wb') as f:
    f.write(asymmetric.dump_certificate(certificate))
```

All name components must be unicode strings. Common name keys include:

 - `country_name`
 - `state_or_province_name`
 - `locality_name`
 - `organization_name`
 - `common_name`

Less common keys include:

 - `organizational_unit_name`
 - `email_address`
 - `street_address`
 - `postal_code`
 - `business_category`
 - `incorporation_locality`
 - `incorporation_state_or_province`
 - `incorporation_country`

See [`CertificateBuilder.subject`](docs/api.md#subject-attribute) for a full
list of supported name keys.

## CA and End-Entity Certificates

Beyond self-signed certificates lives the world of root CAs, intermediate
CAs and end-entity certificates.

The example below will create a root CA and then an end-entity certificate
signed by the root. By simply creating another CA certificate signed by the
root CA, an intermediate CA certificate could be added.

```python
from oscrypto import asymmetric
from certbuilder import CertificateBuilder


# Generate and save the key and certificate for the root CA
root_ca_public_key, root_ca_private_key = asymmetric.generate_pair('rsa', bit_size=2048)

with open('/path/to/my/env/root_ca.key', 'wb') as f:
    f.write(asymmetric.dump_private_key(root_ca_private_key, 'password'))

builder = CertificateBuilder(
    {
        'country_name': 'US',
        'state_or_province_name': 'Massachusetts',
        'locality_name': 'Newbury',
        'organization_name': 'Codex Non Sufficit LC',
        'common_name': 'CodexNS Root CA 1',
    },
    root_ca_public_key
)
builder.self_signed = True
builder.end_entity = False
root_ca_certificate = builder.build(root_ca_private_key)

with open('/path/to/my/env/root_ca.crt', 'wb') as f:
    f.write(asymmetric.dump_certificate(root_ca_certificate))


# Generate an end-entity key and certificate, signed by the root
end_entity_public_key, end_entity_private_key = asymmetric.generate_pair('rsa', bit_size=2048)

with open('/path/to/my/env/will_bond.key', 'wb') as f:
    f.write(asymmetric.dump_private_key(end_entity_private_key, 'password'))

builder = CertificateBuilder(
    {
        'country_name': 'US',
        'state_or_province_name': 'Massachusetts',
        'locality_name': 'Newbury',
        'organization_name': 'Codex Non Sufficit LC',
        'common_name': 'Will Bond',
    },
    end_entity_public_key
)
builder.issuer = root_ca_certificate
end_entity_certificate = builder.build(root_ca_private_key)

with open('/path/to/my/env/will_bond.crt', 'wb') as f:
    f.write(asymmetric.dump_certificate(end_entity_certificate))
```
