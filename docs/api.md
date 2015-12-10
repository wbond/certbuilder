# certbuilder API Documentation

### `pem_armor_certificate()` function

> ```python
> def pem_armor_certificate(certificate):
>     """
>     :param certificate:
>         An asn1crypto.x509.Certificate object of the certificate to armor.
>         Typically this is obtained from CertificateBuilder.build().
>
>     :return:
>         A byte string of the PEM-encoded certificate
>     """
> ```
>
> Encodes a certificate into PEM format

### `CertificateBuilder()` class

> ##### constructor
>
> > ```python
> > def __init__(self, subject, subject_public_key):
> >     """
> >     :param subject:
> >         An asn1crypto.x509.Name object, or a dict - see the docstring
> >         for .subject for a list of valid options
> >     
> >     :param subject_public_key:
> >         An asn1crypto.keys.PublicKeyInfo object containing the public key
> >         the certificate is being issued for
> >     """
> > ```
> >
> > Unless changed, certificates will use SHA-256 for the signature,
> > and will be valid from the moment created for one year. The serial
> > number will be generated from the current time and a random number.
>
> ##### `.self_signed` attribute
>
> > A bool - if the certificate should be self-signed.
>
> ##### `.serial_number` attribute
>
> > An int representable in 160 bits or less - must uniquely identify
> > this certificate when combined with the issuer name.
>
> ##### `.issuer` attribute
>
> > An asn1crypto.x509.Certificate object of the issuer. Used to populate
> > both the issuer field, but also the authority key identifier extension.
>
> ##### `.begin_date` attribute
>
> > A datetime.datetime object of when the certificate becomes valid.
>
> ##### `.end_date` attribute
>
> > A datetime.datetime object of when the certificate is last to be
> > considered valid.
>
> ##### `.subject` attribute
>
> > An asn1crypto.x509.Name object, or a dict with a minimum of the
> > following keys:
> > 
> >  - "country_name"
> >  - "state_or_province_name"
> >  - "locality_name"
> >  - "organization_name"
> >  - "common_name"
> > 
> > Less common keys include:
> > 
> >  - "organizational_unit_name"
> >  - "email_address"
> >  - "street_address"
> >  - "postal_code"
> >  - "business_category"
> >  - "incorporation_locality"
> >  - "incorporation_state_or_province"
> >  - "incorporation_country"
> > 
> > Uncommon keys include:
> > 
> >  - "surname"
> >  - "title"
> >  - "serial_number"
> >  - "name"
> >  - "given_name"
> >  - "initials"
> >  - "generation_qualifier"
> >  - "dn_qualifier"
> >  - "pseudonym"
> >  - "domain_component"
> > 
> > All values should be unicode strings.
>
> ##### `.subject_public_key` attribute
>
> > An asn1crypto.keys.PublicKeyInfo or oscrypto.asymmetric.PublicKey
> > object of the subject's public key.
>
> ##### `.hash_algo` attribute
>
> > A unicode string of the hash algorithm to use when signing the
> > certificate - "sha1" (not recommended), "sha256" or "sha512".
>
> ##### `.ca` attribute
>
> > A bool - if the certificate is a CA cert
>
> ##### `.subject_alt_emails` attribute
>
> > A list of unicode strings - the emails in the subject alt name
> > extension.
>
> ##### `.subject_alt_domains` attribute
>
> > A list of unicode strings - the domains in the subject alt name
> > extension.
>
> ##### `.subject_alt_uris` attribute
>
> > A list of unicode strings - the URIs in the subject alt name
> > extension.
>
> ##### `.subject_alt_ips` attribute
>
> > A list of unicode strings - the IPs in the subject alt name extension.
>
> ##### `.key_usage` attribute
>
> > A set of unicode strings - the allowed usage of the key from the key
> > usage extension.
>
> ##### `.extended_key_usage` attribute
>
> > A set of unicode strings - the allowed usage of the key from the
> > extended key usage extension.
>
> ##### `.crl_url` attribute
>
> > Location of the certificate revocation list (CRL) for the certificate.
> > Will be one of the following types:
> > 
> >  - None for no CRL
> >  - A unicode string of the URL to the CRL for this certificate
> >  - A 2-element tuple of (unicode string URL,
> >    asn1crypto.x509.Certificate object of CRL issuer) for an indirect
> >    CRL
>
> ##### `.delta_crl_url` attribute
>
> > Location of the delta CRL for the certificate. Will be one of the
> > following types:
> > 
> >  - None for no delta CRL
> >  - A unicode string of the URL to the delta CRL for this certificate
> >  - A 2-element tuple of (unicode string URL,
> >    asn1crypto.x509.Certificate object of CRL issuer) for an indirect
> >    delta CRL
>
> ##### `.ocsp_url` attribute
>
> > Location of the OCSP responder for this certificate. Will be one of the
> > following types:
> > 
> >  - None for no OCSP responder
> >  - A unicode string of the URL to the OCSP responder
>
> ##### `.ocsp_no_check` attribute
>
> > A bool - if the certificate should have the OCSP no check extension.
> > Only applicable to certificates created for signing OCSP responses.
> > Such certificates should normally be issued for a very short period of
> > time since they are effectively whitelisted by clients.
>
> ##### `.set_extension()` method
>
> > ```python
> > def set_extension(self, name, value, allow_deprecated=False):
> >     """
> >     :param name:
> >         A unicode string of an extension id name from
> >         asn1crypto.x509.ExtensionId
> >     
> >     :param value:
> >         A value object per the specs defined by asn1crypto.x509.Extension
> >     
> >     :param allow_deprecated:
> >         A bool - indicates if deprecated extensions should be allowed
> >     """
> > ```
> >
> > Sets the value for an extension using a fully constructed
> > asn1crypto.core.Asn1Value object. Normally this should not be needed,
> > and the convenience attributes should be sufficient.
> > 
> > See the definition of asn1crypto.x509.Extension to determine the
> > appropriate object type for a given extension. Extensions are marked
> > as critical when RFC 5280 or RFC 6960 indicate so. If an extension is
> > validly marked as critical or not (such as certificate policies and
> > extended key usage), this class will mark it as non-critical.
>
> ##### `.build()` method
>
> > ```python
> > def build(self, signing_private_key):
> >     """
> >     :param signing_private_key:
> >         An asn1crypto.keys.PrivateKeyInfo or oscrypto.asymmetric.PrivateKey
> >         object for the private key to sign the certificate with. If the key
> >         is self-signed, this should be the private key that matches the
> >         public key, otherwise it needs to be the issuer's private key.
> >     
> >     :return:
> >         An asn1crypto.x509.Certificate object of the newly signed
> >         certificate
> >     """
> > ```
> >
> > Validates the certificate information, constructs the ASN.1 structure
> > and then signs it
