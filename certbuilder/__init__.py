# coding: utf-8
from __future__ import unicode_literals, division, absolute_import, print_function

from datetime import datetime, timedelta
import inspect
import re
import sys
import textwrap
import time

from asn1crypto import x509, keys, core
from asn1crypto.util import int_to_bytes, int_from_bytes, timezone
from oscrypto import asymmetric, util

if sys.version_info < (3,):
    int_types = (int, long)  # noqa
    str_cls = unicode  # noqa
    byte_cls = str
else:
    int_types = (int,)
    str_cls = str
    byte_cls = bytes


__version__ = '0.13.0'
__version_info__ = (0, 13, 0)


def _writer(func):
    """
    Decorator for a custom writer, but a default reader
    """

    name = func.__name__
    return property(fget=lambda self: getattr(self, '_%s' % name), fset=func)


def pem_armor_certificate(certificate):
    """
    Encodes a certificate into PEM format

    :param certificate:
        An asn1crypto.x509.Certificate object of the certificate to armor.
        Typically this is obtained from CertificateBuilder.build().

    :return:
        A byte string of the PEM-encoded certificate
    """

    return asymmetric.dump_certificate(certificate)


class CertificateBuilder(object):

    _self_signed = False
    _serial_number = None
    _issuer = None
    _begin_date = None
    _end_date = None
    _subject = None
    _subject_public_key = None
    _hash_algo = None
    _basic_constraints = None
    _subject_alt_name = None
    _key_identifier = None
    _authority_key_identifier = None
    _key_usage = None
    _extended_key_usage = None
    _crl_distribution_points = None
    _freshest_crl = None
    _authority_information_access = None
    _ocsp_no_check = False
    _other_extensions = None

    _special_extensions = set([
        'basic_constraints',
        'subject_alt_name',
        'key_identifier',
        'authority_key_identifier',
        'key_usage',
        'extended_key_usage',
        'crl_distribution_points',
        'freshest_crl',
        'authority_information_access',
        'ocsp_no_check',
    ])
    _deprecated_extensions = set([
        'subject_directory_attributes',
        'entrust_version_extension',
        'netscape_certificate_type',
    ])

    def __init__(self, subject, subject_public_key):
        """
        Unless changed, certificates will use SHA-256 for the signature,
        and will be valid from the moment created for one year. The serial
        number will be generated from the current time and a random number.

        :param subject:
            An asn1crypto.x509.Name object, or a dict - see the docstring
            for .subject for a list of valid options

        :param subject_public_key:
            An asn1crypto.keys.PublicKeyInfo object containing the public key
            the certificate is being issued for
        """

        self.subject = subject
        self.subject_public_key = subject_public_key
        self.ca = False

        self._hash_algo = 'sha256'
        self._other_extensions = {}

    @_writer
    def self_signed(self, value):
        """
        A bool - if the certificate should be self-signed.
        """

        self._self_signed = bool(value)

        if self._self_signed:
            self._issuer = None

    @_writer
    def serial_number(self, value):
        """
        An int representable in 160 bits or less - must uniquely identify
        this certificate when combined with the issuer name.
        """

        if not isinstance(value, int_types):
            raise TypeError(_pretty_message(
                '''
                serial_number must be an integer, not %s
                ''',
                _type_name(value)
            ))

        if value < 0:
            raise ValueError(_pretty_message(
                '''
                serial_number must be a non-negative integer, not %s
                ''',
                repr(value)
            ))

        if len(int_to_bytes(value)) > 20:
            required_bits = len(int_to_bytes(value)) * 8
            raise ValueError(_pretty_message(
                '''
                serial_number must be an integer that can be represented by a
                160-bit number, specified requires %s
                ''',
                required_bits
            ))

        self._serial_number = value

    @_writer
    def issuer(self, value):
        """
        An asn1crypto.x509.Certificate object of the issuer. Used to populate
        both the issuer field, but also the authority key identifier extension.
        """

        is_oscrypto = isinstance(value, asymmetric.Certificate)
        if not isinstance(value, x509.Certificate) and not is_oscrypto:
            raise TypeError(_pretty_message(
                '''
                issuer must be an instance of asn1crypto.x509.Certificate or
                oscrypto.asymmetric.Certificate, not %s
                ''',
                _type_name(value)
            ))

        if is_oscrypto:
            value = value.asn1

        self._issuer = value.subject

        self._key_identifier = self._subject_public_key.sha1
        self._authority_key_identifier = x509.AuthorityKeyIdentifier({
            'key_identifier': value.public_key.sha1
        })

    @_writer
    def begin_date(self, value):
        """
        A datetime.datetime object of when the certificate becomes valid.
        """

        if not isinstance(value, datetime):
            raise TypeError(_pretty_message(
                '''
                begin_date must be an instance of datetime.datetime, not %s
                ''',
                _type_name(value)
            ))

        self._begin_date = value

    @_writer
    def end_date(self, value):
        """
        A datetime.datetime object of when the certificate is last to be
        considered valid.
        """

        if not isinstance(value, datetime):
            raise TypeError(_pretty_message(
                '''
                end_date must be an instance of datetime.datetime, not %s
                ''',
                _type_name(value)
            ))

        self._end_date = value

    @_writer
    def subject(self, value):
        """
        An asn1crypto.x509.Name object, or a dict with a minimum of the
        following keys:

         - "country_name"
         - "state_or_province_name"
         - "locality_name"
         - "organization_name"
         - "common_name"

        Less common keys include:

         - "organizational_unit_name"
         - "email_address"
         - "street_address"
         - "postal_code"
         - "business_category"
         - "incorporation_locality"
         - "incorporation_state_or_province"
         - "incorporation_country"

        Uncommon keys include:

         - "surname"
         - "title"
         - "serial_number"
         - "name"
         - "given_name"
         - "initials"
         - "generation_qualifier"
         - "dn_qualifier"
         - "pseudonym"
         - "domain_component"

        All values should be unicode strings.
        """

        is_dict = isinstance(value, dict)
        if not isinstance(value, x509.Name) and not is_dict:
            raise TypeError(_pretty_message(
                '''
                subject must be an instance of asn1crypto.x509.Name or a dict,
                not %s
                ''',
                _type_name(value)
            ))

        if is_dict:
            value = x509.Name.build(value)

        self._subject = value

    @_writer
    def subject_public_key(self, value):
        """
        An asn1crypto.keys.PublicKeyInfo or oscrypto.asymmetric.PublicKey
        object of the subject's public key.
        """

        is_oscrypto = isinstance(value, asymmetric.PublicKey)
        if not isinstance(value, keys.PublicKeyInfo) and not is_oscrypto:
            raise TypeError(_pretty_message(
                '''
                subject_public_key must be an instance of
                asn1crypto.keys.PublicKeyInfo or oscrypto.asymmetric.PublicKey,
                not %s
                ''',
                _type_name(value)
            ))

        if is_oscrypto:
            value = value.asn1

        self._subject_public_key = value
        self._key_identifier = self._subject_public_key.sha1
        self._authority_key_identifier = None

    @_writer
    def hash_algo(self, value):
        """
        A unicode string of the hash algorithm to use when signing the
        certificate - "sha1" (not recommended), "sha256" or "sha512".
        """

        if value not in set(['sha1', 'sha256', 'sha512']):
            raise ValueError(_pretty_message(
                '''
                hash_algo must be one of "sha1", "sha256", "sha512", not %s
                ''',
                repr(value)
            ))

        self._hash_algo = value

    @property
    def ca(self):
        """
        A bool - if the certificate is a CA cert
        """

        return self._basic_constraints['ca'].native

    @ca.setter
    def ca(self, value):
        self._basic_constraints = x509.BasicConstraints({'ca': bool(value)})

        if value:
            self._key_usage = x509.KeyUsage(set(['key_cert_sign', 'crl_sign']))
            self._extended_key_usage = x509.ExtKeyUsageSyntax(['ocsp_signing'])
        else:
            self._key_usage = x509.KeyUsage(set(['digital_signature', 'key_encipherment']))
            self._extended_key_usage = x509.ExtKeyUsageSyntax(['server_auth', 'client_auth'])

    @property
    def subject_alt_domains(self):
        """
        A list of unicode strings - the domains in the subject alt name
        extension.
        """

        return self._get_subject_alt('dns_name')

    @subject_alt_domains.setter
    def subject_alt_domains(self, value):
        self._set_subject_alt('dns_name', value)

    @property
    def subject_alt_emails(self):
        """
        A list of unicode strings - the email addresses in the subject alt name
        extension.
        """

        return self._get_subject_alt('rfc822_name')

    @subject_alt_emails.setter
    def subject_alt_emails(self, value):
        self._set_subject_alt('rfc822_name', value)

    @property
    def subject_alt_ips(self):
        """
        A list of unicode strings - the IPs in the subject alt name extension.
        """

        return self._get_subject_alt('ip_address')

    @subject_alt_ips.setter
    def subject_alt_ips(self, value):
        self._set_subject_alt('ip_address', value)

    @property
    def subject_alt_uris(self):
        """
        A list of unicode strings - the URIs in the subject alt name extension.
        """

        return self._get_subject_alt('uniform_resource_identifier')

    @subject_alt_uris.setter
    def subject_alt_uris(self, value):
        self._set_subject_alt('uniform_resource_identifier', value)

    def _get_subject_alt(self, name):
        """
        Returns the native value for each value in the subject alt name
        extension that is an asn1crypto.x509.GeneralName of the type
        specified by the name param.

        :param name:
            A unicode string use to filter the x509.GeneralName objects by -
            is the name attribute of x509.GeneralName

        :return:
            A list of unicode strings
        """

        if self._subject_alt_name is None:
            return []

        output = []
        for general_name in self._subject_alt_name:
            if general_name.name == name:
                output.append(general_name.native)
        return output

    def _set_subject_alt(self, name, values):
        """
        Replaces all existing asn1crypto.x509.GeneralName objects of the
        choice represented by the name param with the values.

        :param name:
            A unicode string of the choice name of the x509.GeneralName object

        :param values:
            A list of unicode strings to use as the values for the new
            x509.GeneralName objects
        """

        if self._subject_alt_name is not None:
            filtered_general_names = []
            for general_name in self._subject_alt_name:
                if general_name.name != name:
                    filtered_general_names.append(general_name)
            self._subject_alt_name = x509.GeneralNames(filtered_general_names)

        else:
            self._subject_alt_name = x509.GeneralNames()

        if values is not None:
            for value in values:
                new_general_name = x509.GeneralName(name=name, value=value)
                self._subject_alt_name.append(new_general_name)

        if len(self._subject_alt_name) == 0:
            self._subject_alt_name = None

    @property
    def key_usage(self):
        """
        A set of unicode strings - the allowed usage of the key from the key
        usage extension.
        """

        if self._key_usage is None:
            return set()

        return self._key_usage.native

    @key_usage.setter
    def key_usage(self, value):
        if not isinstance(value, set) and value is not None:
            raise TypeError(_pretty_message(
                '''
                key_usage must be an instance of set, not %s
                ''',
                _type_name(value)
            ))

        if value == set() or value is None:
            self._key_usage = None
        else:
            self._key_usage = x509.KeyUsage(value)

    @property
    def extended_key_usage(self):
        """
        A set of unicode strings - the allowed usage of the key from the
        extended key usage extension.
        """

        if self._extended_key_usage is None:
            return set()

        return set(self._extended_key_usage.native)

    @extended_key_usage.setter
    def extended_key_usage(self, value):
        if not isinstance(value, set) and value is not None:
            raise TypeError(_pretty_message(
                '''
                extended_key_usage must be an instance of set, not %s
                ''',
                _type_name(value)
            ))

        if value == set() or value is None:
            self._extended_key_usage = None
        else:
            self._extended_key_usage = x509.ExtKeyUsageSyntax(list(value))

    @property
    def crl_url(self):
        """
        Location of the certificate revocation list (CRL) for the certificate.
        Will be one of the following types:

         - None for no CRL
         - A unicode string of the URL to the CRL for this certificate
         - A 2-element tuple of (unicode string URL,
           asn1crypto.x509.Certificate object of CRL issuer) for an indirect
           CRL
        """

        if self._crl_distribution_points is None:
            return None

        return self._get_crl_url(self._crl_distribution_points)

    @crl_url.setter
    def crl_url(self, value):
        self._crl_distribution_points = self._make_crl_distribution_points('crl_url', value)

    @property
    def delta_crl_url(self):
        """
        Location of the delta CRL for the certificate. Will be one of the
        following types:

         - None for no delta CRL
         - A unicode string of the URL to the delta CRL for this certificate
         - A 2-element tuple of (unicode string URL,
           asn1crypto.x509.Certificate object of CRL issuer) for an indirect
           delta CRL
        """

        if self._freshest_crl is None:
            return None

        return self._get_crl_url(self._freshest_crl)

    @delta_crl_url.setter
    def delta_crl_url(self, value):
        self._freshest_crl = self._make_crl_distribution_points('delta_crl_url', value)

    def _get_crl_url(self, distribution_points):
        """
        Grabs the first URL out of a asn1crypto.x509.CRLDistributionPoints
        object

        :param distribution_points:
            The x509.CRLDistributionPoints object to pull the URL out of

        :return:
            A unicode string or None
        """

        if distribution_points is None:
            return None

        for distribution_point in distribution_points:
            name = distribution_point['distribution_point']
            if name.name == 'full_name' and name.chosen[0].name == 'uniform_resource_identifier':
                return name.chosen[0].chosen.native

        return None

    def _make_crl_distribution_points(self, name, value):
        """
        Constructs an asn1crypto.x509.CRLDistributionPoints object

        :param name:
            A unicode string of the attribute name to use in exceptions

        :param value:
            Either a unicode string of a URL, or a 2-element tuple of a
            unicode string of a URL, plus an asn1crypto.x509.Certificate
            object that will be signing the CRL (for indirect CRLs).

        :return:
            None or an asn1crypto.x509.CRLDistributionPoints object
        """

        if value is None:
            return None

        is_tuple = isinstance(value, tuple)
        if not is_tuple and not isinstance(value, str_cls):
            raise TypeError(_pretty_message(
                '''
                %s must be a unicode string or tuple of (unicode string,
                asn1crypto.x509.Certificate), not %s
                ''',
                name,
                _type_name(value)
            ))

        issuer = None
        if is_tuple:
            if len(value) != 2:
                raise ValueError(_pretty_message(
                    '''
                    %s must be a unicode string or 2-element tuple, not a
                    %s-element tuple
                    ''',
                    name,
                    len(value)
                ))

            if not isinstance(value[0], str_cls) or not isinstance(value[1], x509.Certificate):
                raise TypeError(_pretty_message(
                    '''
                    %s must be a tuple of (unicode string,
                    ans1crypto.x509.Certificate), not (%s, %s)
                    ''',
                    name,
                    _type_name(value[0]),
                    _type_name(value[1])
                ))

            url = value[0]
            issuer = value[1].subject
        else:
            url = value

        general_names = x509.GeneralNames([
            x509.GeneralName(
                name='uniform_resource_identifier',
                value=url
            )
        ])
        distribution_point_name = x509.DistributionPointName(
            name='full_name',
            value=general_names
        )
        distribution_point = x509.DistributionPoint({
            'distribution_point': distribution_point_name
        })
        if issuer:
            distribution_point['crl_issuer'] = x509.GeneralNames([
                x509.GeneralName(name='directory_name', value=issuer)
            ])

        return x509.CRLDistributionPoints([distribution_point])

    @property
    def ocsp_url(self):
        """
        Location of the OCSP responder for this certificate. Will be one of the
        following types:

         - None for no OCSP responder
         - A unicode string of the URL to the OCSP responder
        """

        if self._authority_information_access is None:
            return None

        for ad in self._authority_information_access:
            if ad['access_method'].native == 'ocsp' and ad['access_location'].name == 'uniform_resource_identifier':
                return ad['access_location'].chosen.native

        return None

    @ocsp_url.setter
    def ocsp_url(self, value):
        if value is None:
            self._authority_information_access = None
            return

        if not isinstance(value, str_cls):
            raise TypeError(_pretty_message(
                '''
                ocsp_url must be a unicode string, not %s
                ''',
                _type_name(value)
            ))

        access_description = x509.AccessDescription({
            'access_method': 'ocsp',
            'access_location': x509.GeneralName(
                name='uniform_resource_identifier',
                value=value
            )
        })

        self._authority_information_access = x509.AuthorityInfoAccessSyntax([access_description])

    @_writer
    def ocsp_no_check(self, value):
        """
        A bool - if the certificate should have the OCSP no check extension.
        Only applicable to certificates created for signing OCSP responses.
        Such certificates should normally be issued for a very short period of
        time since they are effectively whitelisted by clients.
        """

        if value is None:
            self._ocsp_no_check = None
        else:
            self._ocsp_no_check = bool(value)

    def set_extension(self, name, value, allow_deprecated=False):
        """
        Sets the value for an extension using a fully constructed
        asn1crypto.core.Asn1Value object. Normally this should not be needed,
        and the convenience attributes should be sufficient.

        See the definition of asn1crypto.x509.Extension to determine the
        appropriate object type for a given extension. Extensions are marked
        as critical when RFC 5280 or RFC 6960 indicate so. If an extension is
        validly marked as critical or not (such as certificate policies and
        extended key usage), this class will mark it as non-critical.

        :param name:
            A unicode string of an extension id name from
            asn1crypto.x509.ExtensionId

        :param value:
            A value object per the specs defined by asn1crypto.x509.Extension

        :param allow_deprecated:
            A bool - indicates if deprecated extensions should be allowed
        """

        extension = x509.Extension({
            'extn_id': name
        })
        # We use native here to convert OIDs to meaningful names
        name = extension['extn_id'].native

        if name in self._deprecated_extensions and not allow_deprecated:
            raise ValueError(_pretty_message(
                '''
                An extension of the type %s was added, however it is
                deprecated. Please add the parameter allow_deprecated=True to
                the method call.
                ''',
                name
            ))

        spec = extension.spec('extn_value')

        if not isinstance(value, spec) and value is not None:
            raise TypeError(_pretty_message(
                '''
                value must be an instance of %s, not %s
                ''',
                _type_name(spec),
                _type_name(value)
            ))

        if name in self._special_extensions:
            setattr(self, '_%s' % name, value)
        else:
            if value is None:
                if name in self._other_extensions:
                    del self._other_extensions[name]
            else:
                self._other_extensions[name] = value

    def _determine_critical(self, name):
        """
        :param name:
            The extension to get the critical value for

        :return:
            A bool indicating the correct value of the critical flag for
            an extension, based on information from RFC 5280 and RFC 6960. The
            correct value is based on the terminology SHOULD or MUST.
        """

        if name == 'subject_alt_name':
            return len(self._subject) == 0

        if name == 'basic_constraints':
            return self.ca is True

        return {
            'subject_directory_attributes': False,
            'key_identifier': False,
            'key_usage': True,
            'private_key_usage_period': False,
            'issuer_alt_name': False,
            'name_constraints': True,
            'crl_distribution_points': False,
            # Based on example EV certificates, non-CA certs have this marked
            # as non-critical, most likely because existing browsers don't
            # seem to support policies or name constraints
            'certificate_policies': False,
            'policy_mappings': True,
            'authority_key_identifier': False,
            'policy_constraints': True,
            'extended_key_usage': False,
            'freshest_crl': False,
            'inhibit_any_policy': True,
            'authority_information_access': False,
            'subject_information_access': False,
            'tls_feature': False,
            'ocsp_no_check': False,
            'entrust_version_extension': False,
            'netscape_certificate_type': False,
        }.get(name, False)

    def build(self, signing_private_key):
        """
        Validates the certificate information, constructs the ASN.1 structure
        and then signs it

        :param signing_private_key:
            An asn1crypto.keys.PrivateKeyInfo or oscrypto.asymmetric.PrivateKey
            object for the private key to sign the certificate with. If the key
            is self-signed, this should be the private key that matches the
            public key, otherwise it needs to be the issuer's private key.

        :return:
            An asn1crypto.x509.Certificate object of the newly signed
            certificate
        """

        is_oscrypto = isinstance(signing_private_key, asymmetric.PrivateKey)
        if not isinstance(signing_private_key, keys.PrivateKeyInfo) and not is_oscrypto:
            raise TypeError(_pretty_message(
                '''
                signing_private_key must be an instance of
                asn1crypto.keys.PrivateKeyInfo or
                oscrypto.asymmetric.PrivateKey, not %s
                ''',
                _type_name(signing_private_key)
            ))

        if self._self_signed is not True and self._issuer is None:
            raise ValueError(_pretty_message(
                '''
                Certificate must be self-signed, or an issuer must be specified
                '''
            ))

        if self._self_signed:
            self._issuer = self._subject

        if self._serial_number is None:
            time_part = int_to_bytes(int(time.time()))
            random_part = util.rand_bytes(4)
            self._serial_number = int_from_bytes(time_part + random_part)

        if self._begin_date is None:
            self._begin_date = datetime.now(timezone.utc)

        if self._end_date is None:
            self._end_date = self._begin_date + timedelta(365)

        if not self.ca:
            for ca_only_extension in set(['policy_mappings', 'policy_constraints', 'inhibit_any_policy']):
                if ca_only_extension in self._other_extensions:
                    raise ValueError(_pretty_message(
                        '''
                        Extension %s is only valid for CA certificates
                        ''',
                        ca_only_extension
                    ))

        signature_algo = signing_private_key.algorithm
        if signature_algo == 'ec':
            signature_algo = 'ecdsa'

        signature_algorithm_id = '%s_%s' % (self._hash_algo, signature_algo)

        def _make_extension(name, value):
            return {
                'extn_id': name,
                'critical': self._determine_critical(name),
                'extn_value': value
            }

        extensions = []
        for name in sorted(self._special_extensions):
            value = getattr(self, '_%s' % name)
            if name == 'ocsp_no_check':
                value = core.Null() if value else None
            if value is not None:
                extensions.append(_make_extension(name, value))

        for name in sorted(self._other_extensions.keys()):
            extensions.append(_make_extension(name, self._other_extensions[name]))

        tbs_cert = x509.TbsCertificate({
            'version': 'v3',
            'serial_number': self._serial_number,
            'signature': {
                'algorithm': signature_algorithm_id
            },
            'issuer': self._issuer,
            'validity': {
                'not_before': x509.Time(name='utc_time', value=self._begin_date),
                'not_after': x509.Time(name='utc_time', value=self._end_date),
            },
            'subject': self._subject,
            'subject_public_key_info': self._subject_public_key,
            'extensions': extensions
        })

        if signing_private_key.algorithm == 'rsa':
            sign_func = asymmetric.rsa_pkcs1v15_sign
        elif signing_private_key.algorithm == 'dsa':
            sign_func = asymmetric.dsa_sign
        elif signing_private_key.algorithm == 'ec':
            sign_func = asymmetric.ecdsa_sign

        if not is_oscrypto:
            signing_private_key = asymmetric.load_private_key(signing_private_key)
        signature = sign_func(signing_private_key, tbs_cert.dump(), self._hash_algo)

        return x509.Certificate({
            'tbs_certificate': tbs_cert,
            'signature_algorithm': {
                'algorithm': signature_algorithm_id
            },
            'signature_value': signature
        })


def _pretty_message(string, *params):
    """
    Takes a multi-line string and does the following:

     - dedents
     - converts newlines with text before and after into a single line
     - strips leading and trailing whitespace

    :param string:
        The string to format

    :param *params:
        Params to interpolate into the string

    :return:
        The formatted string
    """

    output = textwrap.dedent(string)

    # Unwrap lines, taking into account bulleted lists, ordered lists and
    # underlines consisting of = signs
    if output.find('\n') != -1:
        output = re.sub('(?<=\\S)\n(?=[^ \n\t\\d\\*\\-=])', ' ', output)

    if params:
        output = output % params

    output = output.strip()

    return output


def _type_name(value):
    """
    :param value:
        A value to get the object name of

    :return:
        A unicode string of the object name
    """

    if inspect.isclass(value):
        cls = value
    else:
        cls = value.__class__
    if cls.__module__ in set(['builtins', '__builtin__']):
        return cls.__name__
    return '%s.%s' % (cls.__module__, cls.__name__)
