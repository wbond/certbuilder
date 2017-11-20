# coding: utf-8
from __future__ import unicode_literals, division, absolute_import, print_function

from datetime import datetime
import unittest
import os

import asn1crypto.x509
from asn1crypto.util import timezone
from oscrypto import asymmetric
from certbuilder import CertificateBuilder


tests_root = os.path.dirname(__file__)
fixtures_dir = os.path.join(tests_root, 'fixtures')


class lazy_class_property(object):  # noqa
    """
    Used for caching lazily generated key pairs.
    """

    def __init__(self, getter):
        self.getter = getter

    def __get__(self, instance, owner):
        value = self.getter(owner)
        setattr(owner, self.getter.__name__, value)

        return value


class CertificateBuilderTests(unittest.TestCase):
    def test_subject_alt_name_shortcuts(self):
        public_key, private_key = self.ec_secp256r1

        builder = CertificateBuilder(
            {'country_name': 'US', 'common_name': 'Test'},
            public_key
        )
        builder.self_signed = True

        self.assertEqual(builder.subject_alt_domains, [])

        builder.subject_alt_domains = ['example.com', 'example.org']
        builder.subject_alt_emails = ['test@example.com', 'test2@example.com']
        builder.subject_alt_ips = ['127.0.0.1']
        builder.subject_alt_uris = ['http://example.com', 'https://bücher.ch']

        self.assertEqual(builder.subject_alt_domains, ['example.com', 'example.org'])
        self.assertEqual(builder.subject_alt_emails, ['test@example.com', 'test2@example.com'])
        self.assertEqual(builder.subject_alt_ips, ['127.0.0.1'])
        self.assertEqual(builder.subject_alt_uris, ['http://example.com', 'https://bücher.ch'])

        builder.subject_alt_domains = []
        self.assertEqual(builder.subject_alt_domains, [])

        builder.subject_alt_emails = []
        self.assertEqual(builder.subject_alt_emails, [])

        builder.subject_alt_ips = []
        self.assertEqual(builder.subject_alt_ips, [])

        builder.subject_alt_uris = []
        self.assertEqual(builder.subject_alt_uris, [])

        builder.subject_alt_uris = ['https://bücher.ch']

        certificate = builder.build(private_key)

        self.assertEqual(b'\x86\x18https://xn--bcher-kva.ch', certificate.subject_alt_name_value[0].contents)

    def test_build_end_entity_cert(self):
        public_key, private_key = self.ec_secp256r1

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
        builder.subject_alt_domains = ['example.com']
        certificate = builder.build(private_key)
        der_bytes = certificate.dump()

        new_certificate = asn1crypto.x509.Certificate.load(der_bytes)

        self.assertEqual('sha256', new_certificate.hash_algo)
        self.assertEqual(
            {
                'country_name': 'US',
                'state_or_province_name': 'Massachusetts',
                'locality_name': 'Newbury',
                'organization_name': 'Codex Non Sufficit LC',
                'common_name': 'Will Bond',
            },
            new_certificate.issuer.native
        )
        self.assertEqual(
            {
                'country_name': 'US',
                'state_or_province_name': 'Massachusetts',
                'locality_name': 'Newbury',
                'organization_name': 'Codex Non Sufficit LC',
                'common_name': 'Will Bond',
            },
            new_certificate.subject.native
        )
        self.assertEqual('ecdsa', new_certificate.signature_algo)
        self.assertEqual(set(['key_usage']), new_certificate.critical_extensions)
        self.assertEqual(set(['digital_signature', 'key_encipherment']), new_certificate.key_usage_value.native)
        self.assertEqual(['server_auth', 'client_auth'], new_certificate.extended_key_usage_value.native)
        self.assertEqual(None, new_certificate.authority_key_identifier)
        self.assertEqual(False, new_certificate.ca)
        self.assertEqual(True, new_certificate.self_issued)
        self.assertEqual('maybe', new_certificate.self_signed)
        self.assertEqual(certificate.public_key.sha1, new_certificate.key_identifier)
        self.assertEqual(['example.com'], new_certificate.valid_domains)

    def test_build_ca_cert(self):
        public_key, private_key = self.ec_secp256r1

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
        builder.hash_algo = 'sha512'
        builder.self_signed = True
        builder.ca = True
        certificate = builder.build(private_key)
        der_bytes = certificate.dump()

        new_certificate = asn1crypto.x509.Certificate.load(der_bytes)

        self.assertEqual('sha512', new_certificate.hash_algo)
        self.assertEqual(
            {
                'country_name': 'US',
                'state_or_province_name': 'Massachusetts',
                'locality_name': 'Newbury',
                'organization_name': 'Codex Non Sufficit LC',
                'common_name': 'Will Bond',
            },
            new_certificate.issuer.native
        )
        self.assertEqual(
            {
                'country_name': 'US',
                'state_or_province_name': 'Massachusetts',
                'locality_name': 'Newbury',
                'organization_name': 'Codex Non Sufficit LC',
                'common_name': 'Will Bond',
            },
            new_certificate.subject.native
        )
        self.assertEqual('ecdsa', new_certificate.signature_algo)
        self.assertEqual(set(['key_usage', 'basic_constraints']), new_certificate.critical_extensions)
        self.assertEqual(set(['key_cert_sign', 'crl_sign']), new_certificate.key_usage_value.native)
        self.assertEqual(None, new_certificate.extended_key_usage_value)
        self.assertEqual(None, new_certificate.authority_key_identifier)
        self.assertEqual(True, new_certificate.ca)
        self.assertEqual(True, new_certificate.self_issued)
        self.assertEqual('maybe', new_certificate.self_signed)
        self.assertEqual(certificate.public_key.sha1, new_certificate.key_identifier)

    def test_build_chain_of_certs(self):
        ca_public_key, ca_private_key = self.ec_secp521r1
        ee_public_key, _ = self.ec_secp256r1

        ca_builder = CertificateBuilder(
            {
                'country_name': 'US',
                'state_or_province_name': 'Massachusetts',
                'locality_name': 'Newbury',
                'organization_name': 'Codex Non Sufficit LC',
                'common_name': 'Codex Non Sufficit LC - Primary CA',
            },
            ca_public_key
        )
        ca_builder.hash_algo = 'sha512'
        ca_builder.self_signed = True
        ca_builder.ca = True
        ca_certificate = ca_builder.build(ca_private_key)

        ee_builder = CertificateBuilder(
            {
                'country_name': 'US',
                'state_or_province_name': 'Massachusetts',
                'locality_name': 'Newbury',
                'organization_name': 'Codex Non Sufficit LC',
                'common_name': 'Will Bond',
            },
            ee_public_key
        )
        ee_builder.issuer = ca_certificate
        ee_builder.serial_number = 1
        ee_certificate = ee_builder.build(ca_private_key)
        der_bytes = ee_certificate.dump()

        new_certificate = asn1crypto.x509.Certificate.load(der_bytes)

        self.assertEqual('sha256', new_certificate.hash_algo)
        self.assertEqual(
            {
                'country_name': 'US',
                'state_or_province_name': 'Massachusetts',
                'locality_name': 'Newbury',
                'organization_name': 'Codex Non Sufficit LC',
                'common_name': 'Codex Non Sufficit LC - Primary CA',
            },
            new_certificate.issuer.native
        )
        self.assertEqual(
            {
                'country_name': 'US',
                'state_or_province_name': 'Massachusetts',
                'locality_name': 'Newbury',
                'organization_name': 'Codex Non Sufficit LC',
                'common_name': 'Will Bond',
            },
            new_certificate.subject.native
        )
        self.assertEqual('ecdsa', new_certificate.signature_algo)
        self.assertEqual(set(['key_usage']), new_certificate.critical_extensions)
        self.assertEqual(set(['digital_signature', 'key_encipherment']), new_certificate.key_usage_value.native)
        self.assertEqual(['server_auth', 'client_auth'], new_certificate.extended_key_usage_value.native)
        self.assertEqual(ca_certificate.key_identifier, new_certificate.authority_key_identifier)
        self.assertEqual(False, new_certificate.ca)
        self.assertEqual(False, new_certificate.self_issued)
        self.assertEqual('no', new_certificate.self_signed)

    def test_validity_utc_times(self):
        public_key, private_key = self.ec_secp256r1

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
        builder.begin_date = datetime(2045, 1, 1, tzinfo=timezone.utc)
        builder.end_date = datetime(2049, 12, 31, tzinfo=timezone.utc)
        certificate = builder.build(private_key)
        der_bytes = certificate.dump()

        new_certificate = asn1crypto.x509.Certificate.load(der_bytes)

        self.assertEqual(new_certificate['tbs_certificate']['validity']['not_before'].name, 'utc_time')
        self.assertEqual(new_certificate['tbs_certificate']['validity']['not_after'].name, 'utc_time')

    def test_validity_general_times(self):
        public_key, private_key = self.ec_secp256r1

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
        builder.begin_date = datetime(2050, 1, 1, tzinfo=timezone.utc)
        builder.end_date = datetime(2052, 1, 1, tzinfo=timezone.utc)
        certificate = builder.build(private_key)
        der_bytes = certificate.dump()

        new_certificate = asn1crypto.x509.Certificate.load(der_bytes)

        self.assertEqual(new_certificate['tbs_certificate']['validity']['not_before'].name, 'general_time')
        self.assertEqual(new_certificate['tbs_certificate']['validity']['not_after'].name, 'general_time')

    # Cached key pairs
    @lazy_class_property
    def ec_secp256r1(self):
        return asymmetric.generate_pair('ec', curve='secp256r1')

    @lazy_class_property
    def ec_secp521r1(self):
        return asymmetric.generate_pair('ec', curve='secp521r1')
