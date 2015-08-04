# coding: utf-8
from __future__ import unicode_literals, division, absolute_import, print_function

import unittest
import os

import asn1crypto.x509
from oscrypto import asymmetric
from certbuilder import CertificateBuilder


tests_root = os.path.dirname(__file__)
fixtures_dir = os.path.join(tests_root, 'fixtures')



class CertificateBuilderTests(unittest.TestCase):

    def test_build_end_entity_cert(self):
        public_key, private_key = asymmetric.generate_pair('ec', curve='secp256r1')

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
        der_bytes = certificate.dump()

        new_certificate = asn1crypto.x509.Certificate.load(der_bytes)

        self.assertEqual('sha256', new_certificate.hash_algo)
        self.assertEqual('ecdsa', new_certificate.signature_algo)
        self.assertEqual({'key_usage', 'basic_constraints'}, new_certificate.critical_extensions)
        self.assertEqual({'digital_signature', 'key_encipherment'}, new_certificate.key_usage_value.native)
        self.assertEqual(['server_auth', 'client_auth'], new_certificate.extended_key_usage_value.native)
        self.assertEqual(None, new_certificate.authority_key_identifier)
        self.assertEqual(True, new_certificate.ca)
        self.assertEqual(True, new_certificate.self_issued)
        self.assertEqual('yes', new_certificate.self_signed)
        self.assertEqual(certificate.public_key.sha1, new_certificate.key_identifier)

    def test_build_ca_cert(self):
        public_key, private_key = asymmetric.generate_pair('ec', curve='secp256r1')

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
        builder.end_entity = False
        certificate = builder.build(private_key)
        der_bytes = certificate.dump()

        new_certificate = asn1crypto.x509.Certificate.load(der_bytes)

        self.assertEqual('sha512', new_certificate.hash_algo)
        self.assertEqual('ecdsa', new_certificate.signature_algo)
        self.assertEqual({'key_usage', 'basic_constraints'}, new_certificate.critical_extensions)
        self.assertEqual({'key_cert_sign', 'crl_sign'}, new_certificate.key_usage_value.native)
        self.assertEqual(['ocsp_signing'], new_certificate.extended_key_usage_value.native)
        self.assertEqual(None, new_certificate.authority_key_identifier)
        self.assertEqual(True, new_certificate.ca)
        self.assertEqual(True, new_certificate.self_issued)
        self.assertEqual('yes', new_certificate.self_signed)
        self.assertEqual(certificate.public_key.sha1, new_certificate.key_identifier)

    def test_build_chain_of_certs(self):
        ca_public_key, ca_private_key = asymmetric.generate_pair('ec', curve='secp521r1')
        ee_public_key, _ = asymmetric.generate_pair('ec', curve='secp256r1')

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
        ca_builder.end_entity = False
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
        self.assertEqual('ecdsa', new_certificate.signature_algo)
        self.assertEqual({'key_usage'}, new_certificate.critical_extensions)
        self.assertEqual({'digital_signature', 'key_encipherment'}, new_certificate.key_usage_value.native)
        self.assertEqual(['server_auth', 'client_auth'], new_certificate.extended_key_usage_value.native)
        self.assertEqual(ca_certificate.key_identifier, new_certificate.authority_key_identifier)
        self.assertEqual(False, new_certificate.ca)
        self.assertEqual(False, new_certificate.self_issued)
        self.assertEqual('no', new_certificate.self_signed)
