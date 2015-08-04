# coding: utf-8
from __future__ import unicode_literals, division, absolute_import, print_function

import unittest
import re

from tests.test_certificate_builder import CertificateBuilderTests


test_classes = [CertificateBuilderTests]


def run(matcher=None):
    suite = unittest.TestSuite()
    loader = unittest.TestLoader()
    for test_class in test_classes:
        if matcher:
            names = loader.getTestCaseNames(test_class)
            for name in names:
                if re.search(matcher, name):
                    suite.addTest(test_class(name))
        else:
            suite.addTest(loader.loadTestsFromTestCase(test_class))
    verbosity = 2 if matcher else 1
    unittest.TextTestRunner(verbosity=verbosity).run(suite)
