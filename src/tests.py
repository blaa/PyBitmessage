#!/usr/bin/env python
# -*- coding: utf-8 -*-
# (C) 2014 by Tomasz bla Fortuna <bla@thera.be>

"""
Test suite for bitmessage functions.

To test with valgrind try to use:
valgrind --tool=memcheck --leak-check=full --suppressions=/usr/lib/valgrind/python.supp python -u tests.py
Compare this run with an empty python interpreter run.
http://stackoverflow.com/questions/20112989/how-to-use-valgrind-with-python
"""

import sys
import unittest

class HighlevelCryptoTestCase(unittest.TestCase):

    def setUp(self):
        pass

    def test_basic(self):
        pass


def suite():
    "Return a suite of all project tests"
    import pyelliptic
    loader = unittest.TestLoader()

    test_elliptic = pyelliptic.tests.suite()

    tests = [
        test_elliptic,
        loader.loadTestsFromTestCase(HighlevelCryptoTestCase)
    ]

    return unittest.TestSuite(tests)



def run_tests():
    if len(sys.argv) == 2 and sys.argv[1] == "calibrate_valgrind":
        return

    all_tests = suite()
    runner = unittest.TextTestRunner(verbosity=2)
    runner.run(all_tests)

if __name__ == "__main__":
    run_tests()
