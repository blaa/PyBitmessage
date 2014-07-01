# -*- coding: utf-8 -*-
# (C) 2014 by Tomasz bla Fortuna <bla@thera.be>
import unittest

import pyelliptic
from pyelliptic.openssl import OpenSSL

"""
Test suite for low-level cryptography functions.

App uses secp256k1 with aes-256-cbc for encryption, focus on those sets.
"""

default_ciphername = 'aes-256-cbc'
default_curve = 'secp256k1'

def from_hex(s):
    out = []
    for i in range(0, len(s), 2):
        pair = s[i:i+2]
        out.append(chr(int(pair, 16)))
    return "".join(out)

def to_hex(s):
    out = []
    for ch in s:
        out.append("%02x" % ord(ch))
    return "".join(out)

class OpenSSLTestCase(unittest.TestCase):
    "OpenSSL module testcases"

    def test_rand(self):
        "Test basic random number generator correctness"
        # There's no way to check if this really is random (it's an
        # algorithmic prng). Still, check for common mistakes.

        data1 = OpenSSL.rand(10)
        data2 = OpenSSL.rand(10)
        self.assertNotEqual(data1, data2)

        blob = OpenSSL.rand(64000)
        stat_zero = [0] * 8
        stat_one = [0] * 8

        for byte in blob:
            byte = ord(byte)
            for i in range(8):
                bit = byte % 2
                byte = byte >> 1
                if bit:
                    stat_one[i] += 1
                else:
                    stat_zero[i] += 1

        for i in range(8):
            diff = float(abs(stat_zero[i] - stat_one[i]))
            # Probabilistic test can sometimes fail, but it should be VERY rare.
            # Result is usually < 500, 0.04 sets limit at a value 1280
            self.assertTrue(diff / stat_zero[i] < 0.04 * stat_zero[i])



class SymmetricTestCase(unittest.TestCase):
    "Testcases for pyelliptic symmetric encryption functions"

    def setUp(self):
        pass

    def test_basic(self):
        "Basic API tests"
        self.assertEqual(pyelliptic.Cipher.get_blocksize('aes-256-cbc'), 16)
        self.assertEqual(pyelliptic.Cipher.get_blocksize('aes-128-cbc'), 16)
        self.assertEqual(pyelliptic.Cipher.get_keysize('aes-256-cbc'), 32)
        self.assertEqual(pyelliptic.Cipher.get_keysize('aes-128-cbc'), 16)

    def _encdec(self, ciphername, msg=None, key=None, iv=None):
        "Helper: Encrypt, then decrypt random message"
        block_size = pyelliptic.Cipher.get_blocksize(ciphername)
        key_size = pyelliptic.Cipher.get_keysize(ciphername)

        # Generate IV, key and random message
        if key is None:
            key = OpenSSL.rand(key_size)
        if iv is None:
            iv = pyelliptic.Cipher.gen_IV(ciphername)
        if msg is None:
            msg = OpenSSL.rand(block_size)

        self.assertEqual(len(iv), block_size)
        self.assertEqual(len(key), key_size)
        self.assertEqual(len(msg), block_size)

        # Create ciphers
        enc_ctx = pyelliptic.Cipher(key=key, iv=iv,
                                    do=pyelliptic.Cipher.ENCRYPT,
                                    ciphername=ciphername,
                                    padding=False)

        dec_ctx = pyelliptic.Cipher(key, iv,
                                    pyelliptic.Cipher.DECRYPT,
                                    ciphername=ciphername,
                                    padding=False)


        # Encrypt with a bit mangled case.
        ciphertext = enc_ctx.update(msg[:10])
        ciphertext += enc_ctx.update('')
        ciphertext += enc_ctx.update(msg[10:])
        ciphertext += enc_ctx.update('')
        ciphertext += enc_ctx.final()

        self.assertEqual(len(msg), block_size)
        self.assertEqual(len(ciphertext), block_size)

        # Result must be of length n*blocksize
        self.assertEqual(len(ciphertext) % block_size, 0, msg="ciphertext has invalid length")
        self.assertEqual(len(ciphertext), len(msg),
                         msg="ciphertext length does not equal msg length and no padding is enabled")


        # Decrypt
        cleartext = dec_ctx.ciphering(ciphertext)

        self.assertEqual(msg, cleartext)
        self.assertNotEqual(msg, ciphertext)
        return msg, ciphertext

    def test_cipher_encdec(self):
        "Test symmetric encryption with pyelliptic/Cipher"

        test_ciphers = [
            'aes-128-cbc',
            'aes-256-cbc',
            'aes-128-cfb',
            'aes-256-cfb',
            'aes-128-ofb',
            'aes-256-ofb',
            'bf-cfb',
            'bf-cbc',
            'rc4',
        ]

        # Test all ciphers in table
        for ciphername in test_ciphers:
            self._encdec(ciphername)


        msg1, ciphertext1 = self._encdec(default_ciphername,
                                         msg='\x01' * 16,
                                         key='\x01' * 32,
                                         iv='\x01' * 16)

        msg2, ciphertext2 = self._encdec(default_ciphername,
                                         msg='\x01' * 16,
                                         key='\x01' * 32,
                                         iv='\x01' * 15 + '\x00')

        msg3, ciphertext3 = self._encdec(default_ciphername,
                                         msg='\x01' * 16,
                                         key='\x01' * 31 + '\x00',
                                         iv='\x01' * 15 + '\x00')

        # Different IV -> different ciphertext
        self.assertNotEqual(ciphertext1, ciphertext2)
        # Different IV/key -> different ciphertext
        self.assertNotEqual(ciphertext1, ciphertext3)
        # Different key -> different ciphertext
        self.assertNotEqual(ciphertext2, ciphertext3)


    def test_aes_vectors(self):
        """Test symmetric encryption with official vectors

        Vectors are defined in 800-38A NIST publication. Taken from here:
        http://www.inconteam.com/software-development/41-encryption/55-aes-test-vectors
        """
        key = from_hex('603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4')

        aes_256_cbc_vectors = [
            # IV, Plaintext, Ciphertext
            ('000102030405060708090A0B0C0D0E0F','6bc1bee22e409f96e93d7e117393172a', 'f58c4c04d6e5f1ba779eabfb5f7bfbd6'),
            ('F58C4C04D6E5F1BA779EABFB5F7BFBD6','ae2d8a571e03ac9c9eb76fac45af8e51',	'9cfc4e967edb808d679f777bc6702c7d'),
            ('9CFC4E967EDB808D679F777BC6702C7D','30c81c46a35ce411e5fbc1191a0a52ef',	'39f23369a9d9bacfa530e26304231461'),
            ('39F23369A9D9BACFA530E26304231461','f69f2445df4f9b17ad2b417be66c3710',	'b2eb05e2c39be9fcda6c19078c6a9d1b'),
        ]

        for test_iv, test_plaintext, test_ciphertext in aes_256_cbc_vectors:
            # Convert
            test_iv, test_plaintext  = from_hex(test_iv), from_hex(test_plaintext)
            test_ciphertext = from_hex(test_ciphertext)

            out_msg, out_ciphertext = self._encdec(default_ciphername, msg=test_plaintext,
                                                   iv=test_iv, key=key)

            self.assertEqual(out_ciphertext, test_ciphertext,
                             msg="Symmetric cipher comparison with a test vector failed")

    def test_padding(self):
        "Test PKCS padding"
        # TODO
        pass

def suite():
    "Return suite of all module tests"
    loader = unittest.TestLoader()
    tests = [
        loader.loadTestsFromTestCase(OpenSSLTestCase),
        loader.loadTestsFromTestCase(SymmetricTestCase),
    ]

    return unittest.TestSuite(tests)
