#!/usr/bin/env python
# -*- coding: utf-8 -*-

#  Copyright (C) 2011 Yann GUIBET <yannguibet@gmail.com>
#  See LICENSE for details.

from pyelliptic.openssl import OpenSSL


class Cipher:
    """
    Symmetric encryption

        import pyelliptic
        iv = pyelliptic.Cipher.gen_IV('aes-256-cfb')
        ctx = pyelliptic.Cipher("secretkey", iv, 1, ciphername='aes-256-cfb')
        ciphertext = ctx.update('test1')
        ciphertext += ctx.update('test2')
        ciphertext += ctx.final()

        ctx2 = pyelliptic.Cipher("secretkey", iv, 0, ciphername='aes-256-cfb')
        print ctx2.ciphering(ciphertext)
    """

    ENCRYPT = 1
    DECRYPT = 0

    def __init__(self, key, iv, do, ciphername='aes-256-cbc', padding=True):
        """
        do == 1 => Encrypt; do == 0 => Decrypt
        """
        assert do in [self.ENCRYPT, self.DECRYPT], "Argument 'do' out of scope"
        self.cipher = OpenSSL.get_cipher(ciphername)
        self.ctx = OpenSSL.EVP_CIPHER_CTX_new()

        keysize = self.cipher.get_keysize()
        assert keysize is None or len(key) == keysize
        assert len(iv) == self.cipher.get_blocksize()

        k = OpenSSL.malloc(key, len(key))
        IV = OpenSSL.malloc(iv, len(iv))
        OpenSSL.EVP_CipherInit_ex(
            self.ctx, self.cipher.get_pointer(), 0, k, IV, do)

        if padding is False:
            # By default PKCS padding is enabled. This case disables it.
            OpenSSL.EVP_CIPHER_CTX_set_padding(self.ctx, 0)


    @staticmethod
    def get_all_cipher():
        """
        static method, returns all ciphers available
        """
        return OpenSSL.cipher_algo.keys()

    @staticmethod
    def get_blocksize(ciphername):
        cipher = OpenSSL.get_cipher(ciphername)
        return cipher.get_blocksize()

    @staticmethod
    def get_keysize(ciphername):
        cipher = OpenSSL.get_cipher(ciphername)
        return cipher.get_keysize()

    @staticmethod
    def gen_IV(ciphername):
        cipher = OpenSSL.get_cipher(ciphername)
        return OpenSSL.rand(cipher.get_blocksize())

    def update(self, input):
        i = OpenSSL.c_int(0)
        buffer = OpenSSL.malloc(b"", len(input) + self.cipher.get_blocksize())
        inp = OpenSSL.malloc(input, len(input))
        if inp is None or buffer is None:
            raise Exception("Not enough memory")

        ret = OpenSSL.EVP_CipherUpdate(self.ctx, OpenSSL.byref(buffer),
                                       OpenSSL.byref(i), inp, len(input))
        if ret == 0:
            raise Exception("[OpenSSL] EVP_CipherUpdate FAIL: " + str(ret))
        return buffer.raw[0:i.value]

    def final(self):
        i = OpenSSL.c_int(0)
        buffer = OpenSSL.malloc(b"", self.cipher.get_blocksize())
        ret = OpenSSL.EVP_CipherFinal_ex(self.ctx, OpenSSL.byref(buffer), OpenSSL.byref(i))
        if ret == 0:
            raise Exception("[OpenSSL] EVP_CipherFinal_ex FAIL: " + str(ret))
        return buffer.raw[0:i.value]

    def ciphering(self, input):
        """
        Do update and final in one method
        """
        buff = self.update(input)
        return buff + self.final()

    def __del__(self):
        OpenSSL.EVP_CIPHER_CTX_cleanup(self.ctx)
        OpenSSL.EVP_CIPHER_CTX_free(self.ctx)
