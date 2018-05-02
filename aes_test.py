#!/usr/bin/env python
# -*- coding:utf-8 -*-
from __future__ import print_function
import os

from cryptography.hazmat.backends import openssl
from cryptography.hazmat.primitives.ciphers import Cipher, modes
from cryptography.hazmat.primitives.ciphers.algorithms import AES
from cryptography.hazmat.primitives.padding import PKCS7


def generate_pseudo_random_bits(n_bits):
    return b'1' * int(n_bits / 8)


import sys


def utf8_from_str(s):
    assert isinstance(s, str)
    if sys.version_info[0] >= 3:  # Python version 3.x
        utf8 = s.encode('utf-8')
    else:
        utf8 = bytes(s)
    return utf8


if "__main__" == __name__:
    from binascii import hexlify

    print('Pseudo random key:')
    key = generate_pseudo_random_bits(128)
    print(hexlify(key).decode())
    iv = os.urandom(16)  # if DEBUG: iv = bytes(bytearray(AES.block_size/8))
    print('Pseudo random IV:')
    print(hexlify(iv).decode())
    #######################################
    plain_test_str = '''Hello world! This is my first secret message. 原始明文字符串汉字按UTF-8编码'''
    plain_text_utf8 = utf8_from_str(plain_test_str)
    print('Plain text:')
    print(plain_text_utf8.decode('utf-8'))
    print('Plain text in hex:')
    print(hexlify(plain_text_utf8).decode())
    padder = PKCS7(AES.block_size).padder()
    padded_data = padder.update(plain_text_utf8) + padder.finalize()
    print('Padded data:')
    print(hexlify(padded_data).decode())
    #######################################
    my_aes128_cipher = Cipher(AES(key), modes.CBC(iv), backend=openssl.backend)
    encryptor = my_aes128_cipher.encryptor()
    ct = encryptor.update(padded_data) + encryptor.finalize()
    print('Encrypted text:')
    print(hexlify(ct).decode())
    #######################################
    decryptor = my_aes128_cipher.decryptor()
    decrypted_data_utf8 = decryptor.update(ct) + decryptor.finalize()
    print('Decrypted data in hex:')
    print(hexlify(decrypted_data_utf8).decode())
    unpadder = PKCS7(AES.block_size).unpadder()
    original_message_utf8 = unpadder.update(decrypted_data_utf8) + unpadder.finalize()
    print('Original message in hex:')
    print(hexlify(original_message_utf8).decode())
    print('Original message:')
    print(original_message_utf8.decode('utf-8'))
