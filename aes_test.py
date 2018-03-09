#!/usr/bin/env python2
# -*-coding:utf-8 -*-
from __future__ import print_function
import os
from cryptography.hazmat.backends import openssl
from cryptography.hazmat.primitives.ciphers import Cipher, modes
from cryptography.hazmat.primitives.ciphers.algorithms import AES
from cryptography.hazmat.primitives.padding import PKCS7


def GeneratePseudoRandomBits128():
    N_BITS = 128
    key = b'1' * (N_BITS / 8)  # if DEBUG: iv = bytes(bytearray(N_BITS / 8))
    return key


if "__main__" == __name__:
    print('Pseudo random key:')
    key = GeneratePseudoRandomBits128()
    print(key.encode('hex'))
    iv = os.urandom(16)  # if DEBUG: iv = bytes(bytearray(AES.block_size/8))
    print('Pseudo random IV:')
    print(iv.encode('hex'))
    #######################################
    plain_text_utf8 = '''Hello world! This is my first secret message. 原始明文字符串汉字按UTF-8编码'''
    print('Plain text:')
    print(plain_text_utf8.decode('utf-8'))
    print('Plain text in hex:')
    print(plain_text_utf8.encode('hex'))
    padder = PKCS7(AES.block_size).padder()
    padded_data = padder.update(plain_text_utf8) + padder.finalize()
    print('Padded data:')
    print(padded_data.encode('hex'))
    #######################################
    my_aes128_cipher = Cipher(AES(key), modes.CBC(iv), backend=openssl.backend)
    encryptor = my_aes128_cipher.encryptor()
    ct = encryptor.update(padded_data) + encryptor.finalize()
    print('Encrypted text:')
    print(ct.encode('hex'))
    #######################################
    decryptor = my_aes128_cipher.decryptor()
    decrypted_data_utf8 = decryptor.update(ct) + decryptor.finalize()
    print('Decrypted data in hex:')
    print(decrypted_data_utf8.encode('hex'))
    unpadder = PKCS7(AES.block_size).unpadder()
    original_message_utf8 = unpadder.update(decrypted_data_utf8) + unpadder.finalize()
    print('Original message in hex:')
    print(original_message_utf8.encode('hex'))
    print('Original message:')
    print(original_message_utf8.decode('utf-8'))
