#!/usr/bin/env python
# -*-coding:utf-8 -*-
from __future__ import print_function
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes


def create_raw_data_file(filename):
    with open(filename, mode='wb') as raw_data_file:
        # Hard-coded data will be written into this file
        raw_data_file.write(b'abc')


if "__main__" == __name__:
    from binascii import hexlify
    import os.path

    filename = 'data.raw'
    if not os.path.exists(filename):
        create_raw_data_file(filename)

    # 测试开始
    hash_alg = hashes.SHA256()
    hasher = hashes.Hash(algorithm=hash_alg, backend=default_backend())
    with open(filename, mode='rb') as raw_data_file:
        while True:
            block = raw_data_file.read(hash_alg.block_size)
            # 注释: 只有进行异步 IO 读写时才可能遇到 block 为 None 的情况
            # if not block:
            #     continue
            if len(block) <= 0:
                break
            hasher.update(block)
    raw_digest = hasher.finalize()
    printable_digest_str = hexlify(raw_digest).decode()
    print('SHA256 result:')
    print(printable_digest_str.upper())
