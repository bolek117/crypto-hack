#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Sat Sep  4 15:57:41 2021

@author: mwitas
"""

import requests
from Crypto.Cipher import AES
from typing import List

BLOCK_SIZE_BYTES = 16
BLOCK_SIZE_STRING = 16
BLOCK_SIZE_HEXSTRING = 32

KEY = b'AAAAAAAAAAAAAAAA'
FLAG = 'crypto{test_flag_123456}'.zfill(2 * BLOCK_SIZE_STRING)


class HexString:
    def __init__(self, data: bytes):
        self.data: bytes = data
        self.plaintext: str = data.decode('utf-8', errors='ignore')
        self.hextext: str = data.hex()

    @staticmethod
    def from_plaintext(plaintext: str) -> 'HexString':
        data = plaintext.encode('utf-8')
        return HexString(data)

    @staticmethod
    def from_hextext(hextext: str) -> 'HexString':
        data = bytearray.fromhex(hextext)
        return HexString(data)

    def blocks(self) -> List['HexString']:
        d = self.data
        return [HexString(d[i:i+BLOCK_SIZE_BYTES]) for i in range(0, len(d), BLOCK_SIZE_BYTES)]

    def __str__(self):
        return f'{self.hextext}'

    def __repr__(self):
        return self.__str__()


# @chal.route('/lazy_cbc/encrypt/<plaintext>/')
def encrypt(hex_plaintext: str, use_local: bool) -> object:
    if not use_local:
        url = f'http://aes.cryptohack.org/lazy_cbc/encrypt/{hex_plaintext}/'
        r = requests.get(url)
        return r.json()

    data = bytes.fromhex(hex_plaintext)
    if len(data) % 16 != 0:
        return {"error": f"Data length must be multiple of 16 (is {len(data)}"}

    cipher = AES.new(KEY, AES.MODE_CBC, KEY)
    encrypted = cipher.encrypt(data)

    return {"ciphertext": encrypted.hex()}


# @chal.route('/lazy_cbc/receive/<ciphertext>/')
def receive(hex_ciphertext: str, use_local: bool) -> object:
    if not use_local:
        url = f'http://aes.cryptohack.org/lazy_cbc/receive/{hex_ciphertext}/'
        r = requests.get(url)
        return r.json()

    ciphertext = bytes.fromhex(hex_ciphertext)
    if len(ciphertext) % 16 != 0:
        return {"error": "Data length must be multiple of 16"}

    cipher = AES.new(KEY, AES.MODE_CBC, KEY)
    decrypted = cipher.decrypt(ciphertext)

    try:
        decrypted.decode()  # ensure plaintext is valid ascii
    except UnicodeDecodeError:
        return {"error": "Invalid plaintext: " + decrypted.hex()}

    return {"success": "Your message has been received"}


# @chal.route('/lazy_cbc/get_flag/<key>/')
def get_flag(hex_key: str, use_local: bool):
    if not use_local:
        url = f'http://aes.cryptohack.org/lazy_cbc/get_flag/{hex_key}/'
        r = requests.get(url)
        return r.json()

    key = bytes.fromhex(hex_key)

    if key == KEY:
        return {"plaintext": FLAG.encode().hex()}
    else:
        return {"error": "invalid key"}


def xor(b1: bytes, b2: bytes) -> bytes:
    return bytes(a ^ b for (a, b) in zip(b1, b2))


def header(s: str) -> None:
    max_len = 128
    print('\n' + '-' * min(len(s), max_len))
    print(s)
    print('-' * min(len(s), max_len))


def main(use_local: bool):
    plaintext = 'FF' * BLOCK_SIZE_BYTES * 2
    plaintext = HexString.from_hextext(plaintext)
    plaintext_blocks = plaintext.blocks()
    p1, p2 = plaintext_blocks

    header(
        f'Execute `encrypt({plaintext.hextext[:2]}...{plaintext.hextext[-2:]})` to get C1 and C2')
    encrypted = encrypt(plaintext.hextext, use_local)
    encrypted = encrypted['ciphertext']
    encrypted = HexString.from_hextext(encrypted)
    blocks = encrypted.blocks()
    print(f'{encrypted=}')

    c1, c2 = blocks
    print(f'{c1=}\n{c2=}')

    header('Swap blocks order')
    c11 = c2
    c12 = c1
    print(f'c11 <- {c2=}\nc12 <- {c1=}')
    
    header(f'Execute `decrypt({c11.hextext[:2]}...{c12.hextext[-2:]})` to get P12')
    swaped = HexString.from_hextext(c11.hextext + c12.hextext)
    decrypted_swap = receive(swaped.hextext, use_local)

    if 'error' not in decrypted_swap:
        raise Exception('Unable to retrieve decrypted content')

    decrypted_hex = decrypted_swap['error'][len('Invalid plaintext: '):]
    decrypted = HexString.from_hextext(decrypted_hex)
    decrypted_blocks = decrypted.blocks()
    print(f'{decrypted=}')

    p11, p12 = decrypted_blocks
    print(f'{p11=}\n{p12=}')

    header('XOR C2 with P12 to get D12')
    print(f'{c2=} XOR {p12=} =')
    
    d12 = xor(c2.data, p12.data)
    d12 = HexString(d12)
    print(f'{d12=}')

    header('Replace D1 with content of D12')
    d1 = d12
    print(f'd1 <- {d12=}')

    header('XOR D1 with P1 to get IV')
    print(f'{d1=} XOR {p1=} = ')
    
    iv = xor(d12.data, p1.data)
    iv = HexString(iv)
    print(f'{iv=}')

    header('Get flag from server')
    flag = get_flag(iv.hextext, use_local)
    flag = HexString.from_hextext(
        flag['plaintext']).plaintext if 'plaintext' in flag else flag
    print(f'{flag=}')


if __name__ == '__main__':
    main(use_local=True)
