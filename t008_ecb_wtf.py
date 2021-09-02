#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Thu Sep  2 14:01:24 2021

@author: mwitas
"""

import os
import requests
from Crypto.Cipher import AES


BLOCK_SIZE = 32
BLOCK_BYTES_SIZE = 16
KEY = b'\x04\x1f\x82\xde\x815\x0b\xfa\x85z\xaa\xbc\x9f\xd3,?'
FLAG = 'crypto{test_flag_abcdef}'.zfill(BLOCK_SIZE)


def decrypt(ciphertext) -> object:
    ciphertext = bytes.fromhex(ciphertext)

    cipher = AES.new(KEY, AES.MODE_ECB)
    try:
        decrypted = cipher.decrypt(ciphertext)
    except ValueError as e:
        return {"error": str(e)}

    return {"plaintext": decrypted.hex()}


def encrypt_flag() -> object:
    iv = os.urandom(16)

    cipher = AES.new(KEY, AES.MODE_CBC, iv)
    encrypted = cipher.encrypt(FLAG.encode())
    ciphertext = iv.hex() + encrypted.hex()

    return {"ciphertext": ciphertext}


def encrypt_remote() -> str:
    return '13a931fe668c461337ae10fabddb975754fc42ae9a10bb5f7d9bf0d470db33234490a9f81d78cbbd2b5bf1ea63089972'


def decrypt_remote(value: bytearray) -> str:
    url = f'http://aes.cryptohack.org/ecbcbcwtf/decrypt/{value.hex()}/'
    r = requests.get(url)
    data = r.json()
    print(f'{r.json()=}')
    return data['plaintext']


def xor(b1: bytearray, b2: bytearray) -> bytearray:
    return bytes(a ^ b for (a, b) in zip(b1, b2))
    

def main(use_local: bool) -> None:
    encrypted = encrypt_flag()['ciphertext'] if use_local else encrypt_remote()
    iv = encrypted[:BLOCK_SIZE]
    ciphertext = encrypted[BLOCK_SIZE:]
    
    print(f'{encrypted=}')
    print(f'{iv=}, {ciphertext=}')
    
    iv_bytes = bytearray.fromhex(iv)
    ciphertext_bytes = bytearray.fromhex(ciphertext)
        
    # decrypted = decrypt(encrypted)['plaintext']
    # print(f'{decrypted=}')
    del encrypted
    
    result = bytearray()
    for i in range(0, len(ciphertext_bytes), BLOCK_BYTES_SIZE):
        block = ciphertext_bytes[i:i+BLOCK_BYTES_SIZE]
        
        decrypted = decrypt(block.hex())['plaintext'] if use_local else decrypt_remote(block)  
        xored = xor(iv_bytes, bytearray.fromhex(decrypted))
        
        result.extend(xored)
        
        iv_bytes = block  
        
    print(result)
    


if __name__ == '__main__':
    main(False)
    
    