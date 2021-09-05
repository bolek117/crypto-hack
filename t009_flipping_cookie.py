#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Thu Sep  2 19:10:13 2021

@author: mwitas
"""

from Crypto.Cipher import AES
import os
import requests
from Crypto.Util.Padding import pad, unpad
from datetime import datetime, timedelta

BLOCK_SIZE = 32
BLOCK_BYTES_SIZE = 16
KEY = b'\x04\x1f\x82\xde\x815\x0b\xfa\x85z\xaa\xbc\x9f\xd3,?'
FLAG = 'crypto{test_flag_abcdef}'.zfill(BLOCK_SIZE)

IV = bytearray.fromhex('6196154567d4659db9e1a6f81f8bbaa5')


# @chal.route('/flipping_cookie/check_admin/<cookie>/<iv>/')
def check_admin(cookie, iv, use_local: bool):
    if use_local:
        cookie = bytes.fromhex(cookie)
        iv = bytes.fromhex(iv)
    
        try:
            cipher = AES.new(KEY, AES.MODE_CBC, iv)
            decrypted = cipher.decrypt(cookie)
            unpadded = unpad(decrypted, 16)
        except ValueError as e:
            return {"error": str(e)}
    
        if b"admin=True" in unpadded.split(b";"):
            return {"flag": FLAG}
        else:
            return {"error": "Only admin can read the flag"}
    else:
      url = f'http://aes.cryptohack.org/flipping_cookie/check_admin/{cookie}/{iv}/'
      r = requests.get(url)
      return r.json()
      

# @chal.route('/flipping_cookie/get_cookie/')
def get_cookie(use_local: bool) -> str:
    if use_local:
        # cookie = "admin=False;expiry=1630690233".encode()
        # iv = IV
        # padded = b'admin=False;expiry=1630690233\x03\x03\x03'
        # encrypted = bytearray.fromhex('ca3596d87c8658d9843e9b419ad0711673acf39e1e173cecdba9b2c8df3acbe5')
        ciphertext = '6196154567d4659db9e1a6f81f8bbaa5ca3596d87c8658d9843e9b419ad0711673acf39e1e173cecdba9b2c8df3acbe5'
    else:
        ciphertext = 'd66a593ee22c40976b8bcdffe4145e85253dc1a78ac136e448baf42dc244b291c81737c2e2b5918514ea4943d985f19c'
        
    return ciphertext


def xor(b1: bytearray, b2: bytearray) -> bytearray:
    return bytes(a ^ b for (a, b) in zip(b1, b2))


def encrypt(text: str) -> bytearray:
    iv = bytes(IV)
    padded = pad(text.encode(), BLOCK_BYTES_SIZE)
    cipher = AES.new(KEY, AES.MODE_CBC, iv)
    encrypted = cipher.encrypt(padded)
    ciphertext = iv.hex() + encrypted.hex()
    return bytearray.fromhex(ciphertext)


def main(use_local: bool) -> None:
    actual_cookie = 'admin=False;expiry=1630690233'
    cookie_blocks = [actual_cookie[i:i+16] for i in range(0, len(actual_cookie), BLOCK_BYTES_SIZE)]
    # cookie_blocks: ['admin=False;expi', 'ry=1630690233\x03\x03\x03']
    
    ciphertext = get_cookie(use_local)
    iv = ciphertext[:BLOCK_SIZE]
    data = ciphertext[BLOCK_SIZE:]
    blocks = [data[i:i+BLOCK_SIZE] for i in range(0, len(data), BLOCK_SIZE)]
    
    wanted_text = {
        'start': len('admin='.encode().hex()),
        'end': len(';expi'.encode().hex())
    }
    modified_block = blocks[0]
    modified_block_parts = [
        modified_block[:wanted_text['start']],
        modified_block[wanted_text['start']:-wanted_text['end']],
        modified_block[-wanted_text['end']:]
    ]
    
    iv_parts = [
        iv[:wanted_text['start']],
        iv[wanted_text['start']:-wanted_text['end']],
        iv[-wanted_text['end']:]
    ]
    
    to_modify = modified_block_parts[1]
    splitted = [to_modify[i:i+2] for i in range(0, len(to_modify), 2)]
    
    new_xor = xor(bytearray.fromhex(iv_parts[1]), b'False')
    new_xor = xor(new_xor, b'True;')
    new_xor = new_xor.hex()
        
    iv_parts[1] = new_xor
    
    reconstructed = blocks[0] + blocks[1]
    reconstructed_iv = ''.join(iv_parts)
    encrypted_block = check_admin(reconstructed, reconstructed_iv, use_local)
    
    print(encrypted_block)
    pass



if __name__ == '__main__':
    main(False)