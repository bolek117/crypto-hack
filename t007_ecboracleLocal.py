#!/usr/bin/env python3.8
import string
import time
import requests

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad

KEY = b'\xc3,\\\xa6\xb5\x80^\x0c\xdb\x8d\xa5z*\xb6\xfe\\'
FLAG = 'crypto{test_flag_abcdef}'
BLOCK_LEN = 32


class Ciphertext:
    RESERVED_BLOCKS: int = 3

    def __init__(self, ciphertext: str, known_text: str, text_to_be_encrypted: str):
        self.text_to_be_encrypted = text_to_be_encrypted
        self.ciphertext = ciphertext
        self.known_text = known_text

        self.blocks = [ciphertext[i:i + BLOCK_LEN] for i in range(0, len(ciphertext), BLOCK_LEN)]
        self.prefix_block = self.blocks[0]
        self.identical_blocks = [block == self.prefix_block for block in self.blocks]

    def checked_block(self, offset: int = 0) -> str:
        return self.blocks[Ciphertext.RESERVED_BLOCKS - 1 + offset]

    @staticmethod
    def from_plaintext(known_text: str, for_reference_block: bool, using_local: bool) -> 'Ciphertext':
        ciphertext, text_to_be_encrypted = Ciphertext._encrypt_with_prefix(known_text, for_reference_block, using_local)
        return Ciphertext(ciphertext, known_text, text_to_be_encrypted)

    @staticmethod
    def _encrypt_with_prefix(known_text: str, for_reference_block: bool, using_local: bool) -> (str, str):
        expected_prefix_length = Ciphertext.RESERVED_BLOCKS * BLOCK_LEN - (len(known_text) + 2)
        if not for_reference_block:
            expected_prefix_length += 2

        prefix = generate_prefix(expected_prefix_length)
        plaintext = prefix if for_reference_block else prefix + known_text

        result = encrypt(plaintext) if using_local else encrypt_remote(plaintext)
        return result, plaintext

    def __str__(self):
        return f'{self.blocks}'

    def __repr__(self):
        return self.__str__()


def generate_prefix(length: int) -> str:
    return '41' * int(length / 2)


def encrypt_remote(plaintext: str) -> str:
    url = f'http://aes.cryptohack.org/ecb_oracle/encrypt'
    s_url = f'{url}/{plaintext}/'
    r = requests.get(s_url)
    return r.json()['ciphertext']


def encrypt(plaintext) -> str:
    plaintext = bytes.fromhex(plaintext)

    padded = pad(plaintext + FLAG.encode(), 16)
    cipher = AES.new(KEY, AES.MODE_ECB)
    try:
        encrypted = cipher.encrypt(padded)
    except ValueError as e:
        raise
        # return {"error": str(e)}

    return encrypted.hex()


def iterate_character(found_characters: bytearray, using_local: bool):
    known_text = found_characters.hex()

    ciphertext = Ciphertext.from_plaintext(known_text, True, using_local)
    reference_block = ciphertext.checked_block()

    found_character = bruteforce_character(known_text, reference_block, using_local)
    return found_character


def bruteforce_character(known_text: str, reference_block: str, using_local: bool) -> str:
    for i in string.printable:
        c = hex(ord(i))[2:].zfill(2)
        # print(c)

        checked_text = known_text + c
        ciphertext = Ciphertext.from_plaintext(checked_text, False, using_local)

        checked_block = ciphertext.checked_block()
        if checked_block == reference_block:
            if using_local:
                time.sleep(0.25)
            return c
        else:
            # print(f'{checked_block=} != {reference_block}')
            pass

    return ''


def main(using_local: bool):
    prefix_length = Ciphertext.RESERVED_BLOCKS * BLOCK_LEN
    print(f'{prefix_length=}')

    base_ciphertext = Ciphertext.from_plaintext('', False, using_local)
    print(f'{base_ciphertext.prefix_block=}')

    found_characters = bytearray()

    max_iterations = int(prefix_length / 2)
    for i in range(max_iterations):
        found_character = iterate_character(found_characters, using_local)
        if found_character == '':
            break

        found_characters.extend(bytearray.fromhex(found_character))
        print(f'Found character: {found_character}, flag: {found_characters.decode()}')

    print(f'Flag: {found_characters.decode()}')
    return


if __name__ == '__main__':
    main(using_local=False)
