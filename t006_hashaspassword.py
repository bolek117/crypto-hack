import hashlib
import os
from Crypto.Cipher import AES

if __name__ == '__main__':
    with open(os.path.join('assets', 'words.txt'), 'r') as f:
        words = [w.strip() for w in f.readlines()]

    ciphertext = bytes.fromhex('c92b7734070205bdf6c0087a751466ec13ae15e6f1bcdd3f3a535ec0f4bbae66')

    for word in words:
        password_hash = hashlib.md5(word.encode()).hexdigest()
        key = bytes.fromhex(password_hash)

        cipher = AES.new(key, AES.MODE_ECB)
        try:
            hex_decrypted = cipher.decrypt(ciphertext).hex()
            ba = bytearray.fromhex(hex_decrypted).decode()
            print({"plaintext": ba, "word": word})
        except (ValueError, AttributeError) as e:
            # print({"error": str(e)})
            pass
