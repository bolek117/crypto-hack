'''curl 'http://aes.cryptohack.org/passwords_as_keys/decrypt/c92b7734070205bdf6c0087a751466ec13ae15e6f1bcdd3f3a535ec0f4bbae66/aa/' \
  -H 'Connection: keep-alive' \
  -H 'Accept: */*' \
  -H 'User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36' \
  -H 'X-Requested-With: XMLHttpRequest' \
  -H 'Sec-GPC: 1' \
  -H 'Referer: http://aes.cryptohack.org/passwords_as_keys/' \
  -H 'Accept-Language: en-US,en;q=0.9,pl;q=0.8' \
  --compressed \
  --insecure ;
curl 'http://aes.cryptohack.org/passwords_as_keys/decrypt/c92b7734070205bdf6c0087a751466ec13ae15e6f1bcdd3f3a535ec0f4bbae66/aabb/' \
  -H 'Connection: keep-alive' \
  -H 'Accept: */*' \
  -H 'User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36' \
  -H 'X-Requested-With: XMLHttpRequest' \
  -H 'Sec-GPC: 1' \
  -H 'Referer: http://aes.cryptohack.org/passwords_as_keys/' \
  -H 'Accept-Language: en-US,en;q=0.9,pl;q=0.8' \
  --compressed \
  --insecure'''
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
