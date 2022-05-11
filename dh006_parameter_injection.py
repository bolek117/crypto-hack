# You're in a position to not only intercept Alice and Bob's DH key exchange, but also rewrite their messages.
# Think about how you can play with the DH equation that they calculate, and therefore sidestep the need to crack any
# discrete logarithm problem.
# Use the script from "Diffie-Hellman Starter 5" to decrypt the flag once you've recovered the shared secret.
# Connect at nc socket.cryptohack.org 13371
import json

from pwn import *
from dh_common import *

ENCODING = 'utf-8'


def get_message_from_line(line: bytes) -> str:
    s = line.decode('utf-8')
    print(s)
    parts = s.split(': ', 1)
    return parts[1]


def get_json_from_line(line: bytes) -> object:
    msg = line.decode('utf-8')
    json_pretty(json.loads(msg))
    return json.loads(msg)


def json_pretty(o: object) -> None:
    print(json.dumps(o, indent=2))


def header(msg: str) -> None:
    print(f'\n------ {msg} -----')


def report_sent_data(s: str) -> None:
    print(f'Sent: {s}')


def recvline_wo_header(r, header: str) -> bytes:
    return r.recvline()[len(header):]


def main():
    context(arch='amd64', os='windows')
    context.timeout = 3

    addr = 'socket.cryptohack.org'
    port = 13371

    with remote(addr, port) as r:
        header('[INTERCEPTED] Alice -> Bob')
        line = recvline_wo_header(r, 'Intercepted from Alice: ')
        data = get_json_from_line(line)

        header('Manipulating data')
        p = int(data['p'], 16)
        g = int(data['g'], 16)
        a = 2

        capital_a = calculate_capital_a(g, a, p)
        manipulated_alice_message_data = {
            'g': data['g'],
            'A': hex(capital_a),
            'p': data['p']
        }

        json_pretty(manipulated_alice_message_data)

        header('Sending modified data')
        line_to_be_sent = json.dumps(manipulated_alice_message_data)
        r.sendline(line_to_be_sent.encode(ENCODING))
        report_sent_data(line_to_be_sent)

        header('Getting B from Bob')
        line = recvline_wo_header(r, 'Send to Bob: Intercepted from Bob: ')
        data = get_json_from_line(line)

        capital_b = int(data['B'], 16)

        shared_secret = calculate_shared_secret(capital_b, a, p)
        print(f'Shared secret: {shared_secret}')

        header('Send modified A as B to Alice')
        line_to_be_sent = json.dumps(data)
        r.sendline(line_to_be_sent.encode(ENCODING))
        report_sent_data(line_to_be_sent)

        header('Receiving encrypted message')
        line = recvline_wo_header(r, 'Send to Alice: Intercepted from Alice: ')
        data = get_json_from_line(line)

        iv = data['iv']
        flag = data['encrypted_flag']

        decrypted = decrypt_flag(shared_secret, iv, flag)
        print(decrypted)


if __name__ == '__main__':
    main()
