def move(ciphertext: str, i: int) -> str:
    res = []
    for l in ciphertext:
        if l == ' ':
            c = l
        else:
            o = ord(l)
            moved = o + i
            if moved > ord('Z'):
                # print(moved)
                moved -= 26

            c = chr(moved)

        res.append(c)

    return ''.join(res)


def main():
    ciphertext = 'AIFX QUFF NBUHE XYGCMY'

    for i in range(24):
        plaintext = move(ciphertext, i)
        print(plaintext)


if __name__ == '__main__':
    main()
