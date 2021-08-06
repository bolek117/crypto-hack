from matrix_operators import matrix2bytes


def add_round_key(s: bytes, k: bytes) -> bytes:
    # result = bytes([pair[0] ^ pair[1] for pair in zip(s, k)])
    result = bytearray()
    for i in range(4):
        for j in range(4):
            result.append(s[i][j] ^ k[i][j])

    return result


if __name__ == '__main__':
    state = [
        [206, 243, 61, 34],
        [171, 11, 93, 31],
        [16, 200, 91, 108],
        [150, 3, 194, 51],
    ]

    round_key = [
        [173, 129, 68, 82],
        [223, 100, 38, 109],
        [32, 189, 53, 8],
        [253, 48, 187, 78],
    ]

    b = add_round_key(state, round_key)
    print(b)
