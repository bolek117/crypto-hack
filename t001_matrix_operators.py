def bytes2matrix(b: bytes):
    """ Converts a 16-byte array into a 4x4 matrix.  """
    return [list(b[i:i + 4]) for i in range(0, len(b), 4)]


def matrix2bytes(matrix) -> bytes:
    """ Converts a 4x4 matrix into a 16-byte array.  """
    result = bytearray()
    # for row in matrix:
    #     for i in row:
    #         result.append(i)
    #
    # return bytes(result)
    return bytes(sum(matrix, []))


if __name__ == '__main__':
    matrix = [
        [99, 114, 121, 112],
        [116, 111, 123, 105],
        [110, 109, 97, 116],
        [114, 105, 120, 125],
    ]

    print(matrix2bytes(matrix))
