def compute(p: int, g: int) -> int:
    start = 0
    stop = p

    # g * d mod 991 = 1
    for d in range(start, stop):
        if g * d % p == 1:
            return d

    raise ValueError(f'Solution not found in range {start} -> {stop}')


if __name__ == '__main__':
    p = 991
    g = 209

    try:
        print(f'd = {compute(p, g)}')
    except ValueError as e:
        print(f'- {e}')
