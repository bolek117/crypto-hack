import sys

min_d = sys.maxsize
max_d = -sys.maxsize


def compute(p: int, g: int, start: int, stop: int) -> int:
    global min_d, max_d

    def l(d):
        print(f'd={d}, Min: {min_d}, max: {max_d}', flush=True)
        pass

    # g * d mod 991 = 1
    for d in range(start, stop):
        res = g * d % p
        if res < min_d:
            min_d = res
            l(d)

        if res > max_d:
            max_d = res
            l(d)

        if res == 1:
            print(f'd = {d}, so {g} * {d} % {p} = 1')
            return d

    raise ValueError(f'Solution not found in range {start} -> {stop}')


if __name__ == '__main__':
    start = 0
    stop = 1000

    p = 991
    g = 209

    try:
        print(f'd = {compute(p, g, start, stop)}')
    except ValueError as e:
        print(f'- {e}')
