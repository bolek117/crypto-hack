def smallest_primitive(n: int) -> int:
    for g in range(2, n):
        subgroup_h = set()

        for j in range(1, n):
            power = pow(g, j) % n

            if power in subgroup_h:
                break

            subgroup_h.add(power)

        if len(subgroup_h) == n-1:
            return g

        print(f'{len(subgroup_h)} - {g}')


def main():
    p = 28151

    smallest_primitive_of_fp = smallest_primitive(p)
    print(smallest_primitive_of_fp)
    pass


if __name__ == '__main__':
    main()
