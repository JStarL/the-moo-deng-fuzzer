TRIVAL_POSITIVE_INTS: list[int] = list(
    {
        *(i for i in range(1, 11)),
        2 ** 16,
    }
)

SPECIAL_INTS: list[int] = list(
    {
        *(i for i in range(-10, 11)),  # -10 to 10
        100,
        101,
        127,
        128,
        0x7FFFFFFF,  # INT_MAX
        0x80000000,  # INT_MIN, 2^32
        0xFFFFFFFF,  # UINT_MAX, -1
        *(2 ** i for i in range(1, 32)),  # 2^i
        *(-(2 ** i) for i in range(1, 32)),  # -(2^i)
        *(2 ** i + 1 for i in range(1, 32)),  # 2^i + 1
        *(2 ** i - 1 for i in range(1, 32)),  # 2^i + 1
        0xFF,
        -2047000000
    }
)
