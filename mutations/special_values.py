SPECIAL_INTS: list[int] = list({
    # 32-bit specific edge cases
    0xFFFFFFFF,  # Max unsigned 32-bit integer (2^32 - 1)
    0x7FFFFFFF,  # Max signed 32-bit integer (2^31 - 1)
    0x80000000,  # Min signed 32-bit integer (-2^31)

    # Edge case values
    0,  # Zero
    -1,  # Negative one
    1,  # Positive one

    # Large numbers near the limits of 32-bit integers
    0xFFFFFFFE,  # Just below UINT_MAX for 32-bit
    0x7FFFFFFE,  # Just below INT_MAX for 32-bit

    # Powers of 2 for 32-bit integers
    *(2 ** i for i in range(1, 32)),

    # Negative powers of 2 for 32-bit integers
    *(-(2 ** i) for i in range(1, 32)),

    # Random special numbers
    314159265,  # Pi approximation
    271828182,  # e approximation
    42,  # The answer to life, universe, and everything
    1337,  # Hacker number
    9001,  # Over 9000!
})

SPECIAL_POSITIVE_INTS = [i for i in SPECIAL_INTS if i > 0]
TRIVAL_POSITIVE_INTS = list({
    2 ** 16
})