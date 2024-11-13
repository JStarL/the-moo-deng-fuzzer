SPECIAL_INTS: list[int] = list({
    # 32-bit specific edge cases
    0xFFFFFFFF,  # Max unsigned 32-bit integer (2^32 - 1)
    0x7FFFFFFF,  # Max signed 32-bit integer (2^31 - 1)
    0x80000000,  # Min signed 32-bit integer (-2^31)

    # 64-bit specific edge cases
    0xFFFFFFFFFFFFFFFF,  # Max unsigned 64-bit integer (2^64 - 1)
    0x7FFFFFFFFFFFFFFF,  # Max signed 64-bit integer (2^63 - 1)
    0x8000000000000000,  # Min signed 64-bit integer (-2^63)
    # Edge case values
    0,  # Zero
    -1,  # Negative one
    1,  # Positive one

    # Large numbers near the limits of 32-bit integers
    0xFFFFFFFE,  # Just below UINT_MAX for 32-bit
    0x7FFFFFFE,  # Just below INT_MAX for 32-bit

    # Large numbers near the limits of 64-bit integers
    0xFFFFFFFFFFFFFFFE,  # Just below UINT_MAX for 64-bit
    0x7FFFFFFFFFFFFFFE,  # Just below INT_MAX for 64-bit

    # Powers of 2 for 32-bit integers
    *(2 ** i for i in range(1, 64)),

    # Negative powers of 2 for 32-bit integers
    *(-(2 ** i) for i in range(1, 64)),

    # Random special numbers
    314159265,  # Pi approximation
    271828182,  # e approximation
    42,  # The answer to life, universe, and everything
    1337,  # Hacker number
    9001,  # Over 9000!
})

# Define special character values as integers for boundary and edge case testing
SPECIAL_CHAR_INTS = [0x00, 0xFF, 0x7F, 0x80]

# Define boundary values in string form for testing in text-based fields
BOUNDARY_CHAR_STRINGS = ["\x00", "\xFF", "\x7F", "\x80"]



SPECIAL_POSITIVE_INTS = [i for i in SPECIAL_INTS if i > 0]
TRIVAL_POSITIVE_INTS = list({
    2 ** 16
})
