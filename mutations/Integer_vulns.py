from typing import Iterator
import random
from special_values import SPECIAL_INTS


def nearby_ints(number: int, extent: int) -> Iterator[int]:
    for i in range(0, extent):
        yield number + i
        yield number - i


def nearby_special_ints(extent) -> Iterator[int]:
    for i in SPECIAL_INTS:
        yield from nearby_ints(i, extent)


def random_ints(count: int, scope, signed: bool = False) -> Iterator[int]:
    """Generate a specified number of random integers within the given scope.

       Args:
           count (int): The number of random integers to generate.
           scope (int): The range within which to generate integers (for signed/unsigned).
           signed (bool): Whether to generate signed integers. Defaults to True.

       Yields:
           int: Random integers either signed or unsigned within the specified scope.
       """
    for _ in range(count):
        # Generate a random integer within the scope
        unsigned_val = random.randint(0, scope)  # For unsigned, randint from 0 to scope

        if signed:
            # Convert to signed integer by allowing negative values
            yield random.randint(-scope, scope)
        else:
            # Return the unsigned value (already generated)
            yield unsigned_val


def to_str(ints_input=None) -> Iterator[bytes]:
    if ints_input is None:
        ints_input = SPECIAL_INTS
    for i in ints_input:
        yield f"{i}".encode()


def to_hex(ints_input=None) -> Iterator[bytes]:
    if ints_input is None:
        ints_input = SPECIAL_INTS
    for i in ints_input:
        yield f"{i:x}".encode()


def to_little_endian(ints_input=None) -> Iterator[bytes]:
    if ints_input is None:
        ints_input = SPECIAL_INTS
    for i in ints_input:
        try:
            yield i.to_bytes(length=8, byteorder="little")
        except OverflowError:
            yield i.to_bytes(length=8, byteorder="little", signed=True)


def to_big_endian(ints_input=None) -> Iterator[bytes]:
    if ints_input is None:
        ints_input = SPECIAL_INTS
    for i in ints_input:
        try:
            yield i.to_bytes(length=8, byteorder="big")
        except OverflowError:
            yield i.to_bytes(length=8, byteorder="big", signed=True)


# Test the function
def test_mutation():
    # Call the function to generate buffer overflow inputs
    for idx, mutated_input in enumerate(nearby_special_ints(10)):
        # Print the length of each generated input to see if it matches expected sizes
        print(f"Generated input {idx + 1}: {(mutated_input)}")


# Run the test
if __name__ == "__main__":
    test_mutation()
