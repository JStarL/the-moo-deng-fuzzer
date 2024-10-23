from typing import Iterator, List, Optional
import random
from special_values import SPECIAL_INTS
from buffer_overflow import buffer_overflow_mutation


def nearby_ints(number: int, extent: int) -> Iterator[int]:
    """Generates integers near the given number within the specified extent.

    Args:
        number (int): The base number.
        extent (int): The range of nearby values to generate.

    Yields:
        Iterator[int]: Integers near the base number.
    """
    for i in range(0, extent):
        yield number + i
        yield number - i


def nearby_special_ints(extent: int) -> Iterator[int]:
    """Generates nearby integers for special values in the list SPECIAL_INTS.

    Args:
        extent (int): The range of nearby values to generate.

    Yields:
        Iterator[int]: Nearby integers for special values.
    """
    for i in SPECIAL_INTS:
        yield from nearby_ints(i, extent)


def nearby_special_ints_add_buf(extent: int) -> Iterator[bytes]:
    """Combines nearby integers with buffer overflow mutations.

    Args:
        extent (int): The range of nearby values to generate.

    Yields:
        Iterator[bytes]: Nearby integers with buffer overflow mutations appended.
    """
    for buf in buffer_overflow_mutation():
        for i in nearby_special_ints(extent):
            # Convert integer to bytes and add buffer overflow
            yield str(i).encode() + buf


def random_ints(count: int, scope: int, signed: bool = False) -> Iterator[int]:
    """Generate random integers within a given scope.

    Args:
        count (int): The number of random integers to generate.
        scope (int): The range for integer generation (for signed/unsigned).
        signed (bool): Generate signed integers if True, otherwise unsigned.

    Yields:
        Iterator[int]: Randomly generated integers.
    """
    for _ in range(count):
        if signed:
            yield random.randint(-scope, scope)
        else:
            yield random.randint(0, scope)


def to_str(ints_input: Optional[List[int]] = None) -> Iterator[bytes]:
    """Converts integers to their byte-string representations.

    Args:
        ints_input (List[int], optional): List of integers to convert.

    Yields:
        Iterator[bytes]: Byte-string representations of integers.
    """
    if ints_input is None:
        ints_input = SPECIAL_INTS
    for i in ints_input:
        yield str(i).encode()


def to_str_add_buf(ints_input: Optional[List[int]] = None) -> Iterator[bytes]:
    """Adds buffer overflow mutations to the string-converted integers.

    Args:
        ints_input (List[int], optional): List of integers to convert.

    Yields:
        Iterator[bytes]: Byte-string representations of integers with buffer overflows appended.
    """
    for buf in buffer_overflow_mutation():
        for s in to_str(ints_input):
            yield s + buf


def to_hex(ints_input: Optional[List[int]] = None) -> Iterator[bytes]:
    """Converts integers to their hexadecimal byte-string representations.

    Args:
        ints_input (List[int], optional): List of integers to convert.

    Yields:
        Iterator[bytes]: Hexadecimal byte-string representations of integers.
    """
    if ints_input is None:
        ints_input = SPECIAL_INTS
    for i in ints_input:
        yield f"{i:x}".encode()


def to_hex_add_buf(ints_input: Optional[List[int]] = None) -> Iterator[bytes]:
    """Adds buffer overflow mutations to the hexadecimal string-converted integers.

    Args:
        ints_input (List[int], optional): List of integers to convert.

    Yields:
        Iterator[bytes]: Hexadecimal byte-string representations of integers with buffer overflows appended.
    """
    for buf in buffer_overflow_mutation():
        for s in to_hex(ints_input):
            yield s + buf


def to_endian(ints_input: Optional[List[int]] = None, order: str = 'little') -> Iterator[bytes]:
    """Converts integers to their byte representation in little or big endian format.

    Args:
        ints_input (List[int], optional): List of integers to convert. Defaults to SPECIAL_INTS.
        order (str, optional): Byte order ('little' or 'big'). Defaults to 'little'.

    Yields:
        Iterator[bytes]: Byte representations of integers in the specified endian order.
    """
    if ints_input is None:
        ints_input = SPECIAL_INTS

    byte_order = 'big' if order != 'little' else 'little'

    for i in ints_input:
        try:
            yield i.to_bytes(8, byteorder=byte_order)
        except OverflowError:
            yield i.to_bytes(8, byteorder=byte_order, signed=True)


def to_endian_add_buf(ints_input: Optional[List[int]] = None, order: str = "little") -> Iterator[bytes]:
    """Adds buffer overflow mutations to the endian-converted integers.

    Args:
        ints_input (List[int], optional): List of integers to convert. Defaults to SPECIAL_INTS.
        order (str, optional): Byte order ('little' or 'big'). Defaults to 'little'.

    Yields:
        Iterator[bytes]: Byte-string representations of integers in endian format with buffer overflows appended.
    """
    for buf in buffer_overflow_mutation():
        for s in to_endian(ints_input, order):
            yield s + buf


# Test the functions
def run_tests() -> None:
    """Run test cases for all functions."""

    # Test nearby_ints
    assert list(nearby_ints(100, 3)) == [100, 100, 101, 99, 102, 98], "nearby_ints test failed"

    # Test nearby_special_ints
    result_nearby_special_ints = list(nearby_special_ints(2))
    assert len(result_nearby_special_ints) == len(SPECIAL_INTS) * 4, "nearby_special_ints test failed"

    # Test nearby_special_ints_add_buf
    result_nearby_special_ints_add_buf = list(nearby_special_ints_add_buf(2))
    assert len(result_nearby_special_ints_add_buf) > 0, "nearby_special_ints_add_buf test failed"

    # Test random_ints
    result_random_ints = list(random_ints(5, 100, signed=True))
    assert len(result_random_ints) == 5, "random_ints test failed"
    assert all(-100 <= x <= 100 for x in result_random_ints), "random_ints (signed) test failed"

    # Test to_str
    assert list(to_str([1, 2, 3])) == [b"1", b"2", b"3"], "to_str test failed"

    # Test to_str_add_buf
    result_to_str_add_buf = list(to_str_add_buf([1, 2]))
    assert len(result_to_str_add_buf) > 0, "to_str_add_buf test failed"

    # Test to_hex
    assert list(to_hex([255, 16, 32])) == [b"ff", b"10", b"20"], "to_hex test failed"

    # Test to_hex_add_buf
    result_to_hex_add_buf = list(to_hex_add_buf([255, 16]))
    assert len(result_to_hex_add_buf) > 0, "to_hex_add_buf test failed"

    # Test to_endian
    assert list(to_endian([255, 16])) == [b'\x00\x00\x00\x00\x00\x00\x00\xff',
                                          b'\x00\x00\x00\x00\x00\x00\x00\x10'], "to_endian test failed"

    # Test to_endian_add_buf
    result_to_endian_add_buf = list(to_endian_add_buf([255, 16]))
    assert len(result_to_endian_add_buf) > 0, "to_endian_add_buf test failed"

    print("All tests passed!")


# Run the tests
if __name__ == "__main__":
    run_tests()
