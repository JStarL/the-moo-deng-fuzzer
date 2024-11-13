from typing import Iterator
import random


def bit_flip(data: bytes) -> Iterator[bytes]:
    """
    Flip individual bits in each byte of the input data.
    """
    for byte_index in range(len(data)):
        for bit_index in range(8):
            mutated_data = bytearray(data)
            mutated_data[byte_index] ^= (1 << bit_index)
            yield bytes(mutated_data)


def byte_flip(data: bytes) -> Iterator[bytes]:
    """
    Flip each byte in the input data with all possible 8-bit masks (0x00 to 0xFF).
    """
    for byte_index in range(len(data)):
        for mask in range(256):
            mutated_data = bytearray(data)
            mutated_data[byte_index] ^= mask
            yield bytes(mutated_data)


def word_flip(data: bytes) -> Iterator[bytes]:
    """
    Flip each 2-byte (word) segment in the input data if length >= 2.
    """
    if len(data) < 2:
        return
    for i in range(len(data) - 1):
        for mask in range(0x10000):  # 16-bit mask
            mutated_data = bytearray(data)
            word_value = ((mutated_data[i] << 8) | mutated_data[i + 1]) ^ mask
            mutated_data[i] = (word_value >> 8) & 0xFF
            mutated_data[i + 1] = word_value & 0xFF
            yield bytes(mutated_data)


def dword_flip(data: bytes) -> Iterator[bytes]:
    """
    Flip each 4-byte (dword) segment in the input data if length >= 4.
    Generates variations by applying a 32-bit mask to each dword.
    """
    if len(data) < 4:
        return
    for i in range(len(data) - 3):
        for mask in range(0x100000000):  # 32-bit mask for dword
            mutated_data = bytearray(data)
            dword_value = int.from_bytes(mutated_data[i:i + 4], "little") ^ mask
            mutated_data[i:i + 4] = dword_value.to_bytes(4, "little")
            yield bytes(mutated_data)


def qword_flip(data: bytes) -> Iterator[bytes]:
    """
    Flip each 8-byte (qword) segment in the input data if length >= 8.
    Generates variations by applying a 64-bit mask to each qword.
    """
    if len(data) < 8:
        return
    for i in range(len(data) - 7):
        for mask in range(0x10000000000000000):  # 64-bit mask for qword
            mutated_data = bytearray(data)
            qword_value = int.from_bytes(mutated_data[i:i + 8], "little") ^ mask
            mutated_data[i:i + 8] = qword_value.to_bytes(8, "little")
            yield bytes(mutated_data)


def critical_bit_flip(data: bytes) -> Iterator[bytes]:
    """
    Flip critical bits (high and low bits) in each byte.
    """
    for byte_index in range(len(data)):
        for bit_index in [0, 7]:  # Only flip the high and low bits
            mutated_data = bytearray(data)
            mutated_data[byte_index] ^= (1 << bit_index)
            yield bytes(mutated_data)


def random_partial_flip(data: bytes) -> Iterator[bytes]:
    """
    Randomly flip two bits within each byte of the input data.
    """
    for byte_index in range(len(data)):
        # Randomly select two unique bit positions in the range 0-7
        bit_index_1, bit_index_2 = random.sample(range(8), 2)

        # Make a mutable copy of the data
        mutated_data = bytearray(data)

        # Flip the selected bits
        mutated_data[byte_index] ^= (1 << bit_index_1) | (1 << bit_index_2)

        # Yield the mutated data as bytes
        yield bytes(mutated_data)


def inject_special_values(data: bytes) -> Iterator[bytes]:
    """
    Inject common boundary values (e.g., 0x00, 0xFF, etc.) into each byte position.
    """
    special_values = [0x00, 0xFF, 0x7F, 0x80]
    for byte_index in range(len(data)):
        for value in special_values:
            mutated_data = bytearray(data)
            mutated_data[byte_index] = value
            yield bytes(mutated_data)

if __name__ == "__main___":

    # Example usage:
    original_data = b"AB"
    i = 0
    for mutation in bit_flip(original_data):
        print("Bit flip:", mutation)
        i += 1
    print(i)
    i = 0
    for mutation in byte_flip(original_data):
        # print("Byte flip:", mutation)
        i += 1
    print(i)
    i = 0
    for mutation in word_flip(original_data):
        # print("Word flip:", mutation)
        i += 1
    print(i)
    i = 0
    for mutation in critical_bit_flip(original_data):
        print("Critical bit flip:", mutation)
        i += 1
    print(i)
    i = 0
    for mutation in random_partial_flip(original_data):
        # print("Partial flip:", mutation)
        i += 1
    print(i)
    i = 0
    for mutation in inject_special_values(original_data):
        print("Inject special values:", mutation)
        i += 1
    print(i)
    i = 0

