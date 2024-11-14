from typing import Iterator
import random
from .special_values import INJECTION_PAYLOADS, BOUNDARY_VALUES, BOUNDARY_CHAR_STRINGS, long_specs, format_specifiers

def data_injection(data: bytes) -> Iterator[bytes]:
    """
    Inject long format specifiers (e.g., %1000x) to test edge cases.
    """
    for spec in INJECTION_PAYLOADS:
        yield spec
        yield data + b" " + spec
        yield spec + b" " + data

def boundary_str_injection(data: bytes) -> Iterator[bytes]:
    """
    Inject special boundary values to test edge cases.
    """
    for spec in BOUNDARY_VALUES:
        yield spec
        # yield data + b" " + spec


def format_injection(data: bytes) -> Iterator[bytes]:
    """
    Inject common format specifiers (e.g., %s, %d, %x) into the byte sequence.
    """
    for spec in format_specifiers:
        # yield data + b"" + spec
        yield spec + b" " + data
        # yield spec


def long_format_specifier(data: bytes) -> Iterator[bytes]:
    """
    Inject long format specifiers (e.g., %1000x) to test edge cases.
    """
    for spec in long_specs:
        yield spec
        yield data + b"" + spec
        yield spec + b"" + data


def boundary_value_injection(data: bytes) -> Iterator[bytes]:
    """
    Inject boundary values (e.g., \x00, \xFF) into the byte sequence.
    """
    for boundary in BOUNDARY_CHAR_STRINGS:
        boundary_bytes = boundary.encode()
        yield boundary_bytes
        yield data.replace(b" ", boundary_bytes)
        yield boundary_bytes + data + boundary_bytes


def random_combined_injection(data: bytes) -> Iterator[bytes]:
    """
    Randomly combines the above injection methods for more comprehensive testing.
    """
    injections = [
        format_injection,
        long_format_specifier,
        boundary_value_injection
    ]
    for _ in range(10):  # Generate 10 random combined mutations
        chosen_injection = random.choice(injections)
        for mutation in chosen_injection(data):
            yield mutation


if __name__ == "__main__":

    # Example usage with bytes
    original_data = b"Test format string"
    print("Basic Format Injection:")
    for mutation in format_injection(original_data):
        print(mutation)

    print("\nLong Format Specifier Injection:")
    for mutation in long_format_specifier(original_data):
        print(mutation)

    print("\nBoundary Value Injection:")
    for mutation in boundary_value_injection(original_data):
        print(mutation)

    print("\nRandom Combined Injection:")
    for mutation in random_combined_injection(original_data):
        print(mutation)
