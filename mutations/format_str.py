from typing import Iterator
import random
from .special_values import INJECTION_PAYLOADS, BOUNDARY_VALUES, BOUNDARY_CHAR_STRINGS
import itertools

def data_injection(data: bytes) -> Iterator[bytes]:
    """
    Inject long format specifiers (e.g., %1000x) to test edge cases.
    """

    for spec in itertools.chain(INJECTION_PAYLOADS, BOUNDARY_VALUES):
        if isinstance(spec, str):
            spec_bin = spec.encode('utf-8')
        else:
            spec_bin = spec
        yield spec_bin
        yield data + b" " + spec_bin
        yield spec_bin + b" " + data



def format_injection(data: bytes) -> Iterator[bytes]:
    """
    Inject common format specifiers (e.g., %s, %d, %x) into the byte sequence.
    """
    format_specifiers = [
        b"%s",  # Outputs a string; tests string handling and buffer boundaries.
        b"%d",  # Outputs a signed integer; useful for numeric parsing and boundary testing.
        b"%x",  # Outputs a hexadecimal integer; reveals memory contents.
        b"%p",  # Outputs a pointer address in hex; tests for memory leak vulnerabilities.
        b"%p %p %p",  # Multiple pointers; tests memory leak potential with several pointers in sequence.
        b"%s %s %s",  # Multiple pointers; tests memory leak potential with several pointers in sequence.
        b"%p %p %p" * 1000,  # Multiple pointers; tests memory leak potential with several pointers in sequence.
        b"%s %s %s" * 1000,  # Multiple pointers; tests memory leak potential with several pointers in sequence.
        b"%lln" * 10000, # Writes 8 bytes to a memory address
        b"%n",
        # Writes the number of bytes written so far to a memory address; tests for arbitrary memory write vulnerabilities.
        b"%hhn",  # Writes 1 byte to a memory address; useful in testing byte-specific vulnerabilities.
        b"%hn",  # Writes 2 bytes to a memory address; partial overwrite vulnerabilities.
        b"%lld",  # Outputs a 64-bit long long integer; relevant for 64-bit integer handling in x86-64.
        b"%llx",  # Outputs a 64-bit long long integer in hex; useful for revealing pointer values on x86-64.
        b"%lx",  # Outputs a 32-bit long integer in hex; useful in mixed 32/64-bit environments.
        b"%lu",  # Outputs an unsigned long integer; used for unsigned boundary checks.
        b"%u",  # Outputs an unsigned integer; helps in testing unsigned integer boundaries.
        b"%f",  # Outputs a floating-point number; tests decimal and floating-point formatting.
        b"%e",  # Outputs a floating-point number in scientific notation; useful for precision testing.
        b"%g",
        # Outputs a floating-point number in compact format (scientific or decimal); tests for switching behavior.
        b"%#x",  # Hex with prefix (0x); useful to test for hex format edge cases.
        b"%o",  # Outputs an octal integer; tests for non-decimal numeral system handling.
        b"%c",  # Outputs a single character; tests ASCII and Unicode handling.
        b"%10.2f",  # Outputs a float with width 10, precision 2; tests width and precision control in floats.
        b"%020x",  # Zero-padded width for hex; useful for format parsing checks.
        b"%-100d",  # Left-aligned with large width; can reveal alignment handling issues.
        b"%.4096d",  # Integer with high precision, stresses the output buffer limits.
        b"%.*s",  # Dynamically specifies precision; tests handling of dynamic format controls.
        b"%1024c",  # Outputs 1024 characters; useful for buffer limit testing.
        b"%#100x",  # Hex with alternate form (0x) and specified width; tests complex formatting handling.
        b"%jX",  # Outputs a 64-bit integer in uppercase hex (POSIX); tests large integer formats.
        b"%+d",  # Signed integer with explicit sign; tests for sign handling.
        b"%ld",  # Long integer format; useful in cross-platform and cross-architecture fuzzing.
        b"%*d",  # Width specified as an argument; tests for width control and format parsing.
        b"%-#010x",  # Combined alignment, padding, prefix; complex format tests for vulnerabilities.
        b"%#08x",  # Hex with prefix and zero padding; useful in detailed formatting fuzzing.
        b"%*.*f",  # Dynamic width and precision for floats; tests floating-point parsing with dynamic arguments.
    ]
    for spec in format_specifiers:
        yield spec
        yield data + b" " + spec
        yield spec + b" " + data


def long_format_specifier(data: bytes) -> Iterator[bytes]:
    """
    Inject long format specifiers (e.g., %1000x) to test edge cases.
    """
    long_specs = [
        b"%1000x",  # Large width, tests for buffer overflow
        b"%9999999s",  # Extremely large width, tests memory allocation issues
        b"%10$s",  # Parameter indexing, potential for memory leak
        b"%10000d",  # Large width integer format
        b"%2147483647d",  # Maximum 32-bit integer width, tests overflow
        b"%32767x",  # Maximum 16-bit signed integer width
        b"%65536s",  # 64KB string width, tests memory allocation limits
        b"%llu",  # Unsigned long long integer
        b"%020x",  # Zero-padded long width, tests format parsing
        b"%-100d",  # Left-aligned large width, may cause memory layout issues
        b"%.*s",  # Dynamic width control, tests format parsing robustness
        b"%999.999f",  # Extremely high-precision float
        b"%10.10x",  # Fixed width hex format, checks for stack overflow
        b"%1024c",  # Outputs 1024 characters, tests buffer limits
        b"%#100x",  # Width with prefix for hex formatting
        b"%.4096d",  # Large precision, tests float processing
        b"%10000000000d",  # Extremely large width integer, tests integer overflow
        b"%lld",  # Long integer format, useful for 64-bit systems
        b"%jx",  # Prints pointer-sized integer, common on POSIX systems
    ]
    
    if isinstance(data, bytes):
        try:
            data = data.decode('utf-8')
        except:
            pass
    
    for spec in long_specs:
        yield spec
        yield data + b" " + spec
        yield spec + b" " + data


def boundary_value_injection(data: bytes) -> Iterator[bytes]:
    """
    Inject boundary values (e.g., \x00, \xFF) into the byte sequence.
    """
    for boundary in BOUNDARY_CHAR_STRINGS:
        boundary_bytes = boundary.encode('utf-8')
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
