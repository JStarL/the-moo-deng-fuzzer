from typing import Iterator
import random
from .special_values import BOUNDARY_CHAR_STRINGS

def format_injection(data: str) -> Iterator[str]:
    """
    Inject common format specifiers (e.g., %s, %d, %x) into the string.
    """
    format_specifiers = [
        "%s",  # Outputs a string; tests string handling and buffer boundaries.
        "%d",  # Outputs a signed integer; useful for numeric parsing and boundary testing.
        "%x",  # Outputs a hexadecimal integer; reveals memory contents.
        "%p",  # Outputs a pointer address in hex; tests for memory leak vulnerabilities.
        "%s %s %s" * 1000,  # Multiple pointers; tests memory leak potential with several pointers in sequence.
        "%s %s %s" * 1000,  # Multiple pointers; tests memory leak potential with several pointers in sequence.
        "%n",
        # Writes the number of bytes written so far to a memory address; tests for arbitrary memory write vulnerabilities.
        "%hhn",  # Writes 1 byte to a memory address; useful in testing byte-specific vulnerabilities.
        "%hn",  # Writes 2 bytes to a memory address; partial overwrite vulnerabilities.
        "%lld",  # Outputs a 64-bit long long integer; relevant for 64-bit integer handling in x86-64.
        "%llx",  # Outputs a 64-bit long long integer in hex; useful for revealing pointer values on x86-64.
        "%lx",  # Outputs a 32-bit long integer in hex; useful in mixed 32/64-bit environments.
        "%lu",  # Outputs an unsigned long integer; used for unsigned boundary checks.
        "%u",  # Outputs an unsigned integer; helps in testing unsigned integer boundaries.
        "%f",  # Outputs a floating-point number; tests decimal and floating-point formatting.
        "%e",  # Outputs a floating-point number in scientific notation; useful for precision testing.
        "%g",
        # Outputs a floating-point number in compact format (scientific or decimal); tests for switching behavior.
        "%#x",  # Hex with prefix (0x); useful to test for hex format edge cases.
        "%o",  # Outputs an octal integer; tests for non-decimal numeral system handling.
        "%c",  # Outputs a single character; tests ASCII and Unicode handling.
        "%10.2f",  # Outputs a float with width 10, precision 2; tests width and precision control in floats.
        "%020x",  # Zero-padded width for hex; useful for format parsing checks.
        "%-100d",  # Left-aligned with large width; can reveal alignment handling issues.
        "%.4096d",  # Integer with high precision, stresses the output buffer limits.
        "%.*s",  # Dynamically specifies precision; tests handling of dynamic format controls.
        "%1024c",  # Outputs 1024 characters; useful for buffer limit testing.
        "%#100x",  # Hex with alternate form (0x) and specified width; tests complex formatting handling.
        "%jX",  # Outputs a 64-bit integer in uppercase hex (POSIX); tests large integer formats.
        "%+d",  # Signed integer with explicit sign; tests for sign handling.
        "%ld",  # Long integer format; useful in cross-platform and cross-architecture fuzzing.
        "%*d",  # Width specified as an argument; tests for width control and format parsing.
        "%-#010x",  # Combined alignment, padding, prefix; complex format tests for vulnerabilities.
        "%#08x",  # Hex with prefix and zero padding; useful in detailed formatting fuzzing.
        "%*.*f",  # Dynamic width and precision for floats; tests floating-point parsing with dynamic arguments.
    ]
    for spec in format_specifiers:
        yield f"{data} {spec}"
        yield f"{spec} {data}"
        yield f"{data[:len(data)//2]} {spec} {data[len(data)//2:]}"


def long_format_specifier(data: str) -> Iterator[str]:
    """
    Inject long format specifiers (e.g., %1000x) to test edge cases.
    """
    long_specs = [
        "%1000x",  # Large width, tests for buffer overflow
        "%9999999s",  # Extremely large width, tests memory allocation issues
        "%10$s",  # Parameter indexing, potential for memory leak
        "%10000d",  # Large width integer format
        "%2147483647d",  # Maximum 32-bit integer width, tests overflow
        "%32767x",  # Maximum 16-bit signed integer width
        "%65536s",  # 64KB string width, tests memory allocation limits
        "%llu",  # Unsigned long long integer
        "%020x",  # Zero-padded long width, tests format parsing
        "%-100d",  # Left-aligned large width, may cause memory layout issues
        "%.*s",  # Dynamic width control, tests format parsing robustness
        "%999.999f",  # Extremely high-precision float
        "%10.10x",  # Fixed width hex format, checks for stack overflow
        "%1024c",  # Outputs 1024 characters, tests buffer limits
        "%#100x",  # Width with prefix for hex formatting
        "%.4096d",  # Large precision, tests float processing
        "%10000000000d",  # Extremely large width integer, tests integer overflow
        "%lld",  # Long integer format, useful for 64-bit systems
        "%jx",  # Prints pointer-sized integer, common on POSIX systems
    ]
    for spec in long_specs:
        yield f"{data} {spec}"
        yield f"{spec} {data}"

def boundary_value_injection(data: str) -> Iterator[str]:
    """
    Inject boundary values (e.g., \x00, \xFF) into the string.
    """
    boundary_values = BOUNDARY_CHAR_STRINGS
    for boundary in boundary_values:
        yield data.replace(" ", boundary)  # Replace spaces with boundary values
        yield f"{boundary}{data}{boundary}"


def random_combined_injection(data: str) -> Iterator[str]:
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

    # Example usage
    original_data = "Test format string"
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
