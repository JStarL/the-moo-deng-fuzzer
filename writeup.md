# Authors

z5280740 - Jibitesh Saha

z5441928 - Li Li

z5437039 - Antheo Raviel Santosa

z5408331 - Halliya Hyeryeon UM

# Fuzzer

The fuzzer that we have developed is a black-box fuzzer which uses a variety of strategies to test binaries for vulnerabilities. It operates on the following formats:

* plaintext
* json
* csv
* xml
* jpg

# The infrastructure

The main code starts in `harness.py`, which calls a `run()` function whose purpose is to run all tests. The `run()` function iterates through the programs and tries to break them one by one.

* Firstly it determines the file type, according to which it executes appropriate commands like reading in a file and setting up appropriate data structures. One data structure we use is a container to represent the types of each cell of each input, for example the type of each value in the JSON object. This type could be an `INT` or a `STRING`.

* For JPG we simply work with the bytes of the file after reading and opening the file as an image object

* The program uses a unified pipeline for all file types which works as follows:

  * Firstly, we create a data structure which holds all the data types of constituent parts of the original data structure, so that we know how to fuzz the individual fields and what produces semi-valid input

  * Then we create a central fuzz processor depending on the file type of the input

    * this fuzz processor iterates through the constituent generators in a round robin format, giving equal weightage to a variety of types of attacks without giving too much weightage to a single type of attack

  * Then the program enters a while True loop where it iterates through each element of the central fuzzer

  * The program tries to convert the fuzzer output to a format suitable for input into the corresponding binary

  * The program determines the input type of the binary input

  * Then the program is run with this input and is monitored for segfaults and crashes
    * We have implemented a simple timeout mechanism where if a program hangs for more than 1 second, we terminate the program

  * If the time to look for a valid crash for a specific binary exceeds the time limit or the central fuzzer generator runs out of inputs, we move on to the next program

* We describe the fuzzing processor's architecture in more detail in the next section

* We describe the mutations in more detail in the *mutations* section

# Fuzzing generators architecture

![logger_diagram](./field_fuzzer.png)
![logger_diagram](./jpeg_fuzz_processing.png)
![logger_diagram](./xml_fuzz_processing.png)

Based on the above diagrams, the central fuzz processing generators call constituent generators at various levels. The JSON, CSV and plaintext fuzzers call the field fuzzer, which then calls integer and string fuzzing generators.

* Integer mutations include special known ints, in decimal, hex and binary form
* String mutations include buffer overflows and format string payloads
* String mutations also include special techniques like injection payloads from SQL Injection

The XML fuzzer calls several XML mutation generators like:

* modifying tags
* modifying inner text
* modifying attributes
* Modifying depth of nested structures (exceeding max depth)
* Modifying breadth of child nodes (exceeding max breadth to test memory limits)
* The attribute generator calls sub generators as in the diagram above

The JPG fuzzer defines various areas of importance in the fuzzer, called markers like the

* Start of image
* quantization table
* start of frame
* etc...

The JPG fuzzer main strategy is to:

* randomly flip bytes *within* regions specified by the markers
* introduce buffer overflows *within* regions specified by the markers
* repeat marker bytes in place
* repear marker bytes at the end
* delete marker bytes

# Mutations

In this section, we describe the mutations used in our fuzzing process. These mutations are either called by the `field_fuzzer()` function or directly by modules such as `csv_parser.py`, which calls the repeated keywords function.

## Overview

This fuzzer employs diverse mutation functions to test for vulnerabilities in integer handling, buffer management, and structured data parsing. Each mutation type targets specific weaknesses, such as boundary conditions, buffer overflow, and format specifier handling. The `load_and_mutate_xml()` function applies these mutations to XML data and tests them on a target C program.

## Nearby Integers and Special Integer Mutations

* `nearby_ints(number: int, extent: int)`:
  * Generates integers near the provided number, within a specified range. This is useful for testing boundary conditions close to specific integer values.

* `nearby_special_ints(extent: int)`:
  * Generates integers near special values defined in `SPECIAL_INTS`. These values include common boundary integers like 0xFFFFFFFF, powers of 2, and other notable numbers.

* `random_ints(count: int, scope: int, signed: bool)`:
  * Produces a defined number of random integers. If `signed` is `True`, both positive and negative values within the scope are generated.

## Integer to X Conversions

These functions convert integers into byte-string formats such as regular strings, hexadecimal, or endian representations. Some functions also include buffer overflow mutations.

* `to_str(ints_input: Optional[List[int]])`:
  * Converts a list of integers into their byte-string representation. If no input is provided, it defaults to using `SPECIAL_INTS`.

* `to_hex(ints_input: Optional[List[int]])`:
  * Converts integers to a hexadecimal byte-string format, ideal for testing hexadecimal data handling.

* `to_endian(ints_input: Optional[List[int]], order: str)`:
  * Converts integers into byte representations, supporting both little-endian and big-endian formats. This function tests how systems manage different byte orders.

## Buffer Overflow Mutations

These functions generate buffer overflows by appending large character sequences to strings or integer-converted data, helping to identify vulnerabilities related to buffer size limitations.

* `buffer_overflow_mutation()`:
  * Creates sequences of 'A' characters in exponentially increasing lengths (128 bytes to 65536 bytes) to test for buffer overflow vulnerabilities.

* `nearby_special_ints_add_buf(extent: int)`:
  * Combines nearby integer values with buffer overflow mutations. Converts integers to bytes and appends buffer overflow strings for testing.

* `to_str_add_buf(ints_input: Optional[List[int]])`:
  * Converts integers to strings and appends buffer overflow sequences, testing how string-handling routines cope with excessive input.

* `to_hex_add_buf(ints_input: Optional[List[int]])`:
  * Converts integers to hexadecimal format and appends buffer overflow strings, useful for hexadecimal input vulnerabilities.

## Keyword Repetition Mutations

These functions mutate input by repeating certain parts of it (e.g., headers or specific keywords) to examine how the system handles repeated patterns.

* `repeat_header(sample_input: bytes, keywords: List[bytes])`:
  * Repeats the header section of a CSV input multiple times, testing the handling of repeated data in structured file formats.

* `repeat_last_keyword(input: List[str], keywords: List[str])`:
  * Repeats the last keyword from a list of strings multiple times, testing how repeated fields or values affect structured data handling.

## XML-Specific Mutations

For XML files, these mutations apply changes directly to XML structure and attributes to test how programs manage malformed or unusual XML data.

* `xml_tag_mutation(xml_content: bytes)`:
  * Mutates XML tag names to test how the system handles unusual or malformed tags.

* `xml_attr_mutation(xml_content: bytes)`:
  * Alters XML attributes, targeting vulnerabilities in attribute parsing and handling.

* `xml_text_mutation(xml_content: bytes)`:
  * Modifies text content within XML tags to examine how text alterations affect XML parsing.

* `xml_nested_mutation(xml_content: bytes)`:
  * Duplicates nested XML structures to create deeply nested patterns, testing the system’s resilience to complex nesting.

## Format Specifier and Boundary Value Mutations

These mutations inject common format specifiers, long format strings, and boundary values into data to simulate format string vulnerabilities and boundary issues.

* `data_injection(data: bytes)`:
  * Injects format specifiers for targeting SQL Injection, XSS, command injection, path traversal, and XXE vulnerabilities. These payloads test how different formats and encodings, including Unicode, are handled.

* `boundary_value_injection(data: bytes)`:
  * Injects boundary values like `\x00`, `\xFF`, and `\x7F` into data to test how programs handle such values.

* `format_injection(data: bytes)`:
  * Inserts standard format specifiers (e.g., `%s`, `%d`, `%x`) into byte sequences to test for format string vulnerabilities.

* `long_format_specifier(data: bytes)`:
  * Injects extended format specifiers, such as `%1000x`, into byte sequences to check for handling of unusually large format specifiers.

# Log

### Logger diagram

![logger_diagram](./logger%20diagram.png)
`logger.py` : Create and set up the log file with configuration depending on sys.argv (log file flag type)

`fuzzer.log` : stored log file for the fuzzer

`harness.py` : creates log and stores it in fuzzer.log file

### Details of Log File format

```
format='(%(asctime)s) %(levelname)s:%(pathname)s-%(lineno)d:%(message)s
```

* **%(asctime)s**: time when log is created
* **%(levelname)s**: level of log *(NOTSET=0, DEBUG=10, INFO=20, WARN=30, ERROR=40, and CRITICAL=50)*
* **%(pathname)s**: path of the file where the log is created
* **%(lineno)d**: line number where the log is created
* **%(message)s**: detailed log message

# Fuzzer statistics details

We keep information pertaining to the statistics in the following global dictionary found in `harness.py`:

```python
statistics = {
     # Statistics of fuzzer - fuzzer statistics variables
    "fuzzer_attempt": 0,
    "fuzzer_success": 0,
    "fuzzer_success_rate": 0
}
```

These values are then used to compare the number of crashes to the number of attempts made by the fuzzer, yielding the current hit rate.

Every time we successfully find a valid crash due to vulnerability, we will put this fuzzer success rate on the stdout so that user can follow the track of the process.

# Memory resetting

There were two different approaches that we attempted in order to implement memory resetting, namely

* running the target binary in a virtual machine, and
* injecting a fork server into the target binary (à la [american fuzzy lop](https://lcamtuf.coredump.cx/afl/) ).

## Issues with virtualisation

After some attempts and research into the first method, we noticed several issues.

Firstly, signalling the hypervisor to take a snapshot would be challenging to do, given the strict boundaries enforced by the virtual machine. As a consequence, any method for the guest to notify the host incurs a notable delay, which may introduce some unwanted state to the process.

Virtualisation also has its overheads, which will accumulate rapidly if we were to parallelise the fuzzing process.

## Issues with forkserveer

The idea of a forkserver originated from [american fuzzy lop](https://lcamtuf.blogspot.com/2014/10/fuzzing-binaries-without-execve.html). In short, the idea is to

* inject a shim into the target binary, which would stop the execution at some arbitrary point (*e.g.* `main()`), after which it would
* wait for a signal from the fuzzer, upon which it would fork itself.

Since a process' memory is not entirely copied upon forking, but instead being copy-on-write, the overhead of this ends up being smaller than that of `execve()`.

It is not conceptually difficult; the shim itself could be something that, say, wraps around `fgets()` and other input-related functions and calls the forkserver to wait. The difficulty lies in writing the shim in assembly. In the end, we end up choosing to forgo this due to time constraints.

# Code coverage

The implementation of a code coverage tracking utility can be broken down into two parts, namely

* finding all the execution paths that exists in the binary, and
* finding which execution paths were taken throughout the fuzzing process.

## Finding all the execution paths

To find all the possible execution paths, we used the [r2pipe](https://book.rada.re/scripting/r2pipe.html) library to interact with [radare2](https://rada.re/n/), allowing us to extract information regarding all of the basic blocks in a given function. This includes

* the address where it jumps to, if an *unconditional* jump exists, or
* an address where it jumps to if a condition succeeds and another if it fails, if a *conditional* jump exists.

This allows us to reconstruct the control flow graph of a given function. Extending this to the entire program entails recursively repeating this process on any function the current function calls.

With this graph, we can find 'dead ends', *i.e.* vertices without any outward edges, and perform a depth-first search to find all the possible paths that can be taken from the starting block to these dead ends, which would yield us all the possible execution paths.

## Finding the paths taken during fuzzing

This is somewhat more challenging, especially when taking the execution time into account. Our planned approach was to attach instrumentation into the running process, either directly with `ptrace()` or by leveraging GDB or radare2. We could then insert a breakpoint at the start of every building block that triggers a logging mechanism to record which blocks were visited during execution. This, however, introduces the overhead incurred by these breakpoints, as it would slow down execution by nature.

## Some miscellaneous issues

Dependencies were a challenge for this. `graph_tool`, which requires the use of Conda instead of virtualenv, which took a while to figure out. Activating these virtual environments inside the Docker container were also challenging to figure out.

There also exists a library called `graph_tool` (without an 's'), which caused some confusion.

# Bugs that can be found using moo-deng fuzzer

* buffer overflow
* format string
* bit/byte flip
* integer mutations
* keyword mutations
* special values

# Possible improvements suggestion

**Log**

* Adding vulnerability type and file extension type to log message was our plan, but couldn't finish it due to time constraint.

**Mutation**

* integer overflow/underflow is not detectable in our fuzzer

**Harness**

* (Statistics part) Could’ve made visualisation of the statistics, Potential of race conditions on counting numbers in statistics dictionary if we use multithread

**Memory Resetting**

* mentioned it in previous section

**Implementation of PDF + ELF**

* due to time constraint, we couldn't implement it but we have a scratch of pdf fuzzer implementation
