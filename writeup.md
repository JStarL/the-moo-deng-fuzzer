# Authors
z5280740 - Jibitesh Saha

z5441928 - Li Li

z5437039 - Antheo Raviel Santosa

z5408331 - Halliya Hyeryeon UM

# How to build and run the Docker container

* `docker build -t comp6447-fuzzer .`
* `docker run -it comp6447-fuzzer`

## Docker command lines to use..
```
docker build -t $IMAGE_NAME . # build the docker image
docker run -it $IMAGE_NAME $CONTAINER_NAME # instantiates a new container from the image and run the default command
docker exec -it $CONTAINER_NAME # use an existing container and run it 
```

# Fuzzer

The fuzzer designed so far is an inital attempt at creating an appropriate, extensible infrastructure which can be used to create a full fledge black box testing system. It is elementary, in the sense that there are a few mutations elaborated on under the *Mutations* section below, and it only caters to JSON and CSV files, as per the requirements of the Mid-point checkin.

# The infrastructure

The main code starts in `harness.py`, which calls a `run()` function whose purpose is to run all tests. The `run()` function iterates through the programs and tries to break them one by one. Firstly it determines the file type, according to which it executes appropriate commands like reading in a file and setting up appropriate data structures. One data structure we use is a container to represent the types of each cell of each input, for example the type of each value in the JSON object. This type could be an `INT` or a `STRING`.

The core of the program are a series of python generator functions which act as fuzzer input generators. The `run()` function creates a json fuzz processor and a csv fuzz processor for JSON and CSV inputs respectively, we perform fuzzing operations. The json fuzz processor does a round robin of fuzzing each field of the json object using a variety of mutations described below under the *mutations* section. The csv fuzz processor first uses repeated keyword techniques for fuzzing before using the same field fuzzing techniques in a round robin format to ensure even fuzzing distribution.

# Mutations

In this section, we describe the mutations that we have used. These mutations have been linked to the `field_fuzzer()` function, or have been directly called by the caller, like the `csv_parser.py` calling the repeated keywords function.

## Nearby Integers and Special Integer Mutations

* `nearby_ints(number: int, extent: int)`:
    * Generates integers near the provided number, within a range defined by extent. Useful for testing boundary conditions near specific integer values.

* `nearby_special_ints(extent: int)`:
    * Generates integers close to special values listed in SPECIAL_INTS. These special integers include boundary values like 0xFFFFFFFF, powers of 2, and other notable numbers.

* `random_ints(count: int, scope: int, signed: bool)`:
    * Generates a specified number of random integers. If signed is true, both positive and negative values are generated within the defined scope.

## Integer to X Conversions

These functions convert integers to byte-string formats such as regular strings, hexadecimal, or endian byte representations. Some functions also append buffer overflow mutations to these strings.

* `to_str(ints_input: Optional[List[int]])`:
    * Converts a list of integers into their string representation in bytes. If no input is provided, it defaults to using SPECIAL_INTS.

* `to_hex(ints_input: Optional[List[int]])`:
    * Converts integers to their hexadecimal byte-string representation, which is useful for testing scenarios that involve hexadecimal input formats.

* `to_endian(ints_input: Optional[List[int]], order: str)`:
    * Converts integers to their byte representations, either in little-endian or big-endian format. This can be used to test how systems handle byte ordering differences.

## Buffer Overflow Mutations

This group of functions focuses on generating buffer overflows by appending large sequences of characters to existing strings or integer-converted data.

* `buffer_overflow_mutation()`:
    * Generates sequences of 'A' characters with exponentially increasing lengths to test for buffer overflow vulnerabilities. The sizes of these sequences range from 128 bytes to 65536 bytes.

* `nearby_special_ints_add_buf(extent: int)`:
    * Combines nearby integers with buffer overflow mutations. It converts the integers to bytes and appends buffer overflow strings for testing.

* `to_str_add_buf(ints_input: Optional[List[int]])`:
    * Converts integers to strings and appends buffer overflow mutations, allowing for testing string-handling routines with potential buffer overflows.

* `to_hex_add_buf(ints_input: Optional[List[int]])`:
    * Converts integers to hexadecimal format and appends buffer overflow sequences, used for testing hexadecimal input vulnerabilities.

## Keyword Repetition Mutations

These functions focus on mutating input by repeating certain portions of the input, either headers or specific keywords, to test how the system handles repeated patterns.

* `repeat_header(sample_input: bytes, keywords: List[bytes])`:
    * Repeats the header section of the CSV input multiple times. This is useful for testing how repeated data is handled in structured file formats.

* `repeat_last_keyword(input: List[str], keywords: List[str])`:
    * Repeats the last keyword from a list of strings multiple times. This can test how systems handle repeated fields or values within structured data.

