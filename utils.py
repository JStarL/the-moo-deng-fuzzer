from enum import Enum
from typing import Generator
from mutations.integer_mutations import nearby_special_ints, to_str, random_ints, nearby_special_ints_add_buf
from mutations.buffer_overflow import buffer_overflow_mutation
from mutations.bit_flip import random_partial_flip
from mutations.format_str import format_injection, boundary_value_injection, long_format_specifier, data_injection
from logger import fuzzer_logger

class FieldType(Enum):
    INTEGER = int,
    FLOAT = float,
    STRING = str,
    BYTES = bytes,
    EMPTY = None

def determine_input_type(input: any) -> FieldType:

    if input is None or isinstance(input, str) and len(input) == 0:
        return FieldType.EMPTY

    if isinstance(input, int):
        return FieldType.INTEGER
    
    if isinstance(input, float):
        return FieldType.FLOAT

    if isinstance(input, str):
        try:
            num = int(input)
            return FieldType.INTEGER
        except:
            # Not an int, try float
            try:
                num = float(input)
                return FieldType.FLOAT
            except:
                # Neither float nor int
                pass
    if isinstance(input, bytes):
        try:
            string = input.decode('utf-8')
            return determine_input_type(string)
        except:
            return FieldType.BYTES

    if isinstance(input, bytes):
        return FieldType.BYTES
    else:
        return FieldType.STRING

def integer_fuzzer():
    yield from nearby_special_ints_add_buf(10)
    yield from nearby_special_ints(10)
    yield from random_ints(528, 2**64, True)
    yield from random_ints(528, 2**64, False)


def float_fuzzer():
    lst = [1.2, 2.3, 4.5, 5.6]
    for i in lst:
        yield i

def field_fuzzer(field_type: FieldType, field_name: str, field_value: any) -> Generator[any, None, None]:
    
    # fuzzer_logger.debug('Start field fuzzer: ' + f'field_type: {field_type}' + f'field_name: {field_name}' + f'field value: {field_value}')

    fuzzers = []

    if field_type == FieldType.INTEGER:
        
        fuzzers.append(integer_fuzzer())
        fuzzers.append(buffer_overflow_mutation())

    elif field_type == FieldType.FLOAT:
       
        fuzzers.append(float_fuzzer())
        fuzzers.append(buffer_overflow_mutation())

    elif field_type == FieldType.STRING:
        
        fuzzers.append(to_str())
        fuzzers.append(buffer_overflow_mutation())
        # fuzzers.append(random_partial_flip(field_value))

        if isinstance(field_value, str):
            field_value_mod = field_value.encode('utf-8')
        else:
            field_value_mod = field_value

        # fuzzers.append(random_combined_injection(field_value_mod))
        fuzzers.append(format_injection(field_value_mod))
        fuzzers.append(data_injection(field_value_mod))
        fuzzers.append(long_format_specifier(field_value_mod))
        fuzzers.append(boundary_value_injection(field_value_mod))
        fuzzers.append(random_partial_flip(field_value_mod))

    elif field_type == FieldType.BYTES:

        fuzzers.append(random_partial_flip(field_value))

    i = 0
    while len(fuzzers) > 0:
        if i >= len(fuzzers):
            i = 0
        
        try:
            yield next(fuzzers[i])
        except StopIteration:
            fuzzers.pop(i)
            continue

        i += 1    
    
    # fuzzer_logger.debug(f"End field fuzzer: Fuzzing {field_name} is complete")

'''
def determine_input_type_old(string: str) -> FieldType:

    if string is None or len(string) == 0:
        return FieldType.EMPTY

    try:
        int(string)
        return FieldType.INTEGER
    except:
        pass

    return FieldType.STRING
'''
