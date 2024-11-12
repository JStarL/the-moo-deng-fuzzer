from enum import Enum
from typing import Generator
from mutations.integer_mutations import nearby_special_ints, to_str
from mutations.buffer_overflow import buffer_overflow_mutation


class FieldType(Enum):
    INTEGER = int,
    FLOAT = float,
    STRING = str,
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
    
    return FieldType.STRING

def integer_fuzzer():
    yield from nearby_special_ints(10)

def float_fuzzer():
    lst = [1.2, 2.3, 4.5, 5.6]
    for i in lst:
        yield i

def string_buffer_overflow():
    yield from buffer_overflow_mutation()

def string_fuzzer():
    yield from to_str()

def field_fuzzer(field_type: FieldType, field_name: str, field_value: any) -> Generator[any, None, None]:
    
    if field_type == FieldType.INTEGER:
        
        yield from integer_fuzzer()

        yield from string_buffer_overflow()

    elif field_type == FieldType.FLOAT:
       
        yield from float_fuzzer()
        
        yield from string_buffer_overflow()

    elif field_type == FieldType.STRING:
        
        yield from string_fuzzer()
    
    print(f"Fuzzing {field_name} is complete")

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
