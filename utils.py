from enum import Enum
from typing import Generator


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
    lst = [-1,2,3,4,5]
    for i in lst:
        yield i

def float_fuzzer():
    lst = [1.2, 2.3, 4.5, 5.6]
    for i in lst:
        yield i

def string_buffer_overflow():
    lst = ['1','2','3','4','5']
    for i in lst:
        yield i

def string_fuzzer():
    lst = ['1','2','3','4','5']
    for i in lst:
        yield i

def field_fuzzer(field_type: FieldType, field_name: str, field_value: any) -> Generator[any, None, None]:
    
    if field_type == FieldType.INTEGER:
        
        gen = integer_fuzzer()

        while True:
            try:
                yield next(gen)

            except StopIteration:
                break
        
        gen = string_buffer_overflow()

        while True:
            try:
                yield next(gen)
            
            except StopIteration:
                break

    elif field_type == FieldType.FLOAT:
        gen = float_fuzzer()

        while True:
            try:
                yield str(next(gen))

            except StopIteration:
                break
        
        gen = string_buffer_overflow()

        while True:
            try:
                yield next(gen)
            
            except StopIteration:
                break
    elif field_type == FieldType.STRING:
        gen = string_fuzzer()
        while True:
            try:
                yield next(gen)
            
            except StopIteration:
                break

    
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