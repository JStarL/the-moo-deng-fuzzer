import json
import copy
from enum import Enum
from typing import Generator, Dict

class FieldType(Enum):
    INTEGER = int,
    STRING = str,
    EMPTY = None,

def read_json_input(filename: str) -> None:
    with open(filename, 'r') as f:
        json_string = f.read()
    
    print('File Contents:\n', json_string)

    global json_input
    try:
        json_input = json.loads(json_string)
        return json_input
    except json.JSONDecodeError as e:
        print(f"Failed to decode JSON: {e}")
        exit(1)

def determine_input_type_old(string: str) -> FieldType:

    if string is None or len(string) == 0:
        return FieldType.EMPTY

    try:
        int(string)
        return FieldType.INTEGER
    except:
        pass

    return FieldType.STRING

def determine_input_type(input: any) -> FieldType:

    if input is None or isinstance(input, str) and len(input) == 0:
        return FieldType.EMPTY

    if isinstance(input, int):
        return FieldType.INTEGER
    
    return FieldType.STRING

def process_json(json_input: Dict):

    json_type = copy.deepcopy(json_input)

    for key in json_input:
        # print(json_input[key])
        json_type[key] = determine_input_type(json_input[key])
    
    return json_type
    
def fuzz_processor(json_input: Dict, json_type: Dict) -> Generator[Dict, None, None]:

    keys_list = list(json_input.keys())

    generators = [json_fuzzer(json_type[key], key) for key in keys_list]

    i = 0
    while True:
        
        if i >= len(generators):
            i = 0
        
        try:
            json_input[keys_list[0]] = next(generators[i])
            yield json_input
        except StopIteration:
            generators.pop(i)
            keys_list.pop(i)
            i -= 1

        i += 1

def integer_fuzzer():
    lst = [-1,2,3,4,5]
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

def json_fuzzer(field_type: FieldType, field_name: str) -> Generator[str, None, None]:
    
    if field_type == FieldType.INTEGER:
        
        gen = integer_fuzzer()

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

# def sample():

#     lst = [i for i in range(5)]

#     for i in lst:
#         yield i
