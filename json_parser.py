import json
import copy
from typing import Generator, Dict, Iterator
from utils import FieldType, determine_input_type, field_fuzzer

def read_json_input(filename: str) -> Dict:
    with open(filename, 'r') as f:
        json_string = f.read()
    
    # print('File Contents:\n', json_string)

    try:
        json_input = json.loads(json_string)
        return json_input
    except json.JSONDecodeError as e:
        print(f"Failed to decode JSON: {e}")
        exit(1)

def process_json(json_input: Dict):

    json_type = copy.deepcopy(json_input)

    for key in json_input:
        # print(json_input[key])
        json_type[key] = determine_input_type(json_input[key])
    
    return json_type

def key_mutator(json_input: Dict) -> Iterator[Dict]:
    key_fuzzer = field_fuzzer(FieldType.STRING, 'key_fuzzer', 'test')

    while True:
        try:
            key = next(key_fuzzer)
            
            if isinstance(key, bytes):
                try:
                    key = key.decode('utf-8')
                except:
                    key = int.from_bytes(key, byteorder='little')
            
            json_input[key] = 'test'
            yield json_input
        except StopIteration:
            break

def json_fuzz_processor(json_input: Dict, json_type: Dict) -> Generator[Dict, None, None]:

    yield from key_mutator(copy.deepcopy(json_input))

    keys_list = list(json_input.keys())

    generators = [field_fuzzer(json_type[key], key, json_input[key]) for key in keys_list]

    i = 0
    while len(generators) > 0:
        
        if i >= len(generators):
            i = 0
        
        try:
            json_input[keys_list[i]] = next(generators[i])
            print(f'{keys_list[i]}: {json_input[keys_list[i]]}')
            if isinstance(json_input[keys_list[i]], bytes):
                try:
                    json_input[keys_list[i]] = json_input[keys_list[i]].decode('utf-8')
                except:
                    print("Can't convert bytes object to str")
                    json_input[keys_list[i]] = "None"
            yield json_input
        except StopIteration:
            generators.pop(i)
            keys_list.pop(i)
            i -= 1

        i += 1
