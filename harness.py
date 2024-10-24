from json_parser import read_json_input, process_json, fuzz_processor
import json
import subprocess
from enum import Enum

programs = ['./binaries/binaries/json1', './binaries/binaries/csv1']
inputs = ['./binaries/example_inputs/json1.txt', './binaries/example_inputs/csv1.txt']

class FileType(Enum):
    JSON = 'json'
    CSV = 'csv'


def determine_file_type(filepath: str) -> FileType:
    with open(filepath, 'r') as f:
        file_string = f.read()
    
    try:
        json.loads(file_string)
        return FileType.JSON
    except:
        return FileType.CSV

for i, program in enumerate(programs):
    file_type = determine_file_type(inputs[i])
    
    exploit_found = False

    if file_type == FileType.JSON:
        
        json_input = read_json_input(inputs[i])
        json_type = process_json(json_input)
        gen = fuzz_processor(json_input, json_type)

        while True:
            try:
                json_mod = next(gen)
            except StopIteration:
                break

            print(json_mod)
            json_string = json.dumps(json_mod)
            result = subprocess.run(program, input=json_string, text=True, universal_newlines=True)
            # print(result.returncode)
            if result.returncode == -6 or result.returncode == -11:
                print('Exploit found, which is:', json_string)
                # Write to file
                exploit_found = True
                bad_filename = './binaries/bad_inputs/bad_' + program.split('/')[-1] + '.txt'
                with open(bad_filename, 'w') as f:
                    f.write(json_string)
                break
        
        if exploit_found:
            continue
