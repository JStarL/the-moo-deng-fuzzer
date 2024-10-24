from json_parser import read_json_input, process_json, json_fuzz_processor
from csv_parser import read_csv_file, process_csv, csv_fuzz_processor
import json
import io
import csv
import subprocess
from enum import Enum
from typing import List


programs = ['./binaries/binaries/json1', './binaries/binaries/csv1']
inputs = ['./binaries/example_inputs/json1.txt', './binaries/example_inputs/csv1.txt']

class FileType(Enum):
    JSON = 'json'
    CSV = 'csv'

def run_program(prog_path: str, input: str | bytes, mode: str = 'TEXT') -> bool:
    '''
    True -> Exploit discovered
    False otherwise
    '''
    
    if mode == 'TEXT':

        result = subprocess.run(prog_path, input=input, text=True, universal_newlines=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    elif mode == 'BINARY':
        result = subprocess.run(prog_path, input=input, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    
    print(f'Ran program: {prog_path}, got this result: {result.returncode}')
    if result.returncode == -6 or result.returncode == -11:
        print(f'Exploit discovered: prog_name = {prog_path}, input = {input}, mode = {mode}')
        return True
    
    return False

def write_csv_string(data: List[List[str]]) -> str:
    output = io.StringIO()
    csv_writer = csv.writer(output)
    for row in data:
        csv_writer.writerow(row)
    
    return output.getvalue()

def write_bad_file(input: str | bytes, prog_path: str, mode: str = 'TEXT') -> None:
    # Write to file
    bad_filename = './binaries/bad_inputs/bad_' + prog_path.split('/')[-1] + ('.txt' if mode == 'TEXT' else '.bin')
    if mode == 'TEXT':
        with open(bad_filename, 'w') as f:
            f.write(input)
    else:
        with open(bad_filename, 'wb') as f:
            f.write()


def determine_file_type(filepath: str) -> FileType:
    with open(filepath, 'r') as f:
        file_string = f.read()
    
    try:
        json.loads(file_string)
        return FileType.JSON
    except:
        return FileType.CSV

def run():
    for i, program in enumerate(programs):
        file_type = determine_file_type(inputs[i])
        exploit_found = False
        while True:

            if file_type == FileType.JSON:
                
                json_input = read_json_input(inputs[i])
                json_type = process_json(json_input)
                gen = json_fuzz_processor(json_input, json_type)

                try:
                    json_mod = next(gen)
                except StopIteration:
                    print(f'Program {programs[i]} not exploited, going to next...')
                    break

                print('json_mod:', json_mod)
                json_string = json.dumps(json_mod)

                exploit_found = run_program(programs[i], json_string, mode='TEXT')
                if exploit_found:
                    write_bad_file(json_string, programs[i], 'TEXT')
                    print(f'Program {programs[i]} exploited, going to next...')

                if exploit_found:
                    break
            
            elif file_type == FileType.CSV:

                csv_input = read_csv_file(inputs[i])
                print(csv_input)
                csv_types = process_csv(csv_input)
                print(csv_types)
                fuzzer = csv_fuzz_processor(csv_input, csv_types)

                try:
                    csv_mod = next(fuzzer)
                except StopIteration:
                    break

                print(f'CSV Mod:\nLine 1: {csv_mod[0][:10]}\nLine 2: {csv_mod[1][:10]}\nLine 3: {csv_mod[2][:10]}\nLine 4: {csv_mod[3][:10]}')
                # print('CSV String:', write_csv_string(csv_mod))
                
                csv_string = write_csv_string(csv_mod)

                exploit_found = run_program(programs[i], csv_string, mode='TEXT')

                if exploit_found:
                    write_bad_file(csv_string, programs[i], 'TEXT')
                    print(f'Program {programs[i]} exploited, going to next...')

                if exploit_found:
                    break


