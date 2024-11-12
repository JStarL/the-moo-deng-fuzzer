from json_parser import read_json_input, process_json, json_fuzz_processor
from csv_parser import read_csv_file, process_csv, csv_fuzz_processor
from jpeg_parser import read_jpg_file, process_jpeg, jpeg_fuzz_processor
import json
import io
import csv
import subprocess
from PIL import Image
from enum import Enum
from typing import List

programs = ['./binaries/json1', './binaries/csv1', './binaries/jpg1']
inputs = ['./example_inputs/json1.txt', './example_inputs/csv1.txt', './example_inputs/jpg1.txt']

# programs = ['/binaries/jpg1']
# inputs = ['example_inputs/jpg1.txt']

class FileType(Enum):
    JSON = 'json'
    CSV = 'csv'
    JPEG = 'jpeg'
    XML = 'xml'
    NULL = 'null'


def run_program(prog_path: str, input: str | bytes, mode: str = 'TEXT') -> bool:
    '''
    True -> Exploit discovered
    False otherwise
    '''

    if mode == 'TEXT':
        result = subprocess.run(prog_path, input=input, text=True, universal_newlines=True, stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE)
    elif mode == 'BINARY':
        result = subprocess.run(prog_path, input=input, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    # print(f'Ran program: {prog_path}, got this result: {result.returncode}')
    if result.returncode == -6 or result.returncode == -11:
        # print(f'Exploit discovered: prog_name = {prog_path}, input = {input}, mode = {mode}')
        print('Return Code:', result.returncode)
        return True

    # print('Return Code:', result.returncode)
    return False


def write_csv_string(data: List[List[str]]) -> str:
    output = io.StringIO()
    csv_writer = csv.writer(output)
    for row in data:
        csv_writer.writerow(row)

    return output.getvalue()

def write_jpeg_input(img_mod) -> bytes:
    # try:
    #     return img_mod.tobytes()
    # except:
    #     print("Couldn't convert image to bytes")
    #     return b'None'
    
    img_byte_arr = io.BytesIO()
    try:
        img_mod.save(img_byte_arr, format='JPEG')
    except:
        print("Couldn't save img")
        return b'None'
    img_byte_arr = img_byte_arr.getvalue()
    return img_byte_arr

def write_bad_file(input: str | bytes, prog_path: str, mode: str = 'TEXT') -> None:
    # Write to file
    bad_filename = './fuzzer_output/bad_' + prog_path.split('/')[-1] + '.txt'
    if mode == 'TEXT':
        with open(bad_filename, 'w') as f:
            f.write(input)
    else:
        with open(bad_filename, 'wb') as f:
            f.write()


def determine_file_type(filepath: str) -> FileType:
    
    types = [FileType.JSON, FileType.CSV, FileType.XML, FileType.JPEG]

    for type in types:
        try:
            if type == FileType.JSON:
                f = open(filepath, 'r')
                file_string = f.read()
                # print(f'Got here: {filepath}')
                json.loads(file_string)
                return FileType.JSON
            elif type == FileType.JPEG:
                Image.open(filepath)
                return FileType.JPEG
            elif type == FileType.CSV:
                file = open(filepath, 'r', newline='')
                csv_reader = csv.DictReader(file)
                data = list(csv_reader)
                if len(data) == 0:
                    raise Exception
                field_count = len(csv_reader.fieldnames)
                if any(len(row) != field_count for row in data):
                    raise Exception
                return FileType.CSV
            elif type == FileType.XML:
                f = open(filepath, 'r')
                file_string = f.read()
                # xml.loads(file_string) # also import 
                return FileType.XML

        except:
            continue

    return FileType.NULL
        

def run():
    for i, program in enumerate(programs):
        file_type = determine_file_type(inputs[i])
        if file_type == FileType.NULL:
            print(f'There was an error determining the filetype, the file {inputs[i]} did not match any format')
            continue
        exploit_found = False

        while True:

            # 1) Read file input

            file_input = None

            if file_type == FileType.JSON:
                file_input = read_json_input(inputs[i])
            elif file_type == FileType.CSV:
                file_input = read_csv_file(inputs[i])
            elif file_type == FileType.JPEG:
                file_input = read_jpg_file(inputs[i])
            
            if file_input is None:
                print(f"Couldn't read in file input for {inputs[i]} of file_type {file_input}")
                break

            # 2) Extract data types of data structures within file

            file_data_types = None

            if file_type == FileType.JSON:
                file_data_types = process_json(file_input)
            elif file_type == FileType.CSV:
                file_data_types = process_csv(file_input)
            elif file_type == FileType.JPEG:
                file_data_types = process_jpeg(file_input)
            
            if file_data_types is None:
                print(f"Couldn't extract data structure types for {inputs[i]}")
                break

            # 3) Initialise fuzzer for respective type of file

            fuzzer = None

            if file_type == FileType.JSON:
                fuzzer = json_fuzz_processor(file_input, file_data_types)
            elif file_type == FileType.CSV:
                fuzzer = csv_fuzz_processor(file_input, file_data_types)
            elif file_type == FileType.JPEG:
                fuzzer = jpeg_fuzz_processor(file_input, file_data_types)
            
            if fuzzer is None:
                print(f"Couldn't create fuzzer for {inputs[i]}")
                break

            complete = False

            while True:

                # 4) Get next mutated input from fuzzer

                try:
                    mod_input = next(fuzzer)
                except StopIteration:
                    print(f'Program {programs[i]} not exploited, going to next...')
                    complete = True
                    break
                
                # 5) Convert mutated input into a format which can be input into binary

                binary_input = None

                if file_type == FileType.JSON:
                    binary_input = json.dumps(mod_input)
                elif file_type == FileType.CSV:
                    binary_input = write_csv_string(mod_input)
                elif file_type == FileType.JPEG:
                    binary_input = write_jpeg_input(mod_input)
                
                if binary_input is None:
                    print(f"Couldn't convert mutated fuzzer output into input for {inputs[i]}")
                    complete = True
                    break
                

                bin_mode = 'TEXT'

                if file_type == FileType.JSON:
                    bin_mode = 'TEXT'
                elif file_type == FileType.CSV:
                    bin_mode = 'TEXT'
                elif file_type == FileType.JPEG:
                    bin_mode = 'BINARY'
                
                exploit_found = run_program(programs[i], binary_input, mode=bin_mode)
                if exploit_found:
                    write_bad_file(binary_input, programs[i], bin_mode)
                    print(f'Program {programs[i]} exploited, going to next...')
                    complete = True
                    break
                

            if complete: break

# The main entry point for execution
if __name__ == "__main__":
    run()

# def run_old():
#     for i, program in enumerate(programs):
#         file_type = determine_file_type(inputs[i])
#         if file_type == FileType.NULL:
#             print(f'There was an error determining the filetype, the file {inputs[i]} did not match any format')
#             continue
#         exploit_found = False
#         while True:

#             if file_type == FileType.JSON:

#                 json_input = read_json_input(inputs[i])
#                 json_type = process_json(json_input)
#                 gen = json_fuzz_processor(json_input, json_type)

#                 complete = False

#                 while True:

#                     try:
#                         json_mod = next(gen)
#                     except StopIteration:
#                         print(f'Program {programs[i]} not exploited, going to next...')
#                         complete = True
#                         break

#                     # print('json_mod:', json_mod)
#                     json_string = json.dumps(json_mod)

#                     exploit_found = run_program(programs[i], json_string, mode='TEXT')
#                     if exploit_found:
#                         write_bad_file(json_string, programs[i], 'TEXT')
#                         print(f'Program {programs[i]} exploited, going to next...')
#                         complete = True
#                         break

#                 if complete: break

#             elif file_type == FileType.CSV:

#                 csv_input = read_csv_file(inputs[i])
#                 csv_types = process_csv(csv_input)
#                 fuzzer = csv_fuzz_processor(csv_input, csv_types)

#                 complete = False

#                 while True:

#                     try:
#                         csv_mod = next(fuzzer)
#                     except StopIteration:
#                         print(f'Program {programs[i]} not exploited, going to next...')
#                         complete = True
#                         break

#                     # print(f'CSV Mod:\nLine 1: {csv_mod[0][:10]}\nLine 2: {csv_mod[1][:10]}\nLine 3: {csv_mod[2][:10]}\nLine 4: {csv_mod[3][:10]}')
#                     # print('CSV String:', write_csv_string(csv_mod))

#                     csv_string = write_csv_string(csv_mod)

#                     exploit_found = run_program(programs[i], csv_string, mode='TEXT')

#                     if exploit_found:
#                         write_bad_file(csv_string, programs[i], 'TEXT')
#                         print(f'Program {programs[i]} exploited, going to next...')
#                         complete = True
#                         break
#                 if complete: break

#             elif file_type == FileType.JPEG:

#                 img = read_jpg_file(inputs[i])

#                 img_exif_types = process_jpeg(img)

#                 fuzzer = jpeg_fuzz_processor(img, img_exif_types)

#                 complete = False

#                 while True:

#                     try:
#                         img_mod = next(fuzzer)
#                     except StopIteration:
#                         print(f'Program {programs[i]} not exploited, going to next...')
#                         complete = True
#                         break
                
#                     img_bytes = write_jpeg_input(img_mod)

#                     exploit_found = run_program(programs[i], img_bytes, mode='BINARY')

#                     if exploit_found:
#                         write_bad_file(img_bytes, programs[i], 'BINARY')
#                         print(f'Program {programs[i]} exploited, going to next...')
#                         complete = True
#                         break
#                 if complete: break

#             elif file_type == FileType.XML:
#                 pass
