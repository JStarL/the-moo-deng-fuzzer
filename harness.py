from json_parser import read_json_input, process_json, json_fuzz_processor
from csv_parser import read_csv_file, process_csv, csv_fuzz_processor
from jpeg_parser import read_jpg_file, process_jpeg, jpeg_fuzz_processor
from plaintext_parser import read_txt_file, process_txt, write_binary_input, txt_fuzz_processor
from xml_parser import read_xml_file, process_xml, xml_fuzz_processor
import json
import io
import sys
import csv
import xml.etree.ElementTree as xml
import subprocess
import time
from PIL import Image
from enum import Enum
from typing import List
from logger import fuzzer_logger

programs = [
    # './binaries/json1',
    # './binaries/json2',
    # './binaries/my_json'
    # './binaries/csv1',
    # './binaries/csv2',
    # './binaries/jpg1',
    './binaries/my_jpeg'
    # './binaries/plaintext1',
    # './binaries/plaintext2',
    # './binaries/plaintext3',
    # './binaries/xml1',
    # './binaries/xml2',
    # './binaries/xml3',
]
inputs = [
    # './example_inputs/json1.txt',
    # './example_inputs/json2.txt',
    # './example_inputs/my_json.txt'
    # './example_inputs/csv1.txt',
    # './example_inputs/csv2.txt'
    # './example_inputs/jpg1.txt',
    './example_inputs/my_jpeg.txt',
    # './example_inputs/plaintext1.txt',
    # './example_inputs/plaintext2.txt',
    # './example_inputs/plaintext3.txt',
    # './example_inputs/xml1.txt',
    # './example_inputs/xml2.txt',
    # './example_inputs/xml3.txt',
]

class FileType(Enum):
    JSON = 'json'
    CSV = 'csv'
    JPEG = 'jpeg'
    XML = 'xml'
    TXT = 'txt'
    NULL = 'null'


def run_program(prog_path: str, input: str | bytes, mode: str = 'TEXT', timeout=0.8) -> bool:
    '''
    True -> Exploit discovered
    False otherwise
    '''

    try:
        if mode == 'TEXT':
            result = subprocess.run(prog_path, timeout=timeout, input=input, text=True, universal_newlines=True, stdout=subprocess.PIPE,
                                    stderr=subprocess.PIPE)
        elif mode == 'BINARY':
            result = subprocess.run(prog_path, timeout=timeout, input=input, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    except subprocess.TimeoutExpired as e:
        fuzzer_logger.debug(f'Program {prog_path} timed out')
        return False

    exit_codes = {
        -11: 'segfault',
        # -6: 'abort',
        -5: 'sigtrap',
        -3: 'abort',
        134: 'abort'
    }
    # print(f'Ran program: {prog_path}, got this result: {result.returncode}')
    if result.returncode in exit_codes.keys():
        # print(f'Exploit discovered: prog_name = {prog_path}, input = {input}, mode = {mode}')
        fuzzer_logger.critical(f'Exploit Return Code: {result.returncode}')
        return True

    fuzzer_logger.debug(f'Normal Return Code: {result.returncode}')
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
            f.write(input)


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
                # print('data:', data)
                if len(data) == 0:
                    # print('len of data == 0')
                    raise Exception
                field_count = len(csv_reader.fieldnames)
                if any(len(row) != field_count for row in data):
                    raise Exception
                
                # Check if there are no commas in the file
                # This will be the case when there is only a single
                if len(data[0].keys()) == 1:
                    raise Exception
                return FileType.CSV
            elif type == FileType.XML:
                f = open(filepath, 'r')
                file_string = f.read()
                xml.parse(filepath)
                return FileType.XML

        except:
            continue

    return FileType.TXT
        

def run():
    for i, program in enumerate(programs):
        start_time = time.time()
        fuzzer_logger.debug(f"Program[{i}] = {program} is executing")
        file_type = determine_file_type(inputs[i])
        fuzzer_logger.debug(f'the file inputs[{i}] has file type: {file_type}')
        if file_type == FileType.NULL:
            fuzzer_logger.critical(f'There was an error determining the filetype, the file {inputs[i]} did not match any format')
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
            elif file_type == FileType.TXT:
                file_input = read_txt_file(inputs[i])
            elif file_type == FileType.XML:
                file_input = read_xml_file(inputs[i])
            
            if file_input is None:
                fuzzer_logger.critical(f"Couldn't read in file input for {inputs[i]} of file_type {file_input}")
                break
            else:
                fuzzer_logger.debug(f'file input: {file_input}')

            # 2) Extract data types of data structures within file

            file_data_types = None

            if file_type == FileType.JSON:
                file_data_types = process_json(file_input)
            elif file_type == FileType.CSV:
                file_data_types = process_csv(file_input)
            elif file_type == FileType.JPEG:
                file_data_types = process_jpeg(file_input)
            elif file_type == FileType.TXT:
                file_data_types = process_txt(file_input)
            elif file_type == FileType.XML:
                file_data_types = process_xml(file_input)
                # print(file_data_types)
                # sys.exit()
            if file_data_types is None:
                fuzzer_logger.critical(f"Couldn't extract data structure types for {inputs[i]}")
                break
            else:
                fuzzer_logger.debug(f'file data types: {file_data_types}')

            # 3) Initialise fuzzer for respective type of file

            fuzzer = None

            if file_type == FileType.JSON:
                fuzzer = json_fuzz_processor(file_input, file_data_types)
            elif file_type == FileType.CSV:
                fuzzer = csv_fuzz_processor(file_input, file_data_types)
            elif file_type == FileType.JPEG:
                fuzzer = jpeg_fuzz_processor(file_input, file_data_types)
            elif file_type == FileType.TXT:
                fuzzer = txt_fuzz_processor(file_input, file_data_types)
            elif file_type == FileType.XML:
                fuzzer = xml_fuzz_processor(file_input, file_data_types)
            
            if fuzzer is None:
                fuzzer_logger.critical(f"Couldn't create fuzzer for {inputs[i]}")
                break
            else:
                fuzzer_logger.debug(f'Fuzzer: {fuzzer}')

            complete = False

            while True:

                curr_time = time.time()

                if curr_time - start_time >= 75:
                    fuzzer_logger.critical(f'Could not exploit {program} in time')
                    complete = True
                    break

                # 4) Get next mutated input from fuzzer

                try:
                    mod_input = next(fuzzer)
                    if isinstance(mod_input, bytes) or isinstance(mod_input, str):
                        fuzzer_logger.debug(f'the modified input: {mod_input[:20]}')
                    elif isinstance(mod_input, int):
                        fuzzer_logger.debug(f'the modified input: {mod_input}')


                except StopIteration:
                    print('mod_input: {}'.format(mod_input))

                    print(f'Program {programs[i]}: NOT exploited, going to next...')
                    fuzzer_logger.critical(f'Program: {programs[i]}: NOT exploited')
                    complete = True
                    # continue
                    break
                
                # 5) Convert mutated input into a format which can be input into binary

                binary_input = None

                if file_type == FileType.JSON:
                    binary_input = json.dumps(mod_input).encode()
                elif file_type == FileType.CSV:
                    binary_input = write_csv_string(mod_input)
                elif file_type == FileType.JPEG:
                    binary_input = mod_input
                elif file_type == FileType.TXT:
                    # print('mod_input:', mod_input)
                    binary_input = write_binary_input(mod_input)
                elif file_type == FileType.XML:
                    # binary_input = write_xml_input(mod_input)
                    binary_input = mod_input

                if binary_input is None:
                    fuzzer_logger.critical(f"Couldn't convert mutated fuzzer output into input for {inputs[i]}")
                    complete = True
                    break
                else:
                    if isinstance(binary_input, str) or isinstance(binary_input, bytes):
                        fuzzer_logger.debug(f'Binary input: {binary_input[:20]}')
                    else:
                        fuzzer_logger.debug(f'Binary input {binary_input}')
                

                bin_mode = 'TEXT'

                if file_type == FileType.JSON:
                    bin_mode = 'BINARY'
                elif file_type == FileType.CSV:
                    bin_mode = 'TEXT'
                elif file_type == FileType.JPEG:
                    bin_mode = 'BINARY'
                elif file_type == FileType.TXT:
                    bin_mode = 'BINARY'
                elif file_type == FileType.XML:
                    bin_mode = 'BINARY'
                
                fuzzer_logger.debug(f'Running program {program}...')
                exploit_found = run_program(programs[i], binary_input, mode=bin_mode)
                if exploit_found:
                    write_bad_file(binary_input, programs[i], bin_mode)
                    print(f'Program {programs[i]}: EXPLOITED, time:{time.time()-start_time} going to next...')
                    fuzzer_logger.critical(f'Program {programs[i]}: EXPLOITED, time: {time.time()-start_time} ')
                    complete = True
                    break

                prev_mod_input = mod_input
                

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
