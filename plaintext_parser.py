from utils import FieldType, determine_input_type, field_fuzzer
from typing import List, Iterator
import copy

def read_txt_file(filename: str) -> List[bytes]:
    with open(filename, 'rb') as f:
        lines = f.read()
        return lines.split(b'\n')

def process_txt(lines: List[bytes]) -> List[FieldType]:
    line_type = []

    for line in lines:
        line_type.append(determine_input_type(line))

    return line_type

def write_binary_input(mod_input):
    for i, elem in enumerate(mod_input):
        if not isinstance(elem, bytes):
            mod_input[i] = str(elem).encode()
    
    return b"\n".join(mod_input)

def txt_fuzz_processor(lines: List[bytes], line_type: List[FieldType]) -> Iterator[List[bytes]]:
    
    fuzzers = [field_fuzzer(line_type[i], f'Line {i}', lines[i]) for i in range(len(lines))]
    i = 0
    complete = [False] * len(lines)
    complete_count = 0

    while complete_count < len(lines):

        if i >= len(fuzzers):
            i = 0
        
        if complete[i]:
            i += 1
            continue
        
        lines_mod = copy.deepcopy(lines)
        try:
            lines_mod[i] = next(fuzzers[i])
            yield lines_mod
        except StopIteration:
            complete[i] = True
            complete_count += 1

        i += 1