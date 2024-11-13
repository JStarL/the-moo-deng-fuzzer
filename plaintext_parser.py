from utils import FieldType, determine_input_type, field_fuzzer
from typing import List, Iterator

def read_txt_file(filename: str) -> bytes:
    with open(filename, 'rb') as f:
        lines = f.read()
        return lines.split(b'\n')

def process_txt(lines: List[bytes]) -> List[FieldType]:
    line_type = []

    for line in lines:
        line_type.append(determine_input_type(line))

    return line_type

def txt_fuzz_processor(lines: List[bytes], line_type: List[FieldType]) -> Iterator[bytes]:
    pass
