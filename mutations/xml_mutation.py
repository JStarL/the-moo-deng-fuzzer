import time
from typing import Iterator, Dict
import xml.etree.ElementTree as xml
import subprocess
from mutations.buffer_overflow import buffer_overflow_mutation
from mutations.format_str import data_injection, boundary_value_injection, format_injection, \
    long_format_specifier, boundary_str_injection
from mutations.integer_mutations import to_str, to_hex, nearby_special_intbytes
from mutations.kv_mutations import del_keys, add_keys, update_keys, update_values
import base64
from logger import fuzzer_logger

Mutators = [
    format_injection,
    long_format_specifier,
    data_injection,
    boundary_value_injection,
    boundary_str_injection,
    to_str, to_hex,
    buffer_overflow_mutation
]

KV_Mutators = [del_keys, update_keys, update_values, add_keys]


def xml_tag_mutation(xml_content: bytes) -> Iterator[bytes]:
    try:
        root = xml.fromstring(xml_content)
    except xml.ParseError:
        return

    for el in root.iter():
        # print(f'tag: {el.tag}')

        # Use the element's tag if available, otherwise use the default payload
        tag_to_mutate = el.tag.encode() if el.tag is not None else b''

        for mutator in Mutators:
            for mutation in mutator(tag_to_mutate):

                try:
                    # Attempt to decode as UTF-8
                    el.tag = mutation.decode('utf-8')
                except UnicodeDecodeError:
                    # Fallback to Base64 encoding if UTF-8 decoding fails
                    el.tag = base64.b64encode(mutation).decode('ascii')


                # print(f'mutation: {mutation}')
                yield xml.tostring(root)


def xml_nested_mutation(xml_content: bytes, max_depth: int = 2 ** 32) -> Iterator[bytes]:
    try:
        root = xml.fromstring(xml_content)
    except xml.ParseError:
        return

    nested_xml = "%n" * 2 ** 10

    for idx in range(1, max_depth + 1):
        nested_xml = f"<{idx}>{nested_xml}</{idx}>"

        if idx % 100000 == 0:
            yield nested_xml.encode()


def xml_attr_mutation(xml_content: bytes) -> Iterator[bytes]:
    try:
        root = xml.fromstring(xml_content)
    except xml.ParseError:
        return

    for el in root.iter():
        original_attrib = el.attrib.copy() if el.attrib else {}

        # print(f"Original attrib for tag '{el.tag}': {original_attrib}")

        for mutator in KV_Mutators:
            for mutated_attrib in mutator(original_attrib):
                el.attrib.clear()
                el.attrib.update(mutated_attrib)

                yield xml.tostring(root)

            el.attrib.clear()
            el.attrib.update(original_attrib)


# XML text mutation
def xml_text_mutation(xml_content: bytes) -> Iterator[bytes]:
    try:
        root = xml.fromstring(xml_content)
    except xml.ParseError:
        return
    for el in root.iter():
        fuzzer_logger.debug(f'xml_text_mutation: tag = {el.tag}')

        # Use the element's tag if available, otherwise use the default payload
        text_to_mutate = el.text.encode() if el.text is not None else b''

        for mutator in Mutators:
            for mutation in mutator(text_to_mutate):
                if isinstance(mutation, str) or isinstance(mutation, bytes):
                    fuzzer_logger.debug(f'mutation: {mutation[:20]}')

                try:
                    # Attempt to decode as UTF-8
                    el.text = mutation.decode('utf-8')
                except UnicodeDecodeError:
                    # Fallback to Base64 encoding if UTF-8 decoding fails
                    el.text = base64.b64encode(mutation).decode('ascii')

                # print(f'text to mutation: {mutation}')
                yield xml.tostring(root)


def run_c_program_with_pdf(prog_path, pdf_data):
    """
    Runs a compiled C program, passing the PDF data as input.

    Parameters:
    - prog_path (str): Path to the compiled C program.
    - pdf_data (bytes): PDF binary data to be tested.

    Returns:
    - result: CompletedProcess instance containing stdout and stderr from the C program.
    """
    result = subprocess.run(
        [prog_path],
        input=pdf_data,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE
    )
    return result


def load_and_mutate_xml(prog_path, file_path):
    """Load XML from a file, apply all mutations, and run each mutated version with the C program."""
    start = time.time()

    try:
        with open(file_path, 'rb') as file:
            xml_content = file.read()

        # Define mutation functions and their descriptions
        mutation_functions = [
            # ("tag", xml_tag_mutation),
            # ("attribute", xml_attr_mutation),
            ("text", xml_text_mutation),
            # ("nest", xml_nested_mutation),
        ]

        # Run each type of mutation
        for mutation_type, mutation_func in mutation_functions:
            for mutation_index, mutated_xml_data in enumerate(mutation_func(xml_content)):

                result = run_c_program_with_pdf(prog_path, mutated_xml_data)
                print(mutated_xml_data.decode())
                exit_codes = {
                    -11: 'segfault',
                    -6: 'abort',
                    -5: 'sigtrap',
                    -3: 'abort',
                    134: 'abort'
                }
                if result.returncode in exit_codes.keys():
                    print(f'time: {time.time() - start}, Exploit Return Code: {result.returncode}\n\n')
                    break
    except FileNotFoundError:
        print(f"Error: File {file_path} not found.")


if __name__ == "__main__":
    # Example usage
    # prog_path = './xml1'  # Path to the compiled C program
    # input_file = 'xml1.txt'  # Path to the input XML file
    # load_and_mutate_xml(prog_path, input_file)
    #
    # prog_path = './xml2'  # Path to the compiled C program
    # input_file = 'xml2.txt'  # Path to the input XML file
    # load_and_mutate_xml(prog_path, input_file)

    prog_path = './xml3'  # Path to the compiled C program
    input_file = 'xml0.txt'  # Path to the input XML file
    load_and_mutate_xml(prog_path, input_file)
