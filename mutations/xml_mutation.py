from typing import Iterator, Dict
import xml.etree.ElementTree as xml
import subprocess
from mutations.buffer_overflow import buffer_overflow_mutation
from mutations.format_str import random_combined_injection, data_injection, boundary_value_injection, format_injection, \
    long_format_specifier, boundary_str_injection
from mutations.integer_mutations import to_str, to_hex, nearby_special_intbytes
from mutations.kv_mutations import random_keys, del_keys, add_keys, update_keys, update_values
import base64

Mutators = [format_injection, long_format_specifier, data_injection, boundary_value_injection, boundary_str_injection,
            to_str, to_hex, buffer_overflow_mutation, random_combined_injection]

KV_Mutators = [random_keys, del_keys, add_keys, update_keys, update_values]
def xml_tag_mutation(xml_content: bytes) -> Iterator[bytes]:
    try:
        root = xml.fromstring(xml_content)
    except xml.ParseError:
        return

    for el in root.iter():
        print(f'tag: {el.tag}')

        # Use the element's tag if available, otherwise use the default payload
        tag_to_mutate = el.tag.encode() if el.tag is not None else ''

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


def xml_attr_mutation(xml_content: bytes) -> Iterator[bytes]:
    try:
        root = xml.fromstring(xml_content)
    except xml.ParseError:
        return

    for el in root.iter():
        original_attrib = el.attrib.copy() if el.attrib else {}

        print(f"Original attrib for tag '{el.tag}': {original_attrib}")

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
        print(f'text: {el.text}')

        # Use the element's tag if available, otherwise use the default payload
        tag_to_mutate = el.text.encode() if el.text is not None else ''

        for mutator in Mutators:
            for mutation in mutator(tag_to_mutate):

                try:
                    # Attempt to decode as UTF-8
                    el.text = mutation.decode('utf-8')
                except UnicodeDecodeError:
                    # Fallback to Base64 encoding if UTF-8 decoding fails
                    el.text = base64.b64encode(mutation).decode('ascii')

                print(f'text to mutation: {mutation}')
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
    try:
        with open(file_path, 'rb') as file:
            xml_content = file.read()

        # Define mutation functions and their descriptions
        mutation_functions = [
            # ("tag", xml_tag_mutation),
            ("attribute", xml_attr_mutation),
            # ("text", xml_text_mutation),
            # ("nest", xml_nested_mutation)
        ]

        # Run each type of mutation
        i = 0
        for mutation_type, mutation_func in mutation_functions:
            for mutation_index, mutated_xml_data in enumerate(mutation_func(xml_content)):
                i += 1
                if i % 100 == 0:
                    print('i: {}'.format(i))
                result_mutated = run_c_program_with_pdf(prog_path, mutated_xml_data)

                # print(xml_content)
                print(mutated_xml_data.decode(), "\n")
                # print("C program stderr:", result_mutated.stderr.decode(errors="ignore"))

    except FileNotFoundError:
        print(f"Error: File {file_path} not found.")


if __name__ == "__main__":
    # Example usage
    prog_path = './xml3'  # Path to the compiled C program
    input_file = 'xml0.txt'  # Path to the input XML file

    load_and_mutate_xml(prog_path, input_file)
