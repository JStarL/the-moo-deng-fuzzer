from typing import Iterator
import xml.etree.ElementTree as xml
import subprocess
from mutations.buffer_overflow import buffer_overflow_mutation
from mutations.format_str import random_combined_injection, data_injection, boundary_value_injection, format_injection, \
    long_format_specifier, boundary_str_injection
from mutations.integer_mutations import to_str, to_hex
import base64

Mutators = [format_injection, long_format_specifier, data_injection, boundary_value_injection, boundary_str_injection,
            to_str, to_hex, buffer_overflow_mutation, random_combined_injection]


# XML tag mutation
def xml_tag_mutation(xml_content: bytes) -> Iterator[bytes]:
    try:
        root = xml.fromstring(xml_content)
    except xml.ParseError:
        return
    for el in root.iter():
        for mutation in (m for mutator in Mutators for m in mutator(el.tag.encode())):
            print('tag {}'.format(el.tag))
            print('mutation {}'.format(mutation))
            el.tag = mutation.decode()
            yield xml.tostring(root)


def xml_nested_mutation(xml_content: bytes, max_depth: int = 100) -> Iterator[bytes]:
    try:
        root = xml.fromstring(xml_content)
    except xml.ParseError:
        return

    current_root = root

    for depth in range(1, max_depth + 1):
        new_root = xml.Element("root")
        new_root.append(current_root)
        current_root = new_root

        # Convert current structure to string
        nested_xml = xml.tostring(current_root)
        # Yield the full XML structure
        yield nested_xml


# XML attribute mutation
def xml_attr_text_mutation(xml_content: bytes) -> Iterator[bytes]:
    try:
        root = xml.fromstring(xml_content)
    except xml.ParseError:
        return
    for el in root.iter():
        for attr in el.attrib:
            for mutation in (m for mutator in Mutators for m in mutator(attr.encode())):
                print('attr {}'.format(attr))
                print('mutation {}'.format(mutation))
                encoded_mutation = base64.b64encode(mutation).decode("ascii")
                el.set(attr, encoded_mutation)
                yield xml.tostring(root)


# XML text mutation
def xml_text_mutation(xml_content: bytes) -> Iterator[bytes]:
    try:
        root = xml.fromstring(xml_content)
    except xml.ParseError:
        return
    for el in root.iter():
        if el.text is None:
            el.text = ''
        for mutation in (m for mutator in Mutators for m in mutator(el.text.encode())):
            print('text {}'.format(el.text))
            print('mutation {}'.format(mutation))
            el.text = mutation.decode(errors="ignore")
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
            ("tag", xml_tag_mutation),
            ("attribute", xml_attr_text_mutation),
            ("text", xml_text_mutation),
            ("nest", xml_nested_mutation)
        ]

        # Run each type of mutation
        for mutation_type, mutation_func in mutation_functions:
            for mutation_index, mutated_xml_data in enumerate(mutation_func(xml_content)):
                result_mutated = run_c_program_with_pdf(prog_path, mutated_xml_data)
                # print(xml_content)
                # print(mutated_xml_data, "\n")
                print("C program stderr:", result_mutated.stderr.decode(errors="ignore"))

    except FileNotFoundError:
        print(f"Error: File {file_path} not found.")


if __name__ == "__main__":
    # Example usage
    prog_path = './xml3'  # Path to the compiled C program
    input_file = 'xml3.txt'  # Path to the input XML file

    load_and_mutate_xml(prog_path, input_file)
