from typing import Iterator
import xml.etree.ElementTree as xml
import subprocess
from mutations.buffer_overflow import buffer_overflow_mutation
from mutations.format_str import random_combined_injection, data_injection
from mutations.integer_mutations import to_str, to_hex


Mutators = [random_combined_injection,data_injection, data_injection, buffer_overflow_mutation, to_str, to_hex]


# XML tag mutation
def xml_tag_mutation(xml_content: bytes) -> Iterator[bytes]:
    try:
        root = xml.fromstring(xml_content)
    except xml.ParseError:
        return
    for mutation in (m for mutator in Mutators for m in mutator(xml_content)):
        for el in root.iter():
            el.tag = mutation.decode(errors="ignore")
            yield xml.tostring(root)


# XML attribute mutation
def xml_attr_text_mutation(xml_content: bytes) -> Iterator[bytes]:
    try:
        root = xml.fromstring(xml_content)
    except xml.ParseError:
        return
    for mutation in (m for mutator in Mutators for m in mutator(xml_content)):
        for el in root.iter():
            for attr in el.attrib:
                el.set(attr, mutation.decode(errors="ignore"))
                yield xml.tostring(root)


# XML text mutation
def xml_text_mutation(xml_content: bytes) -> Iterator[bytes]:
    try:
        root = xml.fromstring(xml_content)
    except xml.ParseError:
        return
    for mutation in (m for mutator in Mutators for m in mutator(xml_content)):
        for el in root.iter():
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
            ("attribute", xml_attr_mutation),
            ("text", xml_text_mutation)
        ]

        # Run each type of mutation
        for mutation_type, mutation_func in mutation_functions:
            for mutation_index, mutated_xml_data in enumerate(mutation_func(xml_content)):
                result_mutated = run_c_program_with_pdf(prog_path, mutated_xml_data)
                # print(xml_content)
                # print(mutated_xml_data, "\n")
                # print("C program stderr:", result_mutated.stderr.decode(errors="ignore"))

    except FileNotFoundError:
        print(f"Error: File {file_path} not found.")


# Example usage
prog_path = './xml3'  # Path to the compiled C program
input_file = 'xml3.txt'  # Path to the input XML file

load_and_mutate_xml(prog_path, input_file)
