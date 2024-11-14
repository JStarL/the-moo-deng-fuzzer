from typing import Iterator
import xml.etree.ElementTree as xml
import copy
import subprocess
from mutations.buffer_overflow import buffer_overflow_mutation
from mutations.format_str import random_combined_injection, data_injection, boundary_value_injection
from mutations.integer_mutations import to_str, to_hex
from utils import determine_input_type, field_fuzzer
import sys

# TODO: Deep nesting
MAX_DEPTH_NEST = 150

mutators = [random_combined_injection, data_injection, boundary_value_injection, buffer_overflow_mutation, to_str, to_hex]

def read_xml_file(filepath: str):
    try:
        tree = xml.parse(filepath)
        return tree
    except:
        print(f"Couldn't parse xml file at {filepath}")
        return None
def process_xml(tree: xml.ElementTree):
    file_type_tree = copy.deepcopy(tree)
    file_type_root = file_type_tree.getroot()
    file_types = list(file_type_root.iter())

    root = tree.getroot()

    # Assume that xml tags are always strings for simplicity
    # Only determines file types for tag contents
    for index, element in enumerate(root.iter()):
        file_types[index].text = determine_input_type(element.text)
    
    return file_type_tree


# XML tag mutation
def xml_text_mutation(xml_tree: xml.ElementTree, xml_type: xml.ElementTree, type: str) -> Iterator[xml.ElementTree]:


    tree_root = xml_tree.getroot()
    tree_elems = list(tree_root.iter())
    print(tree_elems)

    fuzzers = list(tree_elems)
    complete = [False] * len(tree_elems)
    complete_count = 0

    for i, field_type in enumerate(xml_type.getroot().iter()):
        tag_val = None

        if type == 'tag':
            tag_val = tree_elems[i].tag
        elif type == 'attr':
            attr_vals = tree_elems[i].attrib.values()
            if len(attr_vals) == 0:
                complete[i] = True
                complete_count += 1
                continue
            tag_val = next(iter(tree_elems[i].attrib.values()), b'None')
        elif type == 'text':
            tag_val = tree_elems[i].text
        
        fuzzers[i]  = field_fuzzer(field_type.text, tree_elems[i].tag, tag_val)

    i = 0
    while complete_count < len(tree_elems):
        
        if i >= len(tree_elems):
            i = 0
        
        if complete[i]:
            i += 1
            continue

        try:
            mutation = next(fuzzers[i])
        except StopIteration:
            print(f'Finished field fuzzer at {i}')
            complete[i] = True
            complete_count += 1
            i += 1
            continue
        if type == "tag":
            tree_elems[i].tag = mutation.decode(errors="ignore")
        elif type == "attr":
            for attr in tree_elems[i].attrib:
                tree_elems[i].set(attr, mutation.decode(errors="ignore"))
        elif type == "text":
            tree_elems[i].text = mutation.decode(errors="ignore")

        yield xml_tree

        i += 1

    # for el in tree_root.iter():

    #     init_data = None

    #     if type == 'tag':
    #         init_data = el.tag
    #     elif type == 'attr':
    #         init_data = next(iter(el.attrib.values()), None)
    #     elif type == 'text':
    #         init_data = el.text

    #     current_mutators = [
    #         random_combined_injection(init_data),
    #         data_injection(init_data),
    #         boundary_value_injection(init_data),
    #         buffer_overflow_mutation(),
    #         to_str(),
    #         to_hex()
    #     ]

    #     i = 0
    #     while len(current_mutators) > 0:

    #         if i >= len(current_mutators):
    #             i = 0
            
    #         try:
    #             mutation = next(current_mutators[i])
    #         except:
    #             current_mutators.pop(i)
    #             continue

    #         if type == "tag":
    #             el.tag = mutation.decode(errors="ignore")
    #         elif type == "attr":
    #             for attr in el.attrib:
    #                 el.set(attr, mutation.decode(errors="ignore"))
    #         elif type == "text":
    #             el.text = mutation.decode(errors="ignore")

    #         yield xml_tree

# # XML attribute mutation
# def xml_attr_text_mutation(xml_content: bytes) -> Iterator[bytes]:
#     try:
#         root = xml.fromstring(xml_content)
#     except xml.ParseError:
#         return
#     for mutation in (m for mutator in mutators for m in mutator(xml_content)):
#         for el in root.iter():
#             for attr in el.attrib:
#                 el.set(attr, mutation.decode(errors="ignore"))
#                 yield xml.tostring(root)


# # XML text mutation
# def xml_text_mutation(xml_content: bytes) -> Iterator[bytes]:
#     try:
#         root = xml.fromstring(xml_content)
#     except xml.ParseError:
#         return
#     for mutation in (m for mutator in mutators for m in mutator(xml_content)):
#         for el in root.iter():
#             el.text = mutation.decode(errors="ignore")
#             yield xml.tostring(root)

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

def write_xml_input(tree: xml.ElementTree) -> bytes:
    return xml.tostring(tree.getroot(), encoding='utf-8')

def xml_fuzz_processor(tree: xml.ElementTree, file_type_tree: xml.ElementTree) -> Iterator[xml.ElementTree]:
    # Define mutation functions and their descriptions
    mutation_functions = [
        xml_text_mutation(tree, file_type_tree, "tag"),
        xml_text_mutation(tree, file_type_tree, "attr"),
        xml_text_mutation(tree, file_type_tree, "text"),
    ]

    # print('len mutations:', len(mutation_functions))

    i = 0
    while len(mutation_functions) > 0:

        if i >= len(mutation_functions):
            i = 0

        try:
            # print(f'getting next {i}')
            yield next(mutation_functions[i])
        except StopIteration:
            mutation_functions.pop(i)
            continue

        i += 1


# def load_and_mutate_xml(prog_path, file_path):
#     """Load XML from a file, apply all mutations, and run each mutated version with the C program."""
#     try:
#         with open(file_path, 'rb') as file:
#             xml_content = file.read()

#         # Define mutation functions and their descriptions
#         mutation_functions = [
#             ("tag", xml_tag_mutation),
#             ("attribute", xml_attr_text_mutation),
#             ("text", xml_text_mutation)
#         ]

#         # Run each type of mutation
#         for mutation_type, mutation_func in mutation_functions:
#             for mutation_index, mutated_xml_data in enumerate(mutation_func(xml_content)):
#                 result_mutated = run_c_program_with_pdf(prog_path, mutated_xml_data)
#                 # print(xml_content)
#                 # print(mutated_xml_data, "\n")
#                 # print("C program stderr:", result_mutated.stderr.decode(errors="ignore"))

#     except FileNotFoundError:
#         print(f"Error: File {file_path} not found.")
