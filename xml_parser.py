from typing import Iterator
import xml.etree.ElementTree as xml
import copy
from utils import determine_input_type
from mutations.xml_mutation import xml_text_mutation, xml_attr_mutation, xml_tag_mutation, xml_nested_mutation, xml_breadth_mutation
import sys
from logger import fuzzer_logger

def read_xml_file(filepath: str):
    try:
        tree = xml.parse(filepath)
        return tree
    except:
        fuzzer_logger.critical(f"Couldn't parse xml file at {filepath}")
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


def xml_fuzz_processor(tree: xml.ElementTree, file_type_tree: xml.ElementTree) -> Iterator[xml.ElementTree]:
    # Define mutation functions and their descriptions
    mutation_functions = [
        xml_text_mutation,
        xml_attr_mutation,
        xml_tag_mutation,
        xml_breadth_mutation,
        xml_nested_mutation,
    ]
    mutation_generators = [func(xml.tostring(tree.getroot())) for func in mutation_functions]

    while mutation_generators:
        for i, generator in enumerate(mutation_generators):
            try:
                mutated_xml_bytes = next(generator)
                yield mutated_xml_bytes
            except StopIteration:
                # print('generator = ', generator)
                mutation_generators.pop(i)

