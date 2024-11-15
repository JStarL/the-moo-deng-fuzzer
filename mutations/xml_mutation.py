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
import copy
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


def xml_nested_mutation(xml_content: bytes, max_depth: int = 2 ** 15) -> Iterator[bytes]:
    try:
        root = xml.fromstring(xml_content)
    except xml.ParseError:
        return

    nested_xml = "%n" * 2 ** 10

    for idx in range(max_depth):
        nested_xml = f"<{idx}>{nested_xml}</{idx}>"

        if idx % 100000 == 0:
            yield nested_xml.encode()

def xml_breadth_mutation(xml_content: bytes) -> Iterator[bytes]:
    try:
        root = xml.fromstring(xml_content)
    except xml.ParseError:
        return
    new_root = copy.deepcopy(root)
    for i in range(len(root)):
        for _ in range(512):
            new_root.append(root[i])
        yield xml.tostring(new_root)


def xml_attr_mutation(xml_content: bytes) -> Iterator[bytes]:
    try:
        root = xml.fromstring(xml_content)
    except xml.ParseError:
        return

    elements = list(root.iter())

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

        gens = [mutator(text_to_mutate) for mutator in Mutators]
        i = 0
        while len(gens) > 0:
            if i >= len(gens):
                i = 0
            
            try:
                mutation = next(gens[i])
                fuzzer_logger.debug(f'mutation: {mutation[:20]}')
            except StopIteration:
                fuzzer_logger.debug(f'xml_text_mutation for {el.tag} = {text_to_mutate}: finished {gens[i]}')
                gens.pop(i)
                continue

            try:
                # Attempt to decode as UTF-8
                el.text = mutation.decode('utf-8')
            except UnicodeDecodeError:
                # Fallback to Base64 encoding if UTF-8 decoding fails
                el.text = base64.b64encode(mutation).decode('ascii')

            # print(f'text to mutation: {mutation}')
            yield xml.tostring(root)

            i += 1


        # for mutator in Mutators:
        #     for mutation in mutator(text_to_mutate):
        #         if isinstance(mutation, str) or isinstance(mutation, bytes):
        #             fuzzer_logger.debug(f'mutation: {mutation[:20]}')

        #         try:
        #             # Attempt to decode as UTF-8
        #             el.text = mutation.decode('utf-8')
        #         except UnicodeDecodeError:
        #             # Fallback to Base64 encoding if UTF-8 decoding fails
        #             el.text = base64.b64encode(mutation).decode('ascii')

        #         # print(f'text to mutation: {mutation}')
        #         yield xml.tostring(root)

