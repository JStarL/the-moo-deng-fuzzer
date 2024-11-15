from typing import Iterator, Dict
from mutations.buffer_overflow import buffer_overflow_mutation
from mutations.format_str import data_injection, boundary_value_injection, format_injection, \
    long_format_specifier, boundary_str_injection
from mutations.integer_mutations import to_str, to_hex, nearby_special_intbytes
import random

mutators = [data_injection,
            boundary_str_injection,
            format_injection,
            long_format_specifier,
            to_hex,
            nearby_special_intbytes,
            boundary_value_injection,
            buffer_overflow_mutation
            ]

import base64


def update_keys(kv: Dict) -> Iterator[Dict]:
    """Yields dictionaries with keys replaced by mutated versions."""
    for k, v in list(kv.items()):
        for mutator in mutators:
            for k_m in mutator(k.encode()):
                mutated_key = k_m.decode(errors="ignore")
                mod_dict = kv.copy()
                mod_dict[mutated_key] = v
                del mod_dict[k]
                yield mod_dict


def update_values(kv: Dict) -> Iterator[Dict]:
    """Yields dictionaries with values replaced by mutated versions.

    Args:
        kv (Dict): Original dictionary.

    Yields:
        Iterator[Dict]: Modified dictionaries with mutated values.
    """
    for k, v in list(kv.items()):
        for mutator in mutators:
            for v_m in mutator(v.encode()):
                mutated_value = v_m.decode(errors="ignore")
                # Create a copy of the dictionary to avoid modifying the original
                mod_dict = kv.copy()
                # Update the copy with the mutated value
                mod_dict[k] = mutated_value
                # Yield the modified dictionary
                yield mod_dict


def del_keys(kv: Dict) -> Iterator[Dict]:
    """Yields dictionaries with cumulative keys removed."""
    keys = list(kv.keys())
    for i in range(1, len(keys) + 1):
        mod_dict = kv.copy()
        for key in keys[:i]:
            del mod_dict[key]
        yield mod_dict


# def duplicate_keys(kv: Dict) -> Iterator[Dict]:
#     pass


def add_keys(kv: Dict) -> Iterator[Dict]:
    """Yields dictionaries with additional keys added by mutated versions.

    Args:
        kv (Dict): Original dictionary.

    Yields:
        Iterator[Dict]: Modified dictionaries with added keys.
    """

    for mutator in mutators:
        for m in mutator(b''):
            mutated_key = m.decode(errors="ignore")

            mod_dict = kv.copy()
            mod_dict[mutated_key] = mutated_key

            yield mod_dict


def random_keys(kv: Dict) -> Iterator[Dict]:
    """Yields dictionaries with random mutations applied from update_keys, update_values, del_keys, or add_keys.

    Args:
        kv (Dict): Original dictionary.

    Yields:
        Iterator[Dict]: Modified dictionaries with random mutations.
    """
    mutation_functions = [del_keys, update_keys, update_values, add_keys]
    mutation_count = len(kv) * 200 if len(kv) > 1 else 200
    # print()

    for _ in range(mutation_count):
        mutation_func = random.choice(mutation_functions)

        mutated_dict = next(mutation_func(kv), kv)
        yield mutated_dict
