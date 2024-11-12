from typing import Iterator, List
from mutations.special_values import TRIVAL_POSITIVE_INTS
import copy


def repeat_header(keywords: bytes) -> Iterator[bytes]:
    """Repeat header in the input for the specified number of times."""
    for i in TRIVAL_POSITIVE_INTS:
        print("i {}".format(i))
        combined_keywords = keywords
        repeated_keyword = (combined_keywords + b',') * (i - 1) + combined_keywords
        yield repeated_keyword


def repeat_last_keyword(input: List[str], keywords: List[str]) -> Iterator[List[str]]:
    mod_input = copy.deepcopy(input)
    for i in TRIVAL_POSITIVE_INTS:
        extra_keywords = [keywords[-1]] * i
        mod_input.extend(extra_keywords)
        yield mod_input


if __name__ == "__main__":
    # Example CSV input as bytes
    sample_input = b"""
header,must,stay,intact
a,b,c,S
e,f,g,ecr
i,j,k,et
"""

    # Convert the input to a list of strings
    sample_input_str = sample_input.decode('utf-8').splitlines()

    # Keywords to be repeated
    keywords = b'header'

    # Run the repeat_last_keyword function and print the result
    for mutated_input in repeat_header(keywords):
        print(mutated_input.decode('utf-8'))
