from typing import Iterator, List
from mutations.special_values import TRIVAL_POSITIVE_INTS
import copy

def repeat_header(sample_input: bytes, keywords: List[bytes]) -> Iterator[bytes]:
    """Repeat header in the input for the specified number of times."""
    for i in TRIVAL_POSITIVE_INTS:
        combined_keywords = b','.join(keywords)
        repeated_keyword = (combined_keywords + b',') * (i - 1) + combined_keywords
        yield sample_input.replace(combined_keywords, repeated_keyword)

def repeat_last_keyword(input: List[str], keywords: List[str]) -> Iterator[List[str]]:
    mod_input = copy.deepcopy(input)
    for i in TRIVAL_POSITIVE_INTS:
        extra_keywords = [keywords[-1]] * i
        mod_input.extend(extra_keywords)
        yield mod_input


def run_main_keyword_test():
     # Example CSV input as bytes
    sample_input = b"""
                        header,must,stay,intact
                        a,b,c,S
                        e,f,g,ecr
                        i,j,k,et
                        """

    # Keywords to be repeated
    keywords = [b'header', b'must', b'stay', b'intact']

    # Run the repeat_key function and print the result
    for mutated_input in repeat_header(sample_input, keywords):
        print(mutated_input.decode('utf-8'))

# Run the test
if __name__ == "__main__":
    run_main_keyword_test()
