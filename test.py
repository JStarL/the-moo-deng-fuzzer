import json
from typing import Iterator
import random


# Define the real mutators based on your provided information
def close_number_mutation(number: int) -> Iterator[int]:
    """Yields numbers close to the given number by adding or subtracting small amounts."""
    for i in range(0, 1000):
        yield number + i
        yield number - i


def rand_number_mutation(number: int) -> Iterator[int]:
    """Yields random numbers in a range around the given number."""
    for _ in range(0, 1000):
        yield number + random.randint(-1000, 1000)


# Mutators list as per your definition
NUMBER_MUTATORS = [close_number_mutation, rand_number_mutation]


def round_robin(mutated_values):
    """Helper function to iterate over different mutated values from multiple mutators."""
    for mutations in mutated_values:
        for value in mutations:
            yield value


def json_number_value_hunter(sample_input: bytes) -> Iterator[bytes]:
    """Runs each mutator on the values of the sample_input, interpreted as JSON."""
    try:
        # Parse JSON input into a Python dictionary
        parsed_json = json.loads(sample_input.decode().replace("'", '"'))
    except json.JSONDecodeError:
        return

    # Iterate over each key-value pair in the parsed JSON object
    for key, value in parsed_json.items():
        # Create a copy of the JSON dictionary to avoid altering the original one
        mutated_json = parsed_json.copy()

        # Only mutate if the value is an integer
        if not isinstance(value, int):
            continue

        # Apply each number mutator to the integer value
        for mutated_value in round_robin([mutator(value) for mutator in NUMBER_MUTATORS]):
            try:
                mutated_json[key] = mutated_value
            except UnicodeDecodeError:
                continue

            # Yield the mutated JSON as a byte-encoded string
            yield json.dumps(mutated_json).encode()


# Example usage
if __name__ == "__main__":
    # Example JSON input
    input_json = {
        "age": 25,
        "height": 170,
        "name": "John",
        "grades": [85, 90, 92]
    }

    # Convert to bytes
    sample_input = json.dumps(input_json).encode()

    # Apply the json_number_value_hunter function and print results
    for mutated in json_number_value_hunter(sample_input):
        print(mutated.decode())
