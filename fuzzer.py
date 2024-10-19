import json
import random
import string
import subprocess
import os

# Example file paths (you'll need to replace with actual paths)
BINARY_PATH = "binaries/binaries/json1"  # Update this with the correct path to the binary
JSON_INPUT_FILE = "binaries/example_inputs/json1.txt"
FUZZ_ROUNDS = 100  # Number of fuzzing iterations

# # CSV header that must stay intact
# CSV_HEADER = ["header", "must", "stay", "intact"]
#
# # CSV base rows as per the example
# BASE_CSV_ROWS = [
#     ["a", "b", "c", "S"],
#     ["e", "f", "g", "ecr"],
#     ["i", "j", "k", "et"]
# ]

def load_json_input(file_path):
    """Load the JSON input example."""
    with open(file_path, 'r') as f:
        return json.load(f)

def mutate_json(input_data):
    """Mutate the JSON input data."""
    mutated_data = input_data.copy()

    # Mutate 'len' field
    mutated_data['len'] = random.randint(0, 100)

    # Mutate 'input' field by adding random characters
    mutated_data['input'] = ''.join(random.choices(string.ascii_letters + string.digits, k=mutated_data['len']))

    # Mutate 'more_data' field by changing or adding new random strings
    mutated_data['more_data'] = [random.choice(string.ascii_lowercase) * random.randint(1, 5) for _ in range(random.randint(1, 5))]

    return mutated_data

def fuzz_and_test(binary_path, input_data, input_type="json"):
    """Run the binary with fuzzed inputs and capture results."""
    if input_type == "json":
        # Serialize the JSON input
        input_str = json.dumps(input_data)
    elif input_type == "csv":
        pass

    # Write fuzzed input to a temporary file
    temp_input_file = f"bad.{input_type}"
    with open(temp_input_file, 'w') as f:
        f.write(input_str)

    # Run the binary with the fuzzed input and capture output
    try:
        result = subprocess.run([binary_path, temp_input_file], capture_output=True, text=True, timeout=5)
        output = result.stdout
        error = result.stderr

        if result.returncode != 0:
            print(f"Error: Binary crashed or returned error with input: {input_data}")
            print(f"Error Output: {error}")
        else:
            print(f"Binary executed successfully with input: {input_data}")
            print(f"Output: {output}")

    except subprocess.TimeoutExpired:
        print(f"Timeout: Binary took too long to process input: {input_data}")

    finally:
        # Clean up the temporary input file
        os.remove(temp_input_file)

def run_fuzzer():
    """Main fuzzer loop."""
    # Load the example input
    example_input = load_json_input(JSON_INPUT_FILE)

    for i in range(FUZZ_ROUNDS):
        # Mutate the input
        fuzzed_input = mutate_json(example_input)

        # Test the binary with the fuzzed input in both formats
        fuzz_and_test(BINARY_PATH, fuzzed_input, input_type="json")

if __name__ == "__main__":
    run_fuzzer()
