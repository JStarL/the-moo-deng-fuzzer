print('hello')
import json
import random
import string
import subprocess
import os

# Example file paths (you'll need to replace with actual paths)
BINARY_PATH = "binaries/binaries/json1"  # Update this with the correct path to the binary
JSON_INPUT_FILE = "binaries/example_inputs/json1.txt"  # Single JSON input file path
FUZZ_ROUNDS = 100  # Number of fuzzing iterations

def load_json_input(file_path):
    """Load the JSON input example from a single file."""
    with open(file_path, 'r') as f:
        return json.load(f)

def mutate_json(input_data):
    """Mutate the JSON input data."""
    mutated_data = input_data.copy()

    # Mutate 'len' field
    if 'len' in mutated_data:
        mutated_data['len'] = random.randint(0, 100)

    # Mutate 'input' field by adding random characters if it exists
    if 'input' in mutated_data:
        mutated_data['input'] = ''.join(random.choices(string.ascii_letters + string.digits, k=mutated_data.get('len', 10)))

    # Mutate 'more_data' field by changing or adding new random strings if it exists
    if 'more_data' in mutated_data:
        mutated_data['more_data'] = [random.choice(string.ascii_lowercase) * random.randint(1, 5) for _ in range(random.randint(1, 5))]

    return mutated_data

def fuzz_and_test(binary_path, input_data, input_type="json"):
    """Run the binary with fuzzed inputs and capture results."""

    if input_type == "json":
        # Serialize the JSON input
        input_str = json.dumps(input_data)
        print('input_str', input_str)

    # Run the binary with the fuzzed input and capture output
    try:
        result = subprocess.run([binary_path], input=input_str, capture_output=True, text=True, timeout=5)
        output = result.stdout
        error = result.stderr

        if result.returncode != 0:
            error_filename = f"bad_{input_type}.txt"

            print(f"Error: Binary crashed or returned error with input: {input_data}")
            print(f"Error Output: {error}")

            # Write the crashing input to a file for further analysis
            with open(error_filename, "a") as crash_file:
                crash_file.write(f"Input Data: {json.dumps(input_data)}\n")
                crash_file.write(f"Error Output: {error}\n\n")
        else:
            pass
            # print(f"Binary executed successfully with input: {input_data}")
            # print(f"Output: {output}")

    except subprocess.TimeoutExpired:
        print(f"Timeout: Binary took too long to process input: {input_data}")

def run_fuzzer():
    """Main fuzzer loop."""
    # Load the single example input from the specified file
    example_input = load_json_input(JSON_INPUT_FILE)

    for _ in range(FUZZ_ROUNDS):
        # Mutate the input
        fuzzed_input = mutate_json(example_input)

        # Test the binary with the fuzzed input
        fuzz_and_test(BINARY_PATH, fuzzed_input, input_type="json")

if __name__ == "__main__":
    run_fuzzer()
