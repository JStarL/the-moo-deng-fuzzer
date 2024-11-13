from typing import Iterator


def buffer_overflow_mutation(data: bytes) -> Iterator[bytes]:
    """Generates buffer overflows."""
    for i in range(7, 17):
        yield b"A" * 2 ** i


# Test the function
def test_buffer_overflow_mutation():
    # Call the function to generate buffer overflow inputs
    for idx, mutated_input in enumerate(buffer_overflow_mutation()):
        # Print the length of each generated input to see if it matches expected sizes
        print(f"Generated input {idx + 1}: Length = {len(mutated_input)} bytes")


# Run the test
if __name__ == "__main__":
    test_buffer_overflow_mutation()
