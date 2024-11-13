from io import BytesIO
from .special_values import SPECIAL_CHAR_INTS, SPECIAL_INTS
import fitz
import random

# Define the supported metadata keys by fitz library
SUPPORTED_METADATA_KEYS = ["title", "author", "subject", "keywords", "creator", "producer", "creationDate", "modDate"]

def metadata_mutation(doc):
    """
    Mutates metadata by injecting boundary values, oversized strings, invalid keys, and random data.
    This generator yields mutated PDF binaries designed to test parser robustness.
    """
    def yield_mutated_doc_bytes(metadata):
        filtered_metadata = {k: v for k, v in metadata.items() if k in SUPPORTED_METADATA_KEYS}
        doc.set_metadata(filtered_metadata)
        output_pdf_bytes_io = BytesIO()
        doc.save(output_pdf_bytes_io)
        yield output_pdf_bytes_io.getvalue()

    original_metadata = doc.metadata

    # Mutation 1: Inject extremely long and nested strings
    deep_nested_string = "<<" + "A" * 5000 + ">>"
    nested_metadata = {key: deep_nested_string for key in SUPPORTED_METADATA_KEYS}
    yield from yield_mutated_doc_bytes(nested_metadata)

    # Mutation 2: Random invalid control characters in metadata
    control_chars = ''.join(chr(random.choice(SPECIAL_CHAR_INTS)) for _ in range(500))
    control_metadata = {key: control_chars for key in SUPPORTED_METADATA_KEYS}
    yield from yield_mutated_doc_bytes(control_metadata)

    # Mutation 3: Inject extremely large integer values
    large_integers_metadata = {
        "title": str(random.choice(SPECIAL_INTS)),
        "author": str(2**64),
        "subject": str(-2**63),
        "keywords": str(2**32 - 1),
        "creator": "1e308",  # Large float
        "producer": "-1e308",  # Large negative float
        "creationDate": str(2**128),  # Beyond typical integer range
        "modDate": str(-2**128)
    }
    yield from yield_mutated_doc_bytes(large_integers_metadata)

    # Mutation 4: Inject special characters with random ASCII and binary data
    special_binary_data = ''.join(chr(random.randint(0, 255)) for _ in range(1000))
    binary_metadata = {key: special_binary_data for key in SUPPORTED_METADATA_KEYS}
    yield from yield_mutated_doc_bytes(binary_metadata)

    # Mutation 5: Overwrite with random invalid keys and values
    invalid_keys_metadata = {
        "InvalidKey" + str(i): "RandomValue" + special_binary_data[:100]
        for i in range(100)  # Add 100 invalid keys
    }
    yield from yield_mutated_doc_bytes(invalid_keys_metadata)

    # Mutation 6: Alternating extreme values for each key
    alternating_metadata = {
        key: ("A" * 1000 if i % 2 == 0 else "\x00" * 1000) for i, key in enumerate(SUPPORTED_METADATA_KEYS)
    }
    yield from yield_mutated_doc_bytes(alternating_metadata)

    # Restore original metadata
    doc.set_metadata(original_metadata)
