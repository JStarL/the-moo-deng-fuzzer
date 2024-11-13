import fitz
from io import BytesIO
from mutations.pdf_mutations import metadata_mutation
import subprocess


def pdf_parser(pdf_data):
    """
    Parses the PDF binary data and extracts structure information.

    Parameters:
    - pdf_data (bytes): The binary data of the PDF file.

    Returns:
    - tuple: (document object, parsed structure dictionary)
    """
    pdf_bytes_io = BytesIO(pdf_data)
    doc = fitz.open("pdf", pdf_bytes_io)

    structure = {
        "num_pages": doc.page_count,
        "metadata": doc.metadata,
        "pages": []
    }
    for page_num in range(doc.page_count):
        page = doc[page_num]
        page_info = {
            "page_num": page_num + 1,
            "text": page.get_text("text"),
            "images": [
                {
                    "xref": img[0],
                    "width": img[2],
                    "height": img[3],
                    "data": doc.extract_image(img[0])["image"]
                }
                for img in page.get_images(full=True)
            ]
        }
        structure["pages"].append(page_info)
    return doc, structure


def read_pdf_as_bytes(pdf_path):
    """
    Reads a PDF file from the given path and returns it as binary data.

    Parameters:
    - pdf_path (str): Path to the input PDF file.

    Returns:
    - bytes: The binary content of the PDF file.
    """
    with open(pdf_path, "rb") as file:
        pdf_data = file.read()
    return pdf_data


def run_c_program_with_pdf(prog_path, pdf_data):
    """
    Runs a compiled C program, passing the PDF data as input.

    Parameters:
    - prog_path (str): Path to the compiled C program.
    - pdf_data (bytes): PDF binary data to be tested.

    Returns:
    - result: CompletedProcess instance containing stdout and stderr from the C program.
    """
    result = subprocess.run(
        [prog_path],
        input=pdf_data,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE
    )
    return result

def fuzzer_pipeline(pdf_path, prog_path):
    # Step 1: Read PDF as bytes
    pdf_data = read_pdf_as_bytes(pdf_path)

    # Step 2: Parse PDF structure
    _, structure = pdf_parser(pdf_data)  # No need to keep doc; focus on metadata mutation

    # Step 3: Run the C program with the original PDF data
    print("\nRunning C program with original PDF data:")
    result = run_c_program_with_pdf(prog_path, pdf_data)
    print("C program stdout:", result.stdout.decode(errors="ignore"))
    print("C program stderr:", result.stderr.decode(errors="ignore"))

    # Step 4: Apply mutations and run tests for each mutated PDF binary
    for mutation_index, mutated_pdf_data in enumerate(metadata_mutation(pdf_data)):

        print(f"\nRunning C program with mutated PDF data, mutation #{mutation_index + 1}:")
        result_mutated = run_c_program_with_pdf(prog_path, mutated_pdf_data)
        print("C program stdout:", result_mutated.stdout.decode(errors="ignore"))
        print("C program stderr:", result_mutated.stderr.decode(errors="ignore"))


    return


# Example usage
pdf_path = "sample1.pdf"  # Change to the correct PDF file path
prog_path = "./pdf"  # Change to the path of the compiled C program
fuzzer_pipeline(pdf_path, prog_path)
