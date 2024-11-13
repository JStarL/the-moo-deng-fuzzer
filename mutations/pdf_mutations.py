def mutate_file_structure(doc):
    """
    Mutates file structure by injecting potential crash-inducing elements, such as
    excessive nested objects, oversized data blocks, and invalid structures.
    """
    # Clear metadata to simulate missing document info
    doc.set_metadata({})

    # Attempt to add excessive nested structures
    try:
        page = doc[0]
        for i in range(100):  # Adding excessive levels of nested structures
            page.insert_text((72, 72 + i * 10), f"<< /InvalidStructure {i} >>", fontsize=8)
    except Exception as e:
        print(f"Error adding nested structures: {e}")

    # Insert a large, nonsensical data block
    large_text = "/BigData " + "A" * 10000  # Oversized text block
    try:
        page.insert_text((72, 72), large_text, fontsize=12)
    except Exception as e:
        print(f"Error inserting large data block: {e}")

    # Break cross-references by removing random image references
    for page_num in range(doc.page_count):
        page = doc[page_num]
        for img in page.get_images(full=True):
            xref = img[0]
            try:
                page.clean_contents(xref)  # Remove image reference
            except Exception as e:
                print(f"Error breaking cross-references: {e}")

    return doc
