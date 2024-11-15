from PIL import Image
from PIL.ExifTags import TAGS
import io
import random
from utils import FieldType, determine_input_type, field_fuzzer
from typing import Iterator
from mutations.bit_flip import byte_flip, random_partial_flip, inject_special_values
from mutations.keywords import repeat_keyword_inplace, delete_keyword, repeat_keyword_end_bytes
from mutations.buffer_overflow import buffer_overflow_mutation
from logger import fuzzer_logger

MARKERS = {
    "Image Start": 0xFFD8.to_bytes(2, byteorder='big'),
    "Default Header": 0xFFE0.to_bytes(2, byteorder="big"),
    "Quantization Table": 0xFFDB.to_bytes(2, byteorder="big"),
    "Frame Start": 0xFFC0.to_bytes(2, byteorder="big"),
    "Huffman Table": 0xFFC4.to_bytes(2, byteorder="big"),
    "Scan Start": 0xFFDA.to_bytes(2, byteorder="big"),
    "Image End": 0xFFD9.to_bytes(2, byteorder="big")
}

def mutators(data):
    
    mutators = [random_partial_flip(data), inject_special_values(data), buffer_overflow_mutation()]
    
    i = 0
    while len(mutators) > 0:
        if i >= len(mutators):
            i = 0
        
        try:
            yield next(mutators[i])
        except StopIteration:
            mutators.pop(i)
            continue

        i += 1

def header_mutator(img_bin):
    header = MARKERS["Default Header"]
    quanitzation = MARKERS["Quantization Table"]

    return mutate_region(img_bin, start_marker=header, end_marker=quanitzation)

def qt_mutator(img_bin):
    quanitzation = MARKERS["Quantization Table"]
    frame_start = MARKERS["Frame Start"]

    return mutate_region(img_bin, start_marker=quanitzation, end_marker=frame_start)

def frame_mutator(img_bin):
    frame_start = MARKERS["Frame Start"]
    huffman = MARKERS["Huffman Table"]

    return mutate_region(img_bin, start_marker=frame_start, end_marker=huffman)

def huffman_mutator(img_bin):
    huffman = MARKERS["Huffman Table"]
    scan_start = MARKERS["Scan Start"]

    return mutate_region(img_bin, start_marker=huffman, end_marker=scan_start)

def image_content_mutator(img_bin):
    scan_start = MARKERS["Scan Start"]
    image_end = MARKERS["Image End"]

    return mutate_region(img_bin, start_marker=scan_start, end_marker=image_end)

def mutate_region(img_bytes: bytes, start_marker: bytes, end_marker: bytes) -> Iterator[bytes]:

    before_region = img_bytes.split(start_marker)[0]

    region = img_bytes.split(start_marker)[1]
    region = region.split(end_marker)[0]

    after_region = img_bytes.split(end_marker)[1]

    byte_flipper = mutators(region)

    try:
        while True:
            mutated_region = next(byte_flipper)
            yield before_region + start_marker + mutated_region + end_marker + after_region
    except StopIteration:
        fuzzer_logger.debug(f'Tried all byte flip mutations for jpeg')

def edit_markers(img_bytes: bytes) -> Iterator[bytes]:

    mutators = []
    mutators.append(repeat_keyword_inplace(img_bytes, list(MARKERS.values())))
    mutators.append(delete_keyword(img_bytes, list(MARKERS.values())))
    mutators.append(repeat_keyword_end_bytes(img_bytes, list(MARKERS.values())))

    i = 0
    while len(mutators) > 0:
        if i >= len(mutators):
            i = 0
        
        try:
            mod_img_bytes = next(mutators[i])
            yield mod_img_bytes
        except StopIteration:
            mutators.pop(i)
            continue

def jpeg_fuzz_processor(img, img_exif_types):
    img_byte_arr = io.BytesIO()
    img.save(img_byte_arr, format=img.format)
    img_bin = img_byte_arr.getvalue()

    mutators = []
    mutators.append(header_mutator(img_bin))
    mutators.append(qt_mutator(img_bin))
    mutators.append(frame_mutator(img_bin))
    mutators.append(huffman_mutator(img_bin))
    mutators.append(image_content_mutator(img_bin))
    mutators.append(edit_markers(img_bin))

    i = 0

    while len(mutators) > 0:
        if i >= len(mutators):
            i = 0

        try:
            mod_img_bin = next(mutators[i])
            yield mod_img_bin
        except StopIteration:
            # fuzzer_logger.debug(f'Finished index {i}')
            mutators.pop(i)
            continue

        i += 1


def get_jpeg_meta(img):
    jpeg_data = {
        "Filename": img.filename,
        "Image Size": img.size,
        "Image Height": img.height,
        "Image Width": img.width,
        "Image Format": img.format,
        "Image Mode": img.mode,
        "Image is Animated": getattr(img, "is_animated", False),
        "Frames in Image": getattr(img, "n_frames", 1)
    }
    return jpeg_data

def set_jpeg_meta_field(img, meta_key, meta_value):
    # if meta_key == "Filename":
    #     img.filename = meta_value
    # elif meta_key == "Image Size":
    #     return img
    #     img._size = meta_value
    # elif meta_key == "Image Height":
    #     current_width = img.width
    #     img._size = (current_width, meta_value)
    # elif meta_key == "Image Width":
    #     current_height = img.height
    #     img._size = (meta_value, current_height)
    # elif meta_key == "Image Format":
    #     img.format = meta_value
    # elif meta_key == "Image Mode":
    #     img.mode = meta_value
    # elif meta_key == "Image is Animated":
    #     img.is_animated = meta_value
    # elif meta_key == "Frames in Image":
    #     img.n_frames = meta_value
    
    # return img

    exif_data = img.getexif()

    exif_key = next((k for k, v in TAGS.items() if v == meta_key.replace(" ", "")), None)
    if exif_key:
        # if isinstance(meta_value, int):
        #     set_value = meta_value.to_bytes(16, byteorder='little')
        # else:
        set_value = meta_value
        exif_data[exif_key] = set_value
    try:
        img.info['exif'] = exif_data.tobytes()
    except:
        print(f"Couldn't set jpeg meta: ({meta_key}: {meta_value})")

    return img

def read_jpg_file(filepath):
    with open(filepath, 'rb') as f:
        img_bin = f.read()
        img = Image.open(io.BytesIO(img_bin))

        return img

def process_jpeg(img):

    jpeg_type = get_jpeg_meta(img)

    for key in jpeg_type:
        jpeg_type[key] = determine_input_type(jpeg_type[key])
    
    return jpeg_type

def jpeg_fuzz_processor_old(img, img_exif_types):
    
    jpeg_input = get_jpeg_meta(img)

    keys_list = list(img_exif_types.keys())

    generators = [field_fuzzer(img_exif_types[key], key, jpeg_input[key]) for key in keys_list]

    print(img_exif_types)
    # exit()

    i = 0
    while len(generators) > 0:
        # print("Len(gens):", len(generators))
        if i >= len(generators):
            i = 0
        
        try:
            jpeg_input[keys_list[i]] = next(generators[i])
            print(f'{keys_list[i]}: {jpeg_input[keys_list[i]]}')
            img = set_jpeg_meta_field(img, keys_list[i], jpeg_input[keys_list[i]])
            yield img
        except StopIteration:
            generators.pop(i)
            keys_list.pop(i)
            i -= 1

        i += 1
