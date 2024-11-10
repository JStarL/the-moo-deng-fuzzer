from PIL import Image
from PIL.ExifTags import TAGS
import io
import random
import copy
from utils import FieldType, determine_input_type, field_fuzzer



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
    
    # if isinstance(meta_value, int) and meta_value > 2147483647:
    #     meta_value = 5
    #     print(meta_value)

    exif_data = img.getexif()

    exif_key = next((k for k, v in TAGS.items() if v == meta_key.replace(" ", "")), None)
    if exif_key:
        if isinstance(meta_value, int):
            set_value = meta_value.to_bytes(16, byteorder='little')
        else:
            set_value = meta_value
        exif_data[exif_key] = set_value
    try:
        img.info['exif'] = exif_data.tobytes()
    except:
        print(f"Couldn't set jpeg meta: ({meta_key}: {meta_value})")

    return img

def read_jpg_file(filepath):
    return Image.open(filepath)

def process_jpeg(img):

    jpeg_type = get_jpeg_meta(img)

    for key in jpeg_type:
        jpeg_type[key] = determine_input_type(jpeg_type[key])
    
    return jpeg_type

def jpeg_fuzz_processor(img, img_exif_types):
    
    jpeg_input = get_jpeg_meta(img)

    keys_list = list(img_exif_types.keys())

    generators = [field_fuzzer(img_exif_types[key], key, jpeg_input[key]) for key in keys_list]

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

        # print('got here')
        i += 1

def jpeg_fuzz_processor_random(img, noise_percentage=0.01):
    
    # Convert image to RGB mode if it's not already
    if img.mode != 'RGB':
        img = img.convert('RGB')
    
    # Save the image to a bytes buffer
    buffer = io.BytesIO()
    img.save(buffer, format='JPEG')
    image_bytes = buffer.getvalue()
    
    # Find the start of the image data (after SOI and APP0 markers)
    start_index = image_bytes.index(b'\xFF\xDA')  # Start of Scan marker
    
    # Extract the data section
    data_section = bytearray(image_bytes[start_index:])
    
    # Calculate number of bytes to flip
    total_bytes = len(data_section)
    bytes_to_flip = int(total_bytes * noise_percentage)
    
    # Generate random XOR mask
    xor_mask = bytearray(random.getrandbits(8) for _ in range(bytes_to_flip))
    
    # Randomly select bytes to flip and apply XOR
    for i in range(bytes_to_flip):
        byte_index = random.randint(0, total_bytes - 1)
        data_section[byte_index] ^= xor_mask[i]
    
    # Reconstruct the image
    modified_image_bytes = image_bytes[:start_index] + data_section
    
    # Save the modified image
    with open(output_path, 'wb') as f:
        f.write(modified_image_bytes)

    print(f"Noise introduced and image saved to {output_path}")

