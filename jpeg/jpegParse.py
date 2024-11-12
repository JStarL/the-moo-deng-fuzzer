from PIL import Image
from PIL.ExifTags import TAGS
import io
import sys

# must change the file path before we commit
imgPath = './example_inputs/jpg1.txt'
# imgPath = 'test.jpg'
with open(imgPath, 'rb') as file:
    imgBinary = file.read()

print(type(imgBinary)) #test : <class 'bytes'>
print(imgBinary[:10]) # test 

# jpeg image file read from the binary
image = Image.open(io.BytesIO(imgBinary)) # fix error

# print(imgBinary) # test

# jpeg exif data dictionary
jpeg_data = {
    "Filename": image.filename,
    "Image Size": image.size,
    "Image Height": image.height,
    "Image Width": image.width,
    "Image Format": image.format,
    "Image Mode": image.mode,
    "Image is Animated": getattr(image, "is_animated", False),
    "Frames in Image": getattr(image, "n_frames", 1)
}

print(jpeg_data)

# extract other basic metadata
exifdata = image.getexif()

# append additional exif data key-value
for tag_id in exifdata:
    tag = TAGS.get(tag_id, tag_id)
    data = exifdata.get(tag_id)
    if isinstance(data, bytes):
        data = data.decode()
    jpeg_data[tag] = data
    # print(f"{tag:25}: {data}")

for label, value in jpeg_data.items():
    print(f"{label:25}: {value}")


# img.show()

