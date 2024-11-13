from main import Binary
import json

binary = "../binaries/csv1"

cov = Binary(binary)
blocks = cov.get_blocks(0x00001867)

print(f"Type of the `blocks` dictionary is {type(blocks)}")

for block in blocks:
    print("========================")
    print(block)
    print(f"Start: {hex( block['addr'] )}")
    print(f"Size: {block['size']} bytes")
    print("Content:")
    print(cov.r2.cmd(f"pdis {block['size']} @ {block['addr']}"))

print("========================")
