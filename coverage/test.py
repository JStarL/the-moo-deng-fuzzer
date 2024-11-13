from main import Binary
import json

binary = "../binaries/csv1"

cov = Binary(binary)
blocks = json.loads(cov.r2.cmd("afbj @ sym.fread_csv_line"))

for block in blocks:
    print("========================")
    print(f"Start: {hex( block['addr'] )}")
    print(f"Size: {block['size']} bytes")
    print("Content:")
    print(cov.r2.cmd(f"pdis {block['size']} @ {block['addr']}"))

print("========================")
