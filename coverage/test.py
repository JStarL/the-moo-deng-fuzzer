from main import Binary
import json

binary = "../binaries/csv1"

cov = Binary(binary)
addr = 0x00001867
blocks = cov.get_blocks(addr)

# print(f"Type of the `blocks` dictionary is {type(blocks)}")
#
# for block in blocks:
#     print("========================")
#     print(block)
#     print(f"Start: {hex( block['addr'] )}")
#     print(f"Size: {block['size']} bytes")
#     print("Info:")
#     infos = cov.r2.cmdj(f"afbij @ {block['addr']}")
#     for info in infos:
#         print(info)
#         print()
#
# print("========================")

test = cov.r2.cmdj(f"agfj @ sym.fread_csv_line")
print(type(test))
for item in test:
    print(item.keys())
    for block in item['blocks']:
        print(f"keys: { block.keys() }")
        print(f"offset: { block['offset'] }")
        print(f"size: { block['size'] }")
        print(f"jump: { block['jump'] }")
        print(f"fail: { block['fail'] }")
        print()
