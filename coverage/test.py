from binary import Binary
from graph import Function

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
    for block in item["blocks"]:
        print(f"offset: { hex( block.get('offset', 0) ) }")
        print(f"size: { hex( block.get('size', 0) ) }")
        print(f"jump: { hex( block.get('jump', 0) ) }")
        print(f"fail: { hex( block.get('fail', 0) ) }")
        print()

func = Function(binary=cov, main_addr=addr)

