from main import Binary

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
        print(f"offset: { block.get('offset', 'None') }")
        print(f"size: { block.get('size', 'None') }")
        print(f"jump: { block.get('jump', 'None') }")
        print(f"fail: { block.get('fail', 'None') }")
        print()
