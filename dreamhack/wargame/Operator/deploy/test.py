ret_addr = 0x00005555555555c3
base_addr = 0x555555554000
# ret_addr = 0x00007ffff7c29d90
# base_addr = 0x7ffff7c00000

for i in range(64):
    modified_ret_addr = ret_addr ^ (1 << i)
    print(i, hex(modified_ret_addr), hex(modified_ret_addr - base_addr))
