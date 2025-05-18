#!/usr/bin/env python
import sys
import ptrlib as ptr
import pwn

exe = ptr.ELF("./chall_patched")
pwn.context.binary = pwn.ELF(exe.filepath)
libc = ptr.ELF("./libc.so.6")
ld = ptr.ELF("./ld-2.23.so")


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

    def create(size: int):
        io.sendlineafter(b"> ", b"1")
        io.sendlineafter(b"Size: ", str(size).encode())

    def edit(data: bytes, line=True):
        io.sendlineafter(b"> ", b"2")
        io.sendlineafter(b"Data: ", data)

    def show() -> bytes:
        io.sendlineafter(b"> ", b"3")
        io.recvuntil(b"Data: ")
        return io.recvuntil(b"\n==========", drop=True)

    def delete():
        io.sendlineafter(b"> ", b"4")

    def exit_():
        io.sendlineafter(b"> ", b"5")

    # create(0x18)
    # delete()
    # create(0x28)
    # create(0x18)
    #

    create(0)

    io.interactive()
    return


if __name__ == "__main__":
    main()
