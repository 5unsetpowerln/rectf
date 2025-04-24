#!/usr/bin/env python
import sys
import ptrlib as ptr
import pwn

exe = ptr.ELF("./petpals_patched")
pwn.context.binary = pwn.ELF(exe.filepath)
libc = ptr.ELF("./libc.so.6")
ld = ptr.ELF("./ld-linux-x86-64.so.2")


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

    def sla(delim: bytes, data: bytes):
        io.sendlineafter(delim, data)
        return

    def sa(delim: bytes, data: bytes):
        io.sendafter(delim, data)
        return

    def sl(data: bytes):
        io.sendline(data)
        return

    def s(data: bytes):
        io.send(data)
        return

    def r(size: int) -> bytes:
        return io.recv(size)

    def ru(delim: bytes, drop: bool = False) -> bytes:
        return io.recvuntil(delim, drop=drop)

    def rl() -> bytes:
        return io.recvline()

    # animal(0x10):
    # 0x00 ~ 0x08: animal_type_idx
    # 0x08 ~ 0x10: name
    # 0x10 ~ 0x18: name
    # 0x18 ~ 0x20: length (0x10) (uint64_t)
    # 0x20 ~ 0x28: unknown_byte (0x64)

    # animal(0x20):
    # 0x00 ~ 0x08: animal_type_idx
    # 0x08 ~ 0x10: name
    # 0x10 ~ 0x18: name
    # 0x18 ~ 0x20: name
    # 0x20 ~ 0x28: name
    # 0x28 ~ 0x30: length (0x20) (uint64_t)
    # 0x30 ~ 0x38: unknown_byte (0xc8)

    io.interactive()
    return


if __name__ == "__main__":
    main()
