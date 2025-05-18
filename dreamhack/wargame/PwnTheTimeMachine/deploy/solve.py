#!/usr/bin/env python
import sys
import ptrlib as ptr
import pwn

exe = ptr.ELF("./prob_patched")
pwn.context.binary = pwn.ELF(exe.filepath)
libc = ptr.ELF("./libc.so.6")
# ld = ptr.ELF("")


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

    def send(year, mon, day, hour, min, sec):
        io.sendlineafter(b"Year: ", str(year).encode())
        io.sendlineafter(b"Mon: ", str(mon).encode())
        io.sendlineafter(b"Day: ", str(day).encode())
        io.sendlineafter(b"Hour: ", str(hour).encode())
        io.sendlineafter(b"Min: ", str(min).encode())
        io.sendlineafter(b"Sec: ", str(sec).encode())

    # make_ptr:
    #   if time0->tm_hour + 9 <= 0x12:
    #       0x00007fffffffe850 + min * 8
    #   if time0->tm_hour - 0xa <= 9:
    #       0x00007fffffffe850 - min * 8
    #   other:
    #       ????

    year = 2000
    mon = 0x8
    day = 0xF
    hour = 0xA
    min = 0x0
    sec = 0
    input(">> ")
    send(year, mon, day, hour, min, sec)

    io.interactive()
    return


if __name__ == "__main__":
    main()
