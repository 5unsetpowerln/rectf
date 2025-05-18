#!/usr/bin/env python
import sys
import ptrlib as ptr

# import pwn

exe = ptr.ELF("./sp33d1")
# pwn.context.binary = pwn.ELF(exe.filepath)
# libc = ptr.ELF("")
# ld = ptr.ELF("")


def connect():
    if len(sys.argv) > 1 and sys.argv[1] == "remote":
        return ptr.remote("localhost", 5000)
    if len(sys.argv) > 1 and sys.argv[1] == "debug":
        return ptr.process("./debug.sh")
    else:
        return ptr.process("")


def unwrap(x):
    if x is None:
        ptr.logger.error("Failed to unwrap")
        exit(1)
    else:
        return x


def main():
    io = connect()

    io.interactive()
    return


if __name__ == "__main__":
    main()
