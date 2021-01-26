

from pwn import *
import pdb


def add_note(idx, name):
    p.sendlineafter('Your choice :', '1')
    p.sendlineafter('Index :', str(idx))
    p.sendlineafter('"Name :', name)


def show_note(idx):
    p.sendlineafter('Your choice :', '2')
    p.sendlineafter('Index :', str(idx))


def del_note(idx):
    p.sendlineafter('Your choice :', '3')
    p.sendlineafter('Index :', str(idx))


def _exit():
    p.sendlineafter('Your choice :', '4')


p = process('/home/len/pwnable/death_note')

if __name__ == "__main__":
    add_note(0, 'a')
