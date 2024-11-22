# PwnChalenges
## Coredump
```
ulimit -c unlimited
```
## Checksec
```
exe = './test'
elf = context.binary = ELF(exe, checksec=True)
context.log_level = 'debug'
```
## EIP/RIP offset 
```
def findoffset(path,size,after):
    #target=process(path, stdin=PTY, stdout=PTY, stderr=PTY)
    target=process(path)
    target.sendlineafter(after, cyclic(size))
    target.wait()
    # ip_offset = cyclic_find(p.corefile.pc)  # x86
    ip_offset = cyclic_find(target.corefile.read(target.corefile.sp, 4)) # x64
    info('located EIP/RIP offset at {a}'.format(a=ip_offset))
    return ip_offset
```
## Function Address
```
info(hex(elf.symbols['gg']))
```

