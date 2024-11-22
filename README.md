# PwnChalenges
## Coredump
```
ulimit -c unlimited
```
## RIP Offset 
```
def findoffset():
    #of=process('./test', stdin=PTY, stdout=PTY, stderr=PTY)
    of=process('./test')
    of.sendlineafter(':', cyclic(300))
    of.wait()
    # ip_offset = cyclic_find(p.corefile.pc)  # x86
    ip_offset = cyclic_find(of.corefile.read(of.corefile.sp, 4)) # x64
    info('located EIP/RIP offset at {a}'.format(a=ip_offset))
    return ip_offset
```
