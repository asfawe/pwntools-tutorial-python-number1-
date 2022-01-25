from hashlib import md5
from pwn import *

print(cyclic(50))
print(cyclic_find("laaa"))

print(shellcraft.sh())
print(hexdump(asm(shellcraft.sh())))

print(p32(0x13371337))
print(hex(u32(p32(0x13371337))))

l = ELF('/bin/bash')

print(hex(l.address))
print(hex(l.entry))

print(hex(l.got['write']))
print(hex(l.plt['write']))

for address in l.search(b'/bin/sh\x00'):
    print(hex(address))

print(hex(next(l.search(asm('jmp esp')))))

r = ROP(l)
print(r.rbx)

print(xor(xor("A", "B"), "A"))
print(b64e(b"test"))
print(b64e(b"dGVzdA=="))
print(md5sumhex(b'hello'))
# print(shalsumhex(b'hello'))

print(bits(b'a'))


# p = process("/bin/sh")
# p.sendline("echo hello;")
# p.interactive()

# r = process("127.0.0.1", 1234)
# r.sendline("hello")
# r.interactive()
# r.close()