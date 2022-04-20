# Python 101 for hackers (The Cyber Mentor)
Some collection of things I found most useful from this course.

# Table of Contents
Basics
1. [Comprehensions](#Comprehensions)
2. [Inputs](#Inputs)
3. [Read and Write](#Read-and-Write)
4. [Lambdas](#Lambdas)
5. [Other python Sorcery](#other-python-sorcery)

Extending python

6. [Python package manager](#Python-package-manager)
7. [Python virtual environments](#Python-virtual-environments)
8. [Sys](#Sys)
9. [Requests](#Requests)
10. [Pwntools](#Pwntools)


## Comprehensions
```python
import string

list1 = ['a','b','c']
print(list1)

list2 = [x for x in list1]
print(list2)

list3 = [y for y in list1 if y =='a']
print(list3)

list4 = [x for x in range(5)]
print(list4)

list5 = [x for x in string.ascii_letters]
print(list5)


list6 = [hex(x) for x in range(5)]
print(list6)


list6 = [hex(x) if x > 0 else "REPLACED" for x in range(5)]
print(list6)


list7 = [x * x for x in range(5)]
print(list7)

list8 = [x for x in range(5) if x == 0 or x == 1]
print(list8)

list9 = [[1,2,3],[4,5,6],[7,8,9]]
print(list9)

list10 = [y for x in list9 for y in x]
print(list10)

set1 = {x + x for x in range(5)}
print(set1)

list11 = [c for c in "string"]
print(list11)

print("".join(list11))
print("-".join(list11))

list12 = []
for c in "string":
	list12.append(c)
print(list12)
```


## Inputs
```python
while True:
	test = input("Enter the IP: ")
	print (">>> {}".format(test))
	if test == "exit":
		break
	else:
		print("exploiting..")
```

## Read and Write
```python

f = open('names.txt')
print(f)

f = open('names.txt', 'rt')
print(f)

print(f.readlines())
print(f.readlines())


f.seek(0)
for line in f:
	print(line.strip())

f = open("test.txt", "a")
f.write("test 2!")
f.close()

print(f.name)
print(f.closed)
print(f.mode)


with open("names.txt") as f:
	for l in f:
		pass

```

## Lambdas
Anonymous functions without name

```python

# a lambdas is a anonymous function without a name

# take a argument x, then evaluate x + 4
add_4 = lambda x : x + 4
print(add_4(4))

add = lambda x, y: x + y
print(add(10,4))


def addf(x,y):
	return x+y

print(addf(10,4))

# single line
print((lambda x,y: x + y)(10,4))

# lambda is useful for quick 1 liner hacking scripts like such
# to check if value is an even number
is_even = lambda x: x % 2 == 0
print(is_even(2))
```

## Other python Sorcery

### Break input x into arrays of y length

WHAT SORCERY IS THIS?!
```python
blocks = lambda x,y: [x[i:i+y] for i in range(0, len(x), y)]
print(blocks("string",2))
#['st', 'ri', 'ng']
```

### Returns integer representation of each character
```python
# DAMN!
# Returns integer representations of each character
to_ord = lambda x: [ord(i) for i in x]
print(to_ord("ABCD"))

# Same thing as above but more lines
def to_ord(x):
	ret = []
	for i in x:
		ret.append(ord(i))
	return ret

print(to_ord2("ABCD"))
#[65, 66, 67, 68]
```


## Python package manager
https://pypi.org find packages info,installation,guide,documentation

### pip to install
```
pip install pwntools
```

### list packages
```bash
pip list

# Show version of packages
pip freeze
#bcrypt==3.2.0
#capstone==5.0.0rc2
#certifi==2021.10.8
#cffi==1.15.0
```
### requirements.txt
Create a specific list of dependencies of packages to install

```bash
# use `pip freeze` to get the specific version of packages
# eg. create a requirements.txt and you would want a specific list of packages with version info such as

#pwntools==4.7.0
#pycparser==2.21
#pyelftools==0.28

vim requirements.txt

# install those defined packages
pip install -r requirements.txt

```

## Python virtual environments
What if you need to use certain version of packages for 1 script and another for others. The dependency nightmare can be solved using virtual environments: you create containers that isolate each environment (creating a "world" independent from others)

```bash
# install 
pip install virtualenv


# create dir
mkdir world
python -m venv env

# on linux
source env/bin/activate

# windows
powershell -ep bypass
.\env\Scripts\activate


# if you run the following, observe that the packages installed are limited as you are in the newly created container (Not the main hosts')
pip list
pip freeze

# To finish using
deactivate
```

## Sys

```python
import sys

print(sys.version)
# 3.10.2 (tags/v3.10.2:a58ebcc

print(sys.executable)
# C:\Users\Asd\AppData\Local\Programs\Python\Python310\python.exe

print(sys.platform)
# win32

print(sys.path)
# [C:\\Users\\Asd...]

print(sys.modules)
# {'sys': <module 'sys' (built-in)>, 'builtins': <module 'builtins' (built-in)>, '_frozen_importlib': <module '_frozen_importlib' (frozen)>, '_imp': <module '_imp' (built-in)>, '_thread': <module '_thread' (built-in)>, '_warnings': <module '_warnings' (built-in)>, '_weakref'


# Progress status bar
import time

for i in range(0, 51):
	time.sleep(0.001)
	sys.stdout.write("{} [{}{}]\r".format(i, '#'*i, "."*(50-i)))
	sys.stdout.flush()

sys.stdout.write("\n")


# Read parameters provided to your program
if len(sys.argv) != 3:
	print("[X] To run '{}' enter a username and password".format(sys.argv[0]))
	sys.exit(777)

# [X] To run '.\sys.py' enter a username and password
	
username = sys.argv[1]
password = sys.argv[2]

```

## Requests
```python

import requests

x = requests.get('http://httpbin.org/get')

# get all headers
print(x.headers)

# get only server header
print(x.headers['Server'])

# print status code
print(x.status_code)

if x.status_code == 200:
	print("Success!")
elif x.status_code == 404:
	print("Not found!")

# timing requests
print(x.elapsed)

# print cookies
print(x.cookies)

# Get params
x = requests.get('http://httpbin.org/get', params={'id':'1'})
print(x.url)


# send files
files = {'file': open('google.png', 'rb')}
x = requests.post('http://httpbin.org/post', files=files)
print(x.text)

# basic auth
x = requests.get('http://httpbin.org/get', auth=('username','password'))
print(x.text)

# don't verify SSL
x = requests.get('https://expired.badssl.com', verify=False)

# disallow redirects
x = requests.get('https://github.com', allow_redirects=False)
print(x.headers)

# add cookies to Session so you dont have to keep typing it
x = requests.Session()
x.cookies.update({'a':'b'})
print(x.get('http://httpbin.org/cookies').text)


# Get image and write to file
x = requests.get('https://about.google/assets-stories-2021/img/glue-google-color-logo.svg')
with open('google2.svg', 'wb') as f:
	f.write(x.content)
```


## Pwntools