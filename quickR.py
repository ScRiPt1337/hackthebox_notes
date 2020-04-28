import os
import socket

import pyscreenshot as ImageGrab
import zbarlight
from PIL import Image

host = "docker.hackthebox.eu"
port = 32137
s = socket.socket()
s.connect((host, port))

x = 1

with open('received_file', 'wb') as f:
    print('file opened')
    while True:
        print('receiving data...')
        data = s.recv(1024)
        if x == 0:
            print('data=%s', (data))
            if "string: " in str(data):
                break
            f.write(data)
        else:
            if "you got only 3 seconds!" in str(data):
                x = 0

f.close()
os.system("clear")
os.system("cat received_file")
im = ImageGrab.grab(bbox=(30, 50, 700, 700)) 
im.save('screenshot.png')
file_path = 'screenshot.png'
with open(file_path, 'rb') as image_file:
    image = Image.open(image_file)
    image.load()

codes = str(zbarlight.scan_codes(['qrcode'], image))
print('QR codes: %s' % codes)
data = codes.replace("R codes: [b'", "")
data = data.replace(" = ']", "")
data = data.replace("[b'","")
data = data.replace("x", "*")
print(data)
script = eval(data)
lol = str(script)+"\n"
print(script)
s.sendall(lol.encode())
x = s.recv(1024)
print(x)
s.close()
