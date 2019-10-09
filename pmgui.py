import tkinter
import tkinter.messagebox
import hashlib
from cryptography.fernet import Fernet
import base64
import os
from tkinter import Frame
from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
# password = b"SatyaSatzz"

salt = b'\xddL\xa7\xbf\xda\nK\xbc\xf1\xf23\x02\x15\x08\xca\x9e'
kdf = PBKDF2HMAC(
    algorithm=hashes.SHA256(),
    length=32,
    salt=salt,
    iterations=100000,
    backend=default_backend()
)
# key = base64.urlsafe_b64encode(kdf.derive(password))
key=b'79zEqKGIv49Ku6sxUDlWCTSuKoQ55_osIgkb2bYJEKM='
cipher_suite = Fernet(key)

windows = tkinter.Tk()
window=Frame(windows)
window.pack()
windows.title("P-Manager")



def add(web,usn,pas):
    labelll1 = tkinter.Label(window, text = "Added Successfully").pack()

    w=web.get()

    # x=input("Website")
    f=open("pm.txt", "a+")
    f.write(web.get()+"\t")
    # y=input("User name")
    # z=input("password")
    ey = cipher_suite.encrypt(str(usn.get()).encode())
    ez = cipher_suite.encrypt(str(pas.get()).encode())

    f.close()
    f=open("pm.txt", "ab")
    f.write(ey)
    f.close()
    f=open("pm.txt", "a")
    f.write("\t")
    f.close()
    f=open("pm.txt", "ab")
    f.write(ez)
    f.close()
    f=open("pm.txt", "a")
    f.write("\n")


def addb():
    # window= tkinter.Tk()
    global window
    window.destroy()
    window=Frame(windows)

    web= tkinter.StringVar()

    usn= tkinter.StringVar()
    pas= tkinter.StringVar()
    label1 = tkinter.Label(window, text = "Website" ).pack()

    num0 = Entry(window,textvariable=web).pack()

    labe2 = tkinter.Label(window, text = "UserName" ).pack()

    num1 = Entry(window,textvariable=usn).pack()
    label3 = tkinter.Label(window, text = "Password").pack()

    num2 = Entry(window,textvariable=pas).pack()

    adall= tkinter.Button(window, text ="ADDl", command = lambda: add(web,usn,pas)).pack()
    home= tkinter.Button(window, text ="Home", command = lambda: homee()).pack()

    window.pack()
    window.mainloop()

    # add(wwww,usn,pas)


def view():
    home= tkinter.Button(window, text ="Home", command = lambda: homee()).pack()

    f=open("pm.txt", "rb")

    f1=f.readlines()
    arr=[]
    for i in f1:

        passu=i.split()
        arr.append(passu[0])

        arr.append(cipher_suite.decrypt(passu[1]).decode())
        arr.append(cipher_suite.decrypt(passu[2]).decode())
    z=tkinter.Text(window)
    z.pack()
    ch=0
    while(ch<len(arr)):
        z.insert(tkinter.END,str(arr[ch].decode())+"\t"+str(arr[ch+1])+"\t"+str(arr[ch+2])+"\n")
        ch=ch+3

from tkinter import *
def homee():
    global window
    window.destroy()
    window=Frame(windows)
    ad= tkinter.Button(window, text ="ADD", command = lambda: addb()).pack()

    vw = tkinter.Button(window, text ="VIEW", command = lambda: view()).pack()

    window.pack()
    windows.mainloop()
def logg(pwdd):
    global key

    pwaa=base64.urlsafe_b64encode(kdf.derive(pwdd.get().encode()))
    print(pwaa)


    if(pwaa==key):
        homee()

def main():

    pwdd= tkinter.StringVar()
    label1 = tkinter.Label(window, text = "Password" ).pack()

    pwdEntry= Entry(window,textvariable=pwdd).pack()

    print(pwdd)
    Login = tkinter.Button(window, text ="LOGIN", command = lambda: logg(pwdd)).pack()



    window.pack()
    windows.mainloop()
main()
