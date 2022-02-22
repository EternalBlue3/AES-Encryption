import random, base64, hashlib, tkinter
from tkinter import Label, StringVar, Text
from tkinter.constants import DISABLED, NORMAL
from Crypto import Random
from Crypto.Cipher import AES

# Encryption Algorithms

chars = "1234567890abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWKYZ~`!@#$%^&*()_+-={}|\][:;'<,>.?/\""

def generate_key(*length):
    value = []
    flag = 0
    try:
        for i in range(length[0]):
            v = chars[random.randint(0,94)]
            value.append(v)
    except:
        for i in range(random.randint(8,32)):
            v = chars[random.randint(0,93)]
            value.append(v)
    
    return ''.join(value)

class AESCipher():
    def __init__(self, key):
        self.bs = AES.block_size
        self.key = hashlib.sha3_256(key.encode()).digest()

    def encrypt(self, raw):
        raw = self._pad(raw)
        iv = Random.new().read(AES.block_size)
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        return base64.b64encode(iv + cipher.encrypt(raw.encode())).decode()

    def decrypt(self, enc):
        enc = base64.b64decode(enc)
        iv = enc[:AES.block_size]
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        return self._unpad(cipher.decrypt(enc[AES.block_size:])).decode('utf-8')

    def _pad(self, s):
        return s + (self.bs - len(s) % self.bs) * chr(self.bs - len(s) % self.bs)

    @staticmethod
    def _unpad(s):
        return s[:-ord(s[len(s)-1:])]

def tkinterEncrypt():
    global encryption_output
    enckey = keyinput.get()
    message = Message.get()
    encryption_output.set(str(AESCipher(enckey).encrypt(message)))
    
def tkinterDecrypt():
    global encryption_output
    deckey = keyinput.get()
    message = Message.get()
    try:
        encryption_output.set(str(AESCipher(deckey).decrypt(message)))
    except:
        encryption_output.set("An Error Occurred")
            
def tkinterCopy():
    global encryption_output
    app.clipboard_clear()
    app.clipboard_append(encryption_output.get())

# GUI
version = 1.1
bgcolor = '#25b8ea'

def auto_generate_key():
    v = len(str(keyinput.get()))
    for i in range(v):
        keyinput.delete(v - (i+1))
    keyinput.insert('end',str(generate_key(random.randint(3,24))))

app = tkinter.Tk()
app.config(bg=bgcolor)
app.geometry('1100x900')
app.title(f'AES Encrypt v{version}')
app.resizable(False, False)
canvas = tkinter.Canvas(app, width=1100, height=900, bg=bgcolor)
canvas.place(x=0, y=0)

encryption_output = StringVar()
decryptbuttontext = StringVar()
encryptbuttontext = StringVar()
computergenerationtext = StringVar()
copybtntext = StringVar()

titlelbl = tkinter.Label(app, text = f'AES Encryptor v{version}', bg=bgcolor, font='Arial 40 bold', fg='blue')
titlelbl.pack(pady=40)

enclabel = tkinter.Label(app, text = 'Enter a message to Encrypt:', font='Arial 20 bold', fg='white', bg=bgcolor)
enclabel.pack()

Message = tkinter.Entry(app, font = 'Arial 15 bold', bd=0)
Message.pack(pady=20)

keylabel = tkinter.Label(app, text = 'Enter a key:', font='Arial 20 bold', fg='white', bg=bgcolor)
keylabel.pack()

keyinput = tkinter.Entry(app, font = 'Arial 15 bold', bd=0)
keyinput.pack(pady=20)

AutoKey = tkinter.Button(app, textvariable=computergenerationtext, font='Arial 15 bold', bd=0, bg='white', command=auto_generate_key)
AutoKey.pack()
computergenerationtext.set("Computer Generate Key")

encbtn = tkinter.Button(app, textvariable=encryptbuttontext, font='Arial 15 bold', bd=0, bg='white', command=tkinterEncrypt)
encbtn.pack(pady=20)
encryptbuttontext.set("Encrypt")

decbtn = tkinter.Button(app, textvariable=decryptbuttontext, font='Arial 15 bold', bd=0, bg='white', command=tkinterDecrypt)
decbtn.pack(pady=0)
decryptbuttontext.set("Decrypt")

outputtext = tkinter.Label(app, textvariable=encryption_output, font='Monsterrat 10 bold', bg='#25076c', fg='white')
outputtext.pack(pady=20)

copybtn = tkinter.Button(app, textvariable=copybtntext, font='Arial 8 bold', bd=0, bg='white', command=tkinterCopy)
copybtn.pack(pady=8)
copybtntext.set("Copy output to clipboard")

app.mainloop()
