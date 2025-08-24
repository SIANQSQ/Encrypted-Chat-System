import pymysql
from datetime import datetime
import tkinter as tk
from tkinter import scrolledtext, ttk
import asyncio
import pygame
import threading
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
import os
DBHOST = 'qsq.cool'
DBPORT = '3306'
DBUSER = 'chat-test'
DBPASS = 'chat-test'
DBNAME = 'chat-test'

ID = 1
playover = 1

def ChangeState(STATE,Target):  #改变收发状态   状态 目标用户
    try:
        db = pymysql.connect(host=DBHOST, user=DBUSER, password=DBPASS, db=DBNAME)
        cur = db.cursor()
        sql = "update content set STA = %s where ID = %s "
        value = (STATE,Target)
        cur.execute(sql,value)
        db.commit()
    except pymysql.Error as e:
        print("mysql Change State error" + str(e))

def ReadState():
    try:
        db = pymysql.connect(host=DBHOST, user=DBUSER, password=DBPASS, db=DBNAME)
        cur = db.cursor()
        sql_read = "SELECT STA FROM content where ID = %s"
        cur.execute(sql_read,ID)
        db.commit()
        return int(cur.fetchone()[0])
    except pymysql.Error as e:
        print("mysql Read State error" + str(e))

def SendMessage(str, Target):
    try:
        db = pymysql.connect(host=DBHOST, user=DBUSER, password=DBPASS, db=DBNAME)
        cur = db.cursor()
        sql_read = "UPDATE content SET INF = %s WHERE ID = %s"
        value = (str,Target)
        cur.execute(sql_read,value)
        db.commit()
    except pymysql.Error as e:
        print("mysql Send Message error" + str(e))

def SendPassword(Password, Target):
    try:
        db = pymysql.connect(host=DBHOST, user=DBUSER, password=DBPASS, db=DBNAME)
        cur = db.cursor()
        sql_read = "UPDATE content SET Password = %s WHERE ID = %s"
        value = (Password,Target)
        cur.execute(sql_read,value)
        db.commit()
    except pymysql.Error as e:
        print("mysql Send Password error" + str(e))

def Register():
    print("注册新用户")
    NID = GetUserNum()+1
    print("请牢记你的ID是 {}".format(NID))
    UserName = input("请设置用户名")
    nosetpasswd = 1
    while nosetpasswd:
        npwd1 = input("设置密码:")
        npwd2 = input("确认密码:")
        if npwd1 != npwd2:
            print("两次密码不相符，请重试")
        else:
            nosetpasswd = 0
    try:
        db = pymysql.connect(host=DBHOST, user=DBUSER, password=DBPASS, db=DBNAME)
        cur = db.cursor()
        sql_ins = 'INSERT INTO content(ID,Password,UserName,STA,FromWho,INF) VALUE(%s,%s,%s,0,0,0)'
        value = (NID,npwd1,UserName)
        cur.execute(sql_ins,value)
        db.commit()
    except pymysql.Error as e:
        print("注册失败，请重新注册！" + str(e))

def GetUserNum():
    try:
        db = pymysql.connect(host=DBHOST, user=DBUSER, password=DBPASS, db=DBNAME)
        cur = db.cursor()
        sql_find = "SELECT * FROM content"
        cur.execute(sql_find)
        db.commit()
        NoU = cur.fetchall()
        return len(NoU)
    except pymysql.Error as e:
        print("mysql Get User Number error" + str(e))

def ReadPassword():
    global ID
    try:
        db = pymysql.connect(host=DBHOST, user=DBUSER, password=DBPASS, db=DBNAME)
        cur = db.cursor()
        sql_read = "SELECT Password FROM content where ID = %s"
        cur.execute(sql_read, ID)
        db.commit()
        return cur.fetchone()[0]
    except pymysql.Error as e:
        print("mysql Read Password error" + str(e))

def SendFromWho(TargetUser):
    global ID
    try:
        db = pymysql.connect(host=DBHOST, user=DBUSER, password=DBPASS, db=DBNAME)
        cur = db.cursor()
        sql_read = "UPDATE content SET FromWho = %s WHERE ID = %s"
        value = (ID,TargetUser)
        cur.execute(sql_read,value)
        db.commit()
    except pymysql.Error as e:
        print("mysql Send FromWho error" + str(e))

def ReadMessage():
    global ID
    try:
        db = pymysql.connect(host=DBHOST, user=DBUSER, password=DBPASS, db=DBNAME)
        cur = db.cursor()
        sql_read = "SELECT INF FROM content where ID = %s"
        cur.execute(sql_read, ID)
        db.commit()
        return cur.fetchone()[0]
    except pymysql.Error as e:
        print("mysql Read State error" + str(e))

def ReadFromWho():
    global ID
    try:
        db = pymysql.connect(host=DBHOST, user=DBUSER, password=DBPASS, db=DBNAME)
        cur = db.cursor()
        sql_read = "SELECT FromWho FROM content where ID = %s"
        cur.execute(sql_read, ID)
        db.commit()
        return cur.fetchone()[0]
    except pymysql.Error as e:
        print("mysql Read State error" + str(e))

def ReadUserName(FromUser):
    try:
        db = pymysql.connect(host=DBHOST, user=DBUSER, password=DBPASS, db=DBNAME)
        cur = db.cursor()
        sql_read = "SELECT UserName FROM content where ID = %s"
        cur.execute(sql_read, FromUser)
        db.commit()
        return cur.fetchone()[0]
    except pymysql.Error as e:
        print("mysql Read UserName error" + str(e))

def ReadUserID(UserName):
    try:
        db = pymysql.connect(host=DBHOST, user=DBUSER, password=DBPASS, db=DBNAME)
        cur = db.cursor()
        sql_read = "SELECT ID FROM content where UserName = %s"
        cur.execute(sql_read, UserName)
        db.commit()
        return int(cur.fetchone()[0])
    except pymysql.Error as e:
        print("mysql Read ID error" + str(e))

def GetAllUser():
    try:
        db = pymysql.connect(host=DBHOST, user=DBUSER, password=DBPASS, db=DBNAME)
        cur = db.cursor()
        sql_read = "SELECT UserName FROM content where 1"
        cur.execute(sql_read)
        db.commit()
        return cur.fetchall()
    except pymysql.Error as e:
        print("mysql Read All User error" + str(e))
class ChatWindow:
    def __init__(self, master):
        self.master = master
        master.title("用户名: "+ReadUserName(ID))

        # Create and configure the message display area
        self.message_area = scrolledtext.ScrolledText(master, wrap=tk.WORD, width=50, height=20)
        self.message_area.grid(row=0, column=0, columnspan=3, padx=10, pady=10)
        self.message_area.config(state=tk.DISABLED)

        # Create the recipient selection dropdown
        self.recipients = GetAllUser()#["选择聊天对象", "屈圣桥", "陈宇", "李凤坤", "郑天喆", "刘佳雨"]
        self.recipient_var = tk.StringVar(master)
        self.recipient_dropdown = ttk.Combobox(master, textvariable=self.recipient_var, values=self.recipients,
                                               state="readonly", width=15)
        self.recipient_dropdown.grid(row=1, column=0, columnspan=2, padx=10, pady=5)
        self.recipient_var.set(self.recipients[0])  # default value

        # Create the message input field
        self.input_field = tk.Entry(master, width=40)
        self.input_field.grid(row=2, column=0, columnspan=2, padx=10, pady=10)

        # Create the send button
        self.send_button = tk.Button(master, text="Send", command=self.send_message)
        self.send_button.grid(row=2, column=2, padx=10, pady=10)

        # Bind the Enter key to send_message function
        self.input_field.bind("<Return>", lambda event: self.send_message())

        # Start the asyncio event loop in a separate thread
        self.loop = asyncio.new_event_loop()
        threading.Thread(target=self.start_asyncio_loop, daemon=True).start()

    def send_message(self):
        message = self.input_field.get()
        recipient = self.recipient_var.get()
        if message:
            key = generate_key()
            TargetUser = ReadUserID(recipient)
            self.display_message(ReadUserName(ID), f"[To {recipient}] {message}")
            self.input_field.delete(0, tk.END)
            SendMessage(encrypt(message, key), TargetUser)   #发送以string模式
            SendFromWho(TargetUser)  # 告诉接收方谁给你发的
            ChangeState(1, TargetUser)
            PlayBeep('beepsen.mp3')


    def receive_message(self, sender, message):
        self.master.after(0, self.display_message, sender, message)

    def display_message(self, sender, message):
        self.message_area.config(state=tk.NORMAL)
        self.message_area.insert(tk.END, f"{sender}: {message}\n")
        self.message_area.config(state=tk.DISABLED)
        self.message_area.see(tk.END)

    def start_asyncio_loop(self):
        asyncio.set_event_loop(self.loop)
        self.loop.run_forever()

    async def check_for_messages(self):
        while True:
            if ReadState() == 1:
                PlayBeep('beeprec.mp3')
                From = int(ReadFromWho())  # 得到发送方ID
                sender = ReadUserName(From)
                key = get_key(From)
                message = decrypt(ReadMessage(), key)  #接收以string模式，转成byte再解密
                self.receive_message(sender, message)
                ChangeState(0, ID)

def PlayBeep(file_path):
    pygame.mixer.init()
    pygame.mixer.music.load(file_path)
    pygame.mixer.music.play()





def generate_key():

    global ID
    IDStr=str(ID)
    KeyID=""  #ID向量
    if len(IDStr)==1:
        KeyID = "---"+IDStr
    elif len(IDStr)==2:
        KeyID = "--" + IDStr
    elif len(IDStr)==3:
        KeyID = "-"+ IDStr
    elif len(IDStr) == 4:
        KeyID = "" + IDStr

    current_time = datetime.now()
    # 使用系统时间加密
    formatted_time = current_time.strftime("%Y%m%d%H%M")
    key = (formatted_time+KeyID).encode('utf-8')
    return key

def get_key(FromUser):
    IDStr=str(FromUser)
    KeyID=""  #ID向量
    if len(IDStr)==1:
        KeyID = "---"+IDStr
    elif len(IDStr)==2:
        KeyID = "--" + IDStr
    elif len(IDStr)==3:
        KeyID = "-"+ IDStr
    elif len(IDStr) == 4:
        KeyID = "" + IDStr
    current_time = datetime.now()
    formatted_time = current_time.strftime("%Y%m%d%H%M")
    key = (formatted_time + KeyID).encode('utf-8')
    return key

def encrypt(plaintext, key):
    """对称加密"""
    # 填充明文，使其长度符合块大小要求
    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    padded_data = padder.update(plaintext.encode()) + padder.finalize()

    # 初始向量（IV）

    iv = os.urandom(16)

    # 创建AES加密器
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()

    # 加密数据
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()

    # 返回IV和密文
    return iv + ciphertext


def decrypt(ciphertext, key):
    """对称解密"""
    # 提取IV和密文
    iv = ciphertext[:16]
    actual_ciphertext = ciphertext[16:]

    # 创建AES解密器
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()

    # 解密数据
    padded_plaintext = decryptor.update(actual_ciphertext) + decryptor.finalize()

    # 去除填充
    unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
    plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()

    # 返回明文
    return plaintext.decode()




if __name__ == "__main__":
    print("实时加密，尽享聊天乐趣！")
    print("目前共有 " + str(GetUserNum()) + " 名用户")

    NoReg = 1
    Nologin = 1
    Noenter = 1
    while NoReg:
        order = int(input("1 登录 2 注册\n请输入: "))
        if order == 1:
            NoReg = 0
        elif order == 2:
            Register()
            NoReg = 0
    while Nologin:
        ID = input("请输入您的客户端ID: ")
        PWD = input("请输入密码: ")
        if PWD == ReadPassword():
            Nologin = 0
        else:
            print("密码错误，请重试")
    while Noenter:
        order = int(input("1 启动聊天 2 更改密码\n请输入: "))
        if order == 2:
            npwd1 = input("新的密码: ")
            npwd2 = input("确认密码: ")
            if npwd1 != npwd2:
                print("两次密码不符，请重试")
            else:
                SendPassword(npwd1, ID)
        elif order == 1:
            Noenter = 0

    ChangeState(0, ID)
    print("启动聊天窗口")
    root = tk.Tk()
    chat_app = ChatWindow(root)

    # Start the async message checking
    asyncio.run_coroutine_threadsafe(chat_app.check_for_messages(), chat_app.loop)
    root.mainloop()




'''
key = generate_key()
    print(f"Generated Key: {key.hex()}")

    plaintext = "你好我是屈圣桥"
    print(f"未加密: {plaintext}")

    ciphertext = encrypt(plaintext, key)
    print(f"加密后: {ciphertext.hex()}")

    decrypted_plaintext = decrypt(ciphertext, key)
    print(f"解密后: {decrypted_plaintext}")
'''
