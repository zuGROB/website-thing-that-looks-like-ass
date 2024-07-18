from http.server import HTTPServer, SimpleHTTPRequestHandler
from socketserver import ThreadingMixIn
import os
import random
import threading
import json
import urllib.parse
import re
from collections import defaultdict
from datetime import datetime, timedelta
import shutil

# Пути к файлам
COMMENTS_FILE = 'comments.json'
BANNED_IPS_FILE = 'banned_ips.json'

# Глобальные переменные
comments = {}
banned_ips = set()
suspicious_activity = defaultdict(list)

# Список паттернов подозрительных запросов
SUSPICIOUS_PATTERNS = [
    r'(?i)(nmap|nikto|wikto|sf|sqlmap|bsqlbf|w3af|acunetix|havij|appscan)',
    r'/\.[^/]*$',
    r'(?i)\.(asp|aspx|jsp|cgi|exe|bat|cmd|sh|pl)$',
    r'(?i)etc/passwd',
    r'(?i)etc/shadow',
    r'(?i)proc/self/environ',
    r'(?:/\.\.){2,}',  # Дополнительный паттерн для path traversal
    r'(?i)admin',
    r'(?i)password',
    r'(?i)login',
    r';&|&&|\|\||;',  # Разделители команд
    r'\bping\b|\bnetcat\b|\bnc\b|\btelnet\b|\bnetstat\b',
    r'\bchmod\b|\bchown\b|\bchgrp\b|\bmkdir\b',
    r'(?i)(include|require)(_once)?\s*\(',
    r'(?i)upload\s*\(',
    r'<script.*?>',
    r'(?i)on\w+\s*=',  # Обработчики событий
    r'(?i)javascript:',
    r'phpMyAdmin',
    r'.env',
    r'cgi',
    r'HNAP',
    r'conf.bin',
    r'/cgi-bin/',
    r'setup.cgi',
    r'cmd=rm+-rf',
    r'wget+http://',
    r'\$\(.*\)',  # Попытки выполнения команд
    r'eval\(',    # Попытки выполнения кода
    r'base64_decode\(',
    r'(?:\.\.\/){2,}',  # Path traversal
]

# Функции для работы с файлами
def load_json(filename, default):
    try:
        with open(filename, 'r') as f:
            return json.load(f)
    except FileNotFoundError:
        return default

def save_json(filename, data):
    with open(filename, 'w') as f:
        json.dump(data, f)

def load_comments():
    global comments
    comments = load_json(COMMENTS_FILE, {})

def save_comments():
    save_json(COMMENTS_FILE, comments)

def load_banned_ips():
    global banned_ips
    banned_ips = set(load_json(BANNED_IPS_FILE, []))

def save_banned_ips():
    save_json(BANNED_IPS_FILE, list(banned_ips))

# Функции для обработки подозрительной активности
def is_suspicious(path):
    return any(re.search(pattern, path) for pattern in SUSPICIOUS_PATTERNS)

def record_suspicious_activity(ip):
    now = datetime.now()
    suspicious_activity[ip].append(now)
    
    # Удаляем старые записи (старше 1 часа)
    suspicious_activity[ip] = [t for t in suspicious_activity[ip] if now - t < timedelta(hours=1)]
    
    # Если более 0 подозрительных запросов за час, баним IP
    if len(suspicious_activity[ip]) > 0:
        return ban_ip(ip)
    return None

def ban_ip(ip):
    banned_ips.add(ip)
    save_banned_ips()
    print(f"IP {ip} забанен за подозрительную активность")
    return "KILL YOURSELF!"

# Функция для поиска изображений
def find_images():
    image_extensions = ('.jpg', '.jpeg', '.png', '.gif', '.bmp')
    images = []
    user_profile = os.path.expanduser('~')
    folders_to_search = ['Downloads', 'Documents', 'Pictures']
    
    for folder in folders_to_search:
        folder_path = os.path.join(user_profile, folder)
        if os.path.exists(folder_path):
            for root, _, files in os.walk(folder_path):
                for file in files:
                    if file.lower().endswith(image_extensions):
                        images.append(os.path.join(root, file))
    
    return images

# HTML контент
html_content = open('mainpage.html', 'r', encoding='utf-8').read()

# Обработчик HTTP-запросов
class MyHandler(SimpleHTTPRequestHandler):
    def do_GET(self):
        client_ip = self.client_address[0]
        
        if client_ip in banned_ips:
            self.send_error(403, "KILL YOURSELF!")
            return
        
        if is_suspicious(self.path):
            message = record_suspicious_activity(client_ip)
            if message:
                self.send_response(403)
                self.send_header('Content-type', 'text/plain')
                self.end_headers()
                self.wfile.write(message.encode())
                return
            self.send_error(400, "Bad Request")
            return
        
        if self.path == '/':
            self.send_response(200)
            self.send_header('Content-type', 'text/html')
            self.end_headers()
            self.wfile.write(html_content.encode())
        elif self.path == '/favicon.ico':
            try:
                with open('favicon.ico', 'rb') as f:
                    self.send_response(200)
                    self.send_header('Content-type', 'image/x-icon')
                    self.end_headers()
                    self.wfile.write(f.read())
            except FileNotFoundError:
                self.send_error(404, "Favicon not found")
        elif self.path == '/random_image':
            if all_images:
                image_path = random.choice(all_images)
                try:
                    with open(image_path, 'rb') as f:
                        self.send_response(200)
                        self.send_header('Content-type', self.guess_type(image_path))
                        self.send_header('X-Image-Path', image_path)
                        self.end_headers()
                        self.wfile.write(f.read())
                    print(f"Запрошена картинка: {image_path}")
                except Exception as e:
                    print(f"Ошибка при открытии файла {image_path}: {e}")
                    self.send_error(500, "Internal server error")
            else:
                self.send_error(404, "No images found")
        elif self.path.startswith('/get_comments'):
            query = urllib.parse.urlparse(self.path).query
            params = urllib.parse.parse_qs(query)
            image_path = params.get('image_path', [''])[0]
            self.send_response(200)
            self.send_header('Content-type', 'application/json')
            self.end_headers()
            self.wfile.write(json.dumps(comments.get(image_path, [])).encode())
        elif self.path == '/minecraft':
            self.send_response(200)
            self.send_header('Content-type', 'text/html')
            self.end_headers()
            with open('minecraft.html', 'rb') as f:
                self.wfile.write(f.read())
    
        elif self.path == '/download_modpack':
            modpack_path = r'C:\Users\user\Documents\WEB\data\modpack.zip'
            if os.path.exists(modpack_path):
                file_size = os.path.getsize(modpack_path)
                self.send_response(200)
                self.send_header('Content-type', 'application/zip')
                self.send_header('Content-Disposition', 'attachment; filename="modpack.zip"')
                self.send_header('Content-Length', str(file_size))
                self.end_headers()
                with open(modpack_path, 'rb') as f:
                    buffer_size = 64 * 1024  # 64 KB буфер
                    while True:
                        buffer = f.read(buffer_size)
                        if not buffer:
                            break
                        self.wfile.write(buffer)
            else:
                self.send_error(404, "Modpack not found")
        else:
            super().do_GET()

    def do_POST(self):
        client_ip = self.client_address[0]
        
        if client_ip in banned_ips:
            self.send_error(403, "COOK YOURSELF!")
            return
        
        if is_suspicious(self.path):
            message = record_suspicious_activity(client_ip)
            if message:
                self.send_response(403)
                self.send_header('Content-type', 'text/plain')
                self.end_headers()
                self.wfile.write(message.encode())
                return
            self.send_error(400, "Bad Request")
            return
        
        if self.path == '/add_comment':
            content_length = int(self.headers['Content-Length'])
            post_data = self.rfile.read(content_length).decode('utf-8')
            params = urllib.parse.parse_qs(post_data)
            image_path = params.get('image_path', [''])[0]
            comment = params.get('comment', [''])[0]
            
            if image_path and comment:
                if image_path not in comments:
                    comments[image_path] = []
                comments[image_path].append(comment)
                
                save_comments()
                
                self.send_response(200)
                self.send_header('Content-type', 'application/json')
                self.end_headers()
                self.wfile.write(json.dumps({"status": "success"}).encode())
            else:
                self.send_error(400, "Bad Request")
        else:
            self.send_error(404, "Not Found")

    def guess_type(self, path):
        if path.lower().endswith(('.jpg', '.jpeg')):
            return 'image/jpeg'
        elif path.lower().endswith('.png'):
            return 'image/png'
        elif path.lower().endswith('.gif'):
            return 'image/gif'
        elif path.lower().endswith('.bmp'):
            return 'image/bmp'
        else:
            return 'application/octet-stream'

class ThreadedHTTPServer(ThreadingMixIn, HTTPServer):
    """Handle requests in a separate thread."""

def run_server(port=80):
    server_address = ('', port)
    httpd = ThreadedHTTPServer(server_address, MyHandler)
    print(f'Многопоточный сервер запущен на порту {port}')
    print(f'Количество найденных изображений: {len(all_images)}')
    print(f'Текущее количество активных потоков: {threading.active_count()}')
    httpd.serve_forever()

if __name__ == '__main__':
    load_comments()
    load_banned_ips()
    all_images = find_images()
    
    try:
        run_server()
    except PermissionError:
        print("Ошибка: Недостаточно прав для использования порта 80.")
        print("Попробуйте запустить скрипт с правами администратора или использовать порт выше 1024.")
        port = int(input("Введите номер порта (например, 8080): "))
        run_server(port)
