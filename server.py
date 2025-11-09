import socket
import os
import threading
import json
import hashlib
import hmac
from pathlib import Path

class FileServer:
    def __init__(self, host='127.0.0.1', port=5555):
        self.host = host
        self.port = port
        self.server_socket = None
        self.shared_directory = "server_files"
        self.upload_directory = "server_uploads"
        
        # Security: Simple user database (Day 5)
        self.users = {
            'admin': self.hash_password('admin123'),
            'user1': self.hash_password('password1')
        }
        
        # Secret key for HMAC authentication
        self.secret_key = b'your-secret-key-here'
        
        # Create directories if they don't exist
        Path(self.shared_directory).mkdir(exist_ok=True)
        Path(self.upload_directory).mkdir(exist_ok=True)
        
    def hash_password(self, password):
        """Hash password using SHA-256"""
        return hashlib.sha256(password.encode()).hexdigest()
    
    def generate_token(self, username):
        """Generate authentication token using HMAC"""
        message = f"{username}".encode()
        return hmac.new(self.secret_key, message, hashlib.sha256).hexdigest()
    
    def verify_token(self, username, token):
        """Verify authentication token"""
        expected_token = self.generate_token(username)
        return hmac.compare_digest(expected_token, token)
    
    def start(self):
        """Day 1: Setup server socket communication"""
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server_socket.bind((self.host, self.port))
        self.server_socket.listen(5)
        
        print(f"[*] Server started on {self.host}:{self.port}")
        print(f"[*] Shared directory: {self.shared_directory}")
        print(f"[*] Upload directory: {self.upload_directory}")
        print("[*] Waiting for connections...")
        
        while True:
            try:
                client_socket, address = self.server_socket.accept()
                print(f"[+] Connection from {address}")
                
                # Handle each client in a separate thread
                client_thread = threading.Thread(
                    target=self.handle_client,
                    args=(client_socket, address)
                )
                client_thread.daemon = True
                client_thread.start()
                
            except KeyboardInterrupt:
                print("\n[*] Server shutting down...")
                break
            except Exception as e:
                print(f"[!] Error: {e}")
        
        self.server_socket.close()
    
    def handle_client(self, client_socket, address):
        """Handle individual client connections"""
        authenticated = False
        username = None
        
        try:
            # Day 5: Authentication
            auth_data = self.receive_json(client_socket)
            
            if auth_data and auth_data.get('command') == 'AUTH':
                username = auth_data.get('username')
                password = auth_data.get('password')
                
                if username in self.users and self.users[username] == self.hash_password(password):
                    token = self.generate_token(username)
                    self.send_json(client_socket, {
                        'status': 'success',
                        'message': 'Authentication successful',
                        'token': token
                    })
                    authenticated = True
                    print(f"[+] User '{username}' authenticated from {address}")
                else:
                    self.send_json(client_socket, {
                        'status': 'error',
                        'message': 'Invalid credentials'
                    })
                    client_socket.close()
                    return
            
            # Main command loop
            while authenticated:
                data = self.receive_json(client_socket)
                
                if not data:
                    break
                
                command = data.get('command')
                token = data.get('token')
                
                # Verify token for each command
                if not self.verify_token(username, token):
                    self.send_json(client_socket, {
                        'status': 'error',
                        'message': 'Invalid token'
                    })
                    break
                
                # Day 2: File listing
                if command == 'LIST':
                    self.handle_list(client_socket)
                
                # Day 3: File download
                elif command == 'DOWNLOAD':
                    filename = data.get('filename')
                    self.handle_download(client_socket, filename)
                
                # Day 4: File upload
                elif command == 'UPLOAD':
                    filename = data.get('filename')
                    filesize = data.get('filesize')
                    self.handle_upload(client_socket, filename, filesize)
                
                elif command == 'EXIT':
                    print(f"[-] Client {address} disconnected")
                    break
                
                else:
                    self.send_json(client_socket, {
                        'status': 'error',
                        'message': 'Unknown command'
                    })
        
        except Exception as e:
            print(f"[!] Error handling client {address}: {e}")
        
        finally:
            client_socket.close()
    
    def handle_list(self, client_socket):
        """Day 2: Send list of available files"""
        try:
            files = []
            for filename in os.listdir(self.shared_directory):
                filepath = os.path.join(self.shared_directory, filename)
                if os.path.isfile(filepath):
                    size = os.path.getsize(filepath)
                    files.append({
                        'name': filename,
                        'size': size,
                        'size_readable': self.format_size(size)
                    })
            
            self.send_json(client_socket, {
                'status': 'success',
                'files': files
            })
            print(f"[*] Sent file list: {len(files)} files")
            
        except Exception as e:
            self.send_json(client_socket, {
                'status': 'error',
                'message': str(e)
            })
    
    def handle_download(self, client_socket, filename):
        """Day 3: Send file to client"""
        try:
            filepath = os.path.join(self.shared_directory, filename)
            
            if not os.path.exists(filepath):
                self.send_json(client_socket, {
                    'status': 'error',
                    'message': 'File not found'
                })
                return
            
            filesize = os.path.getsize(filepath)
            
            # Send file metadata
            self.send_json(client_socket, {
                'status': 'success',
                'filesize': filesize
            })
            
            # Send file data
            with open(filepath, 'rb') as f:
                bytes_sent = 0
                while bytes_sent < filesize:
                    chunk = f.read(4096)
                    if not chunk:
                        break
                    client_socket.sendall(chunk)
                    bytes_sent += len(chunk)
            
            print(f"[↓] Sent file: {filename} ({self.format_size(filesize)})")
            
        except Exception as e:
            print(f"[!] Error sending file: {e}")
    
    def handle_upload(self, client_socket, filename, filesize):
        """Day 4: Receive file from client"""
        try:
            filepath = os.path.join(self.upload_directory, filename)
            
            # Send ready signal
            self.send_json(client_socket, {'status': 'ready'})
            
            # Receive file data
            with open(filepath, 'wb') as f:
                bytes_received = 0
                while bytes_received < filesize:
                    chunk = client_socket.recv(min(4096, filesize - bytes_received))
                    if not chunk:
                        break
                    f.write(chunk)
                    bytes_received += len(chunk)
            
            if bytes_received == filesize:
                self.send_json(client_socket, {
                    'status': 'success',
                    'message': 'File uploaded successfully'
                })
                print(f"[↑] Received file: {filename} ({self.format_size(filesize)})")
            else:
                self.send_json(client_socket, {
                    'status': 'error',
                    'message': 'File transfer incomplete'
                })
                
        except Exception as e:
            self.send_json(client_socket, {
                'status': 'error',
                'message': str(e)
            })
            print(f"[!] Error receiving file: {e}")
    
    def send_json(self, sock, data):
        """Send JSON data with length prefix"""
        json_data = json.dumps(data).encode('utf-8')
        length = len(json_data)
        sock.sendall(length.to_bytes(4, 'big'))
        sock.sendall(json_data)
    
    def receive_json(self, sock):
        """Receive JSON data with length prefix"""
        try:
            length_bytes = sock.recv(4)
            if not length_bytes:
                return None
            length = int.from_bytes(length_bytes, 'big')
            
            data = b''
            while len(data) < length:
                chunk = sock.recv(min(4096, length - len(data)))
                if not chunk:
                    return None
                data += chunk
            
            return json.loads(data.decode('utf-8'))
        except:
            return None
    
    def format_size(self, size):
        """Format file size in human-readable format"""
        for unit in ['B', 'KB', 'MB', 'GB']:
            if size < 1024.0:
                return f"{size:.2f} {unit}"
            size /= 1024.0
        return f"{size:.2f} TB"


if __name__ == "__main__":
    server = FileServer()
    
    # Create some sample files for testing
    sample_files = ["sample1.txt", "sample2.txt", "readme.txt"]
    for filename in sample_files:
        filepath = os.path.join(server.shared_directory, filename)
        if not os.path.exists(filepath):
            with open(filepath, 'w') as f:
                f.write(f"This is a sample file: {filename}\n")
                f.write("Created for testing the file sharing system.\n")
    
    print("\n" + "="*50)
    print("FILE SHARING SERVER")
    print("="*50)
    print("\nDefault Users:")
    print("  Username: admin  | Password: admin123")
    print("  Username: user1  | Password: password1")
    print("="*50 + "\n")
    
    server.start()
