import socket
import os
import json
import hashlib
from pathlib import Path

class FileClient:
    def __init__(self, host='127.0.0.1', port=5555):
        self.host = host
        self.port = port
        self.client_socket = None
        self.download_directory = "client_downloads"
        self.authenticated = False
        self.token = None
        self.username = None
        
        # Create download directory if it doesn't exist
        Path(self.download_directory).mkdir(exist_ok=True)
    
    def connect(self):
        """Day 1: Connect to server"""
        try:
            self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.client_socket.connect((self.host, self.port))
            print(f"[+] Connected to server at {self.host}:{self.port}")
            return True
        except Exception as e:
            print(f"[!] Connection failed: {e}")
            return False
    
    def authenticate(self, username, password):
        """Day 5: Authenticate with server"""
        try:
            # Send authentication request
            self.send_json({
                'command': 'AUTH',
                'username': username,
                'password': password
            })
            
            # Receive response
            response = self.receive_json()
            
            if response and response.get('status') == 'success':
                self.authenticated = True
                self.token = response.get('token')
                self.username = username
                print(f"[+] {response.get('message')}")
                return True
            else:
                print(f"[!] Authentication failed: {response.get('message', 'Unknown error')}")
                return False
                
        except Exception as e:
            print(f"[!] Authentication error: {e}")
            return False
    
    def list_files(self):
        """Day 2: Request and display file list"""
        if not self.authenticated:
            print("[!] Not authenticated")
            return None
        
        try:
            self.send_json({
                'command': 'LIST',
                'token': self.token
            })
            
            response = self.receive_json()
            
            if response and response.get('status') == 'success':
                files = response.get('files', [])
                
                if not files:
                    print("\n[*] No files available on server")
                    return []
                
                print("\n" + "="*70)
                print("AVAILABLE FILES")
                print("="*70)
                print(f"{'No.':<5} {'Filename':<40} {'Size':<15}")
                print("-"*70)
                
                for idx, file_info in enumerate(files, 1):
                    print(f"{idx:<5} {file_info['name']:<40} {file_info['size_readable']:<15}")
                
                print("="*70 + "\n")
                return files
            else:
                print(f"[!] Error: {response.get('message', 'Unknown error')}")
                return None
                
        except Exception as e:
            print(f"[!] Error listing files: {e}")
            return None
    
    def download_file(self, filename):
        """Day 3: Download file from server"""
        if not self.authenticated:
            print("[!] Not authenticated")
            return False
        
        try:
            # Request file
            self.send_json({
                'command': 'DOWNLOAD',
                'filename': filename,
                'token': self.token
            })
            
            # Receive metadata
            response = self.receive_json()
            
            if not response or response.get('status') != 'success':
                print(f"[!] Error: {response.get('message', 'Unknown error')}")
                return False
            
            filesize = response.get('filesize')
            filepath = os.path.join(self.download_directory, filename)
            
            print(f"[*] Downloading: {filename} ({self.format_size(filesize)})")
            
            # Receive file data
            with open(filepath, 'wb') as f:
                bytes_received = 0
                while bytes_received < filesize:
                    chunk = self.client_socket.recv(min(4096, filesize - bytes_received))
                    if not chunk:
                        break
                    f.write(chunk)
                    bytes_received += len(chunk)
                    
                    # Progress indicator
                    progress = (bytes_received / filesize) * 100
                    print(f"\r[*] Progress: {progress:.1f}%", end='', flush=True)
            
            print(f"\n[+] Download complete: {filepath}")
            return True
            
        except Exception as e:
            print(f"\n[!] Error downloading file: {e}")
            return False
    
    def upload_file(self, filepath):
        """Day 4: Upload file to server"""
        if not self.authenticated:
            print("[!] Not authenticated")
            return False
        
        try:
            if not os.path.exists(filepath):
                print(f"[!] File not found: {filepath}")
                return False
            
            filename = os.path.basename(filepath)
            filesize = os.path.getsize(filepath)
            
            # Send upload request
            self.send_json({
                'command': 'UPLOAD',
                'filename': filename,
                'filesize': filesize,
                'token': self.token
            })
            
            # Wait for ready signal
            response = self.receive_json()
            
            if not response or response.get('status') != 'ready':
                print(f"[!] Server not ready: {response.get('message', 'Unknown error')}")
                return False
            
            print(f"[*] Uploading: {filename} ({self.format_size(filesize)})")
            
            # Send file data
            with open(filepath, 'rb') as f:
                bytes_sent = 0
                while bytes_sent < filesize:
                    chunk = f.read(4096)
                    if not chunk:
                        break
                    self.client_socket.sendall(chunk)
                    bytes_sent += len(chunk)
                    
                    # Progress indicator
                    progress = (bytes_sent / filesize) * 100
                    print(f"\r[*] Progress: {progress:.1f}%", end='', flush=True)
            
            # Receive confirmation
            response = self.receive_json()
            
            if response and response.get('status') == 'success':
                print(f"\n[+] Upload complete: {filename}")
                return True
            else:
                print(f"\n[!] Upload failed: {response.get('message', 'Unknown error')}")
                return False
                
        except Exception as e:
            print(f"\n[!] Error uploading file: {e}")
            return False
    
    def send_json(self, data):
        """Send JSON data with length prefix"""
        json_data = json.dumps(data).encode('utf-8')
        length = len(json_data)
        self.client_socket.sendall(length.to_bytes(4, 'big'))
        self.client_socket.sendall(json_data)
    
    def receive_json(self):
        """Receive JSON data with length prefix"""
        try:
            length_bytes = self.client_socket.recv(4)
            if not length_bytes:
                return None
            length = int.from_bytes(length_bytes, 'big')
            
            data = b''
            while len(data) < length:
                chunk = self.client_socket.recv(min(4096, length - len(data)))
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
    
    def close(self):
        """Close connection"""
        if self.client_socket:
            try:
                self.send_json({
                    'command': 'EXIT',
                    'token': self.token
                })
            except:
                pass
            self.client_socket.close()
            print("[*] Connection closed")


def main():
    print("\n" + "="*50)
    print("FILE SHARING CLIENT")
    print("="*50 + "\n")
    
    client = FileClient()
    
    # Day 1: Connect to server
    if not client.connect():
        return
    
    # Day 5: Authentication
    print("\n--- LOGIN ---")
    username = input("Username: ")
    password = input("Password: ")
    
    if not client.authenticate(username, password):
        client.close()
        return
    
    # Main menu
    while True:
        print("\n" + "-"*50)
        print("MAIN MENU")
        print("-"*50)
        print("1. List available files")
        print("2. Download file")
        print("3. Upload file")
        print("4. Exit")
        print("-"*50)
        
        choice = input("\nEnter your choice (1-4): ").strip()
        
        if choice == '1':
            # Day 2: List files
            client.list_files()
        
        elif choice == '2':
            # Day 3: Download file
            files = client.list_files()
            if files:
                selection = input("\nEnter file number or name to download: ").strip()
                
                # Check if user entered a number
                try:
                    file_idx = int(selection) - 1
                    if 0 <= file_idx < len(files):
                        filename = files[file_idx]['name']
                    else:
                        print("[!] Invalid selection")
                        continue
                except ValueError:
                    filename = selection
                
                client.download_file(filename)
        
        elif choice == '3':
            # Day 4: Upload file
            filepath = input("\nEnter path to file to upload: ").strip()
            client.upload_file(filepath)
        
        elif choice == '4':
            print("\n[*] Exiting...")
            break
        
        else:
            print("[!] Invalid choice. Please try again.")
    
    client.close()


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n[*] Client terminated by user")
    except Exception as e:
        print(f"\n[!] Error: {e}")
