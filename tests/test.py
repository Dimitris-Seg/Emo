import socket

HOST = "example.com"
PORT = 80
request = f"GET / HTTP/1.1\r\nHost: {HOST}\r\nConnection: close\r\n\r\n"

# Create socket and connect
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.connect((HOST, PORT))

# Send request
sock.sendall(request.encode())

# Receive response
response = sock.recv(4096)
print("Received:\n", response.decode())

# Close socket
sock.close()
