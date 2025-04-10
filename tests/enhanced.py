#!/bin/python3
import socket

# List of hostnames or IP addresses
hosts = ["example.com", "google.com", "yahoo.com"]  # Add more servers as needed
PORT = 80
request_template = "GET / HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n"

num_requests = 1  # Number of requests to make for each server

for host in hosts:
    for i in range(num_requests):
        # Create socket and connect
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((host, PORT))

        # Prepare the request for the current host
        request = request_template.format(host=host)

        # Send request
        sock.sendall(request.encode())

        # Receive response
        response = sock.recv(4096)
        print(f"Response {i+1} from {host}:\n", response.decode())

        # Close socket
        sock.close()
