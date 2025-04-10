#!/bin/python3
import requests
import socket

# --- HTTP request using 'requests' ---
def send_http_request():
    try:
        response = requests.get("http://httpbin.org/get")
        print("HTTP Response:")
        print(response.text)
    except Exception as e:
        print("HTTP request failed:", e)

# --- Raw TCP request using sockets ---
def send_tcp_request():
    try:
        host = "example.com"
        port = 80
        message = b"HELLO SERVER\r\n"

        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(2)
            s.connect((host, port))
            s.sendall(message)
            data = s.recv(1024)

        print("\nTCP Response:")
        print(data.decode(errors="ignore"))
    except Exception as e:
        print("TCP request failed:", e)

if __name__ == "__main__":
    send_http_request()
    send_tcp_request()
