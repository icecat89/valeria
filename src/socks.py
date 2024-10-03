#!/usr/bin/python

import socket
import threading


CHUNK_SIZE = 4096

def sock_recv(sock):
  recv_buf = b''
  while True:
    recv = sock.recv(CHUNK_SIZE)
    recv_buf += recv
    if len(recv) < CHUNK_SIZE:
      break

  return recv_buf

def sock_send(sock, send_buf):
  l = len(send_buf)
  n = l // CHUNK_SIZE

  sock.send(send_buf[:l % CHUNK_SIZE])

  for i in range(2, n):
    sock.send(send_buf[CHUNK_SIZE:i*CHUNK_SIZE])

  if n>0 and l % CHUNK_SIZE != 0:
      sock.send(send_buf[:- (l % CHUNK_SIZE)])


def handle_client(client):
  # negotiation
  buf = sock_recv(client)
  print(f'+++ Socks V{buf[0]}')
  
  if buf[1]==b'\x00':
    print(f'+++ METHOD {buf[1]} : NO AUTHENTICATION REQUIRED')
  elif buf[1]==b'\x01':
    print(f'+++ METHOD {buf[1]} : GSSAPI')
  elif buf[1]==b'\x02':
    print(f'+++ METHOD {buf[1]} : UESRNAME/PASSWORD')
  elif 0x03 <= buf[1] <= 0x7f:
    print(f'+++ METHOD {buf[1]}: INA ASSIGNED')
  elif 0x80 <= buf[1] <= 0xfe:
    print(f'+++ METHOD {buf[1]} : PRIVATE METHOD')
  else:
    print(f'+++ METHOD {buf[1]} : NO ACCEPTABLE METHOD')

  # send our method : NO AUTH REQUIRED
  buf = b'\x05\x00'
  sock_send(client, buf)

  # requests
  client_request_buf = sock_recv(client)
  print(client_request_buf)

  reply_buf = b'\x05\x03\x00\x01\x00\x00\x00\x00\x04\x38'
  sock_send(client, reply_buf)
  # close connection
  client.close()
  print("[!] Connection closed")


  

def server_loop():
  server = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
  server.bind(('0.0.0.0', 1080))
  server.listen(5)

  print('[*] Listening on port 1080...')

  while True:
    client, addr = server.accept()
    print('[+] client', addr, 'has connected to the server!')

    client_thread = threading.Thread(target=handle_client, args=(client,))
    client_thread.start()


if __name__=='__main__':
  server_loop()


