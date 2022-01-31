import socket
from struct import pack, unpack

server_addr = './integrator.sock'

command = f"getconfig integration"
s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
s.connect(server_addr)
header_format = "<I"
header_size = 4
msg_bytes = command.encode()
s.send(pack(header_format, len(msg_bytes)) + msg_bytes)
size = unpack(header_format, s.recv(header_size, socket.MSG_WAITALL))[0]
resp = s.recv(size, socket.MSG_WAITALL)
#print(resp.decode())
rec_msg_ok, rec_msg = resp.decode().split(" ", 1)
s.close()
if rec_msg_ok.startswith('ok'):
   print(rec_msg)