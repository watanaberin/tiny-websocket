
import base64
import hashlib
import select
import socket
from optparse import OptionParser
from frame import WebsocketFrame

TCP_IP = '127.0.0.1'
TCP_PORT = 5006
BUFFER_SIZE = 1024 * 1024

DEFAULT_HTTP_RESPONSE = (
    b'''<HTML><HEAD><meta http-equiv="content-type" content="text/html;charset=utf-8">\r\n
<TITLE>200 OK</TITLE></HEAD><BODY>\r\n
<H1>200 OK</H1>\r\n
Welcome to the default.\r\n
</BODY></HTML>\r\n\r\n''')

MAGIC_WEBSOCKET_UUID_STRING = '258EAFA5-E914-47DA-95CA-C5AB0DC85B11'

def make_listening_tcp_socket(host: str, port: int) -> socket:
    tcp_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    tcp_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    tcp_socket.bind((host, port))
    tcp_socket.listen(1)
    print(f'Listening on host {host} port {port}')
    return tcp_socket


def listen_and_handle(listening_socket):
    input_sockets = [listening_socket]
    output_sockets = []
    xlist = []
    while True:
        readable_sockets = select.select(input_sockets,
                                         output_sockets,
                                         xlist,
                                         5)[0]

        for ready_socket in readable_sockets:
            # Make sure the socket is not closed
            if (ready_socket.fileno() == -1):
                continue
            if ready_socket == listening_socket:
                handle_new_connection(listening_socket, input_sockets)
            elif ready_socket in input_sockets:
                print('Handling websocket message')
                handle_websocket_message(ready_socket, input_sockets)


def handle_new_connection(main_door_socket, input_sockets):
    # When we get a connection on the main socket, we want to accept a new
    # connection and add it to our input socket list. When we loop back around,
    # that socket will be ready to read from.
    print('Handling main door socket')
    client_socket, client_addr = main_door_socket.accept()
    print(f'New socket {client_socket.fileno()} from address: {client_addr}')
    handle_request(client_socket, input_sockets)


def handle_websocket_message(client_socket, input_sockets):
    data_in_bytes = client_socket.recv(BUFFER_SIZE)
    if data_in_bytes == b'':
        print('Recv empty message')
        input_sockets.remove(client_socket)
        return
    websocket_frame = WebsocketFrame()
    websocket_frame.populate(data_in_bytes)
    print('Received message:', websocket_frame.get_payload_data().decode('utf-8'))
    return


def handle_request(client_socket, input_sockets):
    print('Handling request from client socket:', client_socket.fileno())
    message = ''
    # Very naive approach: read until we find the last blank line
    while True:
        data_in_bytes = client_socket.recv(BUFFER_SIZE)
        if len(data_in_bytes) == 0:
            close_socket(client_socket, input_sockets)
            return
        message_segment = data_in_bytes.decode()
        message += message_segment
        if (len(message) > 4 and message_segment[-4:] == '\r\n\r\n'):
            break
    
    (method, target, http_version, headers_map) = parse_request(message)
    print(f'{method} {target} {http_version}')
    
    if client_socket in input_sockets:
        client_socket.send(b'HTTP/1.1 200 OK\r\n\r\n' + DEFAULT_HTTP_RESPONSE)
        return

    if is_valid_ws_handshake_request(method,
                                        target,
                                        http_version,
                                        headers_map):
        print('request to ws endpoint!')
        handle_ws_handshake_request(
            client_socket,
            input_sockets,
            headers_map)
        return
    else:
        client_socket.send(b'HTTP/1.1 400 Bad Request\r\n\r\n')
        close_socket(client_socket, input_sockets)
        return


def handle_ws_handshake_request(client_socket,
                                input_socket,
                                headers_map):
    input_socket.append(client_socket)

    sec_websocket_accept_value = generate_sec_websocket_accept(
        headers_map.get('sec-websocket-key'))

    websocket_response = ''
    websocket_response += 'HTTP/1.1 101 Switching Protocols\r\n'
    websocket_response += 'Upgrade: websocket\r\n'
    websocket_response += 'Connection: Upgrade\r\n'
    websocket_response += (
        'Sec-WebSocket-Accept: ' + sec_websocket_accept_value.decode() + '\r\n')
    websocket_response += '\r\n'

    print('\nresponse:\n', websocket_response)

    client_socket.send(websocket_response.encode())


def generate_sec_websocket_accept(sec_websocket_key):
    combined = sec_websocket_key + MAGIC_WEBSOCKET_UUID_STRING
    hashed_combined_string = hashlib.sha1(combined.encode())
    encoded = base64.b64encode(hashed_combined_string.digest())
    return encoded


def is_valid_ws_handshake_request(method, target, http_version, headers_map):
    # There are a few things to verify to see if it's a valid WS handshake.
    # First, the method must be get.
    is_get = method == 'GET'
    # HTTP version must be >= 1.1. We can do a really naive check.
    http_version_number = float(http_version.split('/')[1])
    http_version_enough = http_version_number >= 1.1
    headers_valid = (
        ('upgrade' in headers_map and
         headers_map.get('upgrade') == 'websocket') and
        ('connection' in headers_map and
         headers_map.get('connection') == 'Upgrade') and
        ('sec-websocket-key' in headers_map)
    )
    return (is_get and http_version_enough and headers_valid)


def parse_request(request):
    headers_map = {}
    split_request = request.split('\r\n\r\n')[0].split('\r\n')
    [method, target, http_version] = split_request[0].split(' ')
    headers = split_request[1:]
    for header_entry in headers:
        [header_name, value] = header_entry.split(': ')
        headers_map[header_name.lower()] = value
    return (method, target, http_version, headers_map)


def close_socket(client_socket, input_sockets):
    print('closing socket')
    input_sockets.remove(client_socket)
    client_socket.close()
    return

def main():
    parser = OptionParser()
    parser.add_option('--host', default=TCP_IP, help='server to listen to', action='store', type='string', dest='host')
    parser.add_option('--port', default=TCP_PORT, help='port to listen to', action='store', type='int', dest='port')

    (options, args) = parser.parse_args()

    listening_socket = make_listening_tcp_socket(options.host, options.port)
    listen_and_handle(listening_socket)
    
if __name__ == '__main__':
    main()
