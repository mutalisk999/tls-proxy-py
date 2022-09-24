import asyncio
import json
import socket
import ssl

import socks5
import logging

from network import tcp_copy


async def conn_handler(_loop, _conn_socket):
    # read handshake data
    try:
        data = await _loop.sock_recv(_conn_socket, 1024 * 1024)
        check = socks5.parse_handshake_body(data)
        if not check:
            _conn_socket.close()
            return
        await _loop.sock_sendall(_conn_socket, b'\x05\x00')
    except Exception as ex:
        logging.warning(str(ex))
        _conn_socket.close()
        return

    # read request data
    try:
        data = await _loop.sock_recv(_conn_socket, 1024 * 1024)
        values = socks5.parse_request_body(data)

        if values[0] == chr(0x01):
            # ip v6
            if values[1] == chr(0x04):
                raise Exception("ip v6 not supported")

            client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            client_socket.setblocking(False)

            # ip v4 or domain name
            if values[1] in (chr(0x01), chr(0x03)):
                data = [0x05, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]

            try:
                await _loop.sock_connect(client_socket, (values[2], values[3]))
                await _loop.sock_sendall(_conn_socket, bytes(data))
            except Exception as ex:
                if isinstance(ex, ConnectionRefusedError):
                    data[1] = 0x05
                elif isinstance(ex, TimeoutError):
                    data[1] = 0x04
                else:
                    data[1] = 0x03
                logging.warning(str(ex))
                await _loop.sock_sendall(_conn_socket, bytes(data))
                _conn_socket.close()
                return

            # exchange data
            _loop.create_task(tcp_copy(_loop, _conn_socket, client_socket))
            _loop.create_task(tcp_copy(_loop, client_socket, _conn_socket))

        else:
            logging.warning("CMD: 0x%x not support" % int(values[0]))
            _conn_socket.close()
            return

    except Exception as ex:
        logging.warning(str(ex))
        _conn_socket.close()
        return


async def run_server(_loop, _server_conf):
    listen_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listen_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listen_socket = ssl.wrap_socket(
        listen_socket, server_side=True, keyfile=_server_conf.get("server_key"),
        certfile=_server_conf.get("server_cert")
    )
    listen_socket.setblocking(False)
    listen_socket.bind((_server_conf.get("listen_host"), _server_conf.get("listen_port")))
    listen_socket.listen(0)

    while True:
        connect_socket, _ = await _loop.sock_accept(listen_socket)
        _loop.create_task(conn_handler(loop, connect_socket))


def load_server_conf(conf_file):
    server_conf = json.loads(open(conf_file).read(1024 * 1024))
    assert server_conf is not None \
           and server_conf.get("listen_host") is not None \
           and server_conf.get("listen_port") is not None \
           and server_conf.get("server_key") is not None \
           and server_conf.get("server_cert") is not None
    return server_conf


if __name__ == "__main__":
    logging.basicConfig(
        level=logging.DEBUG,
        format='[%(asctime)s] {%(pathname)s:%(lineno)d} %(levelname)s - %(message)s',
        datefmt='%H:%M:%S'
    )
    server_conf = load_server_conf("server.json")
    loop = asyncio.get_event_loop()
    loop.create_task(run_server(loop, server_conf))
    loop.run_forever()
