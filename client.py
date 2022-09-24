import json
import logging
import socket
import ssl
import asyncio

from network import tcp_copy


async def conn_handler(_loop, _conn_socket):
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.setblocking(False)
    client_socket = ssl.wrap_socket(client_socket, keyfile=client_conf.get("client_key"),
                                    certfile=client_conf.get("client_cert"))
    try:
        await _loop.sock_connect(client_socket, (client_conf.get("server_host"),
                                                 client_conf.get("server_port")))
    except Exception as ex:
        logging.warning(str(ex))
        if isinstance(ex, ConnectionRefusedError):
            await _loop.sock_sendall(_conn_socket, b"ConnectionRefusedError")
        elif isinstance(ex, TimeoutError):
            await _loop.sock_sendall(_conn_socket, b"TimeoutError")
        else:
            await _loop.sock_sendall(_conn_socket,
                                     str(ex).encode(encoding="ascii", errors="ignore"))
        _conn_socket.close()
        return

    _loop.create_task(tcp_copy(_loop, _conn_socket, client_socket))
    _loop.create_task(tcp_copy(_loop, client_socket, _conn_socket))


async def run_client(_loop, _client_conf):
    listen_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listen_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listen_socket.setblocking(False)
    listen_socket.bind((_client_conf.get("listen_host"), _client_conf.get("listen_port")))
    listen_socket.listen(0)

    while True:
        connect_socket, _ = await _loop.sock_accept(listen_socket)
        _loop.create_task(conn_handler(loop, connect_socket))


def load_client_conf(conf_file):
    client_conf = json.loads(open(conf_file).read(1024 * 1024))
    assert client_conf is not None and client_conf.get("listen_host") is not None \
           and client_conf.get("listen_port") is not None \
           and client_conf.get("server_host") is not None \
           and client_conf.get("server_port") is not None \
           and client_conf.get("client_key") is not None \
           and client_conf.get("client_cert") is not None
    return client_conf


if __name__ == "__main__":
    logging.basicConfig(
        level=logging.DEBUG,
        format='[%(asctime)s] {%(pathname)s:%(lineno)d} %(levelname)s - %(message)s',
        datefmt='%H:%M:%S'
    )
    client_conf = load_client_conf("client.json")
    loop = asyncio.get_event_loop()
    loop.create_task(run_client(loop, client_conf))
    loop.run_forever()
