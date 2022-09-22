import json
import socket
import ssl

import gevent
from gevent import monkey
from gevent.select import select
from typing import Optional, Dict
import socks5
import logging

monkey.patch_all()

server_conf: Optional[Dict] = None


def conn_handler(conn_socket):
    # read handshake data
    try:
        data = conn_socket.recv(1024 * 1024)
        check = socks5.parse_handshake_body(data)
        if not check:
            conn_socket.close()
            return
        conn_socket.send(b'\x05\x00')
    except Exception as ex:
        logging.warning(str(ex))
        conn_socket.close()
        return

    # read request data
    try:
        data = conn_socket.recv(1024 * 1024)
        values = socks5.parse_request_body(data)

        if values[0] == chr(0x01):
            if values[1] == chr(0x04):
                client_socket = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
                client_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            else:
                client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                client_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

            data = [0x05, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]
            try:
                client_socket.connect((values[2].decode("ascii"), values[3]))
                conn_socket.send(bytes(data))
            except ConnectionRefusedError as ex:
                data[1] = 0x05
                conn_socket.send(bytes(data))
                conn_socket.close()
                return
            except TimeoutError as ex:
                data[1] = 0x04
                conn_socket.send(bytes(data))
                conn_socket.close()
                return
            except Exception as ex:
                data[1] = 0x03
                conn_socket.send(bytes(data))
                conn_socket.close()
                return

            # exchange data
            while True:
                try:
                    read_fds, _, error_fds = select([conn_socket, client_socket], [], [conn_socket, client_socket])
                    if conn_socket in error_fds or client_socket in error_fds:
                        logging.warning("conn_socket/client_socket error.")
                        conn_socket.close()
                        client_socket.close()
                        return

                    if conn_socket in read_fds:
                        data = conn_socket.recv(1024 * 1024)
                        logging.debug(data)
                        if not data:
                            logging.warning("conn_socket close.")
                            conn_socket.close()
                            client_socket.close()
                            return
                        client_socket.send(data)

                    if client_socket in read_fds:
                        data = client_socket.recv(1024 * 1024)
                        logging.debug(data)
                        if not data:
                            logging.warning("client_socket close.")
                            conn_socket.close()
                            client_socket.close()
                            return
                        conn_socket.send(data)
                except Exception as ex:
                    logging.warning(str(ex))
                    conn_socket.close()
                    client_socket.close()
                    return
        else:
            conn_socket.close()
            return

    except Exception as ex:
        logging.warning(str(ex))
        conn_socket.close()
        return


def load_server_conf(conf_file):
    global server_conf

    f = open(conf_file)
    s = f.read(1024 * 1024)
    server_conf = json.loads(s)
    assert server_conf is not None and server_conf.get("listen_host") is not None and server_conf.get(
        "listen_port") is not None and server_conf.get("server_key") is not None and server_conf.get(
        "server_cert") is not None


def run_server():
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket = ssl.wrap_socket(
        server_socket, server_side=True, keyfile=server_conf.get("server_key"), certfile=server_conf.get("server_cert")
    )

    server_socket.bind((server_conf.get("listen_host"), server_conf.get("listen_port")))
    server_socket.listen(0)

    while True:
        connect_socket, _ = server_socket.accept()
        gevent.spawn(conn_handler, connect_socket)


if __name__ == "__main__":
    logging.getLogger().setLevel(logging.DEBUG)
    load_server_conf("server.json")
    run_server()
