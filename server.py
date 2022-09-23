import json
import socket
import ssl

import gevent
from gevent import monkey
from gevent.select import select
from typing import Optional, Dict
import socks5
import logging

from network import tcp_read_timeout

monkey.patch_all()

server_conf: Optional[Dict] = None


def conn_handler(conn_socket):
    # read handshake data
    try:
        data = tcp_read_timeout(conn_socket, 5)
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
        data = tcp_read_timeout(conn_socket, 5)
        values = socks5.parse_request_body(data)

        if values[0] == chr(0x01):
            # ip v6
            if values[1] == chr(0x04):
                raise Exception("ip v6 not supported")

            client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            client_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

            # ip v4 or domain name
            if values[1] in (chr(0x01), chr(0x03)):
                data = [0x05, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]

            try:
                client_socket.connect((values[2].decode("ascii"), values[3]))
                conn_socket.send(bytes(data))
            except Exception as ex:
                if isinstance(ex, ConnectionRefusedError):
                    data[1] = 0x05
                elif isinstance(ex, TimeoutError):
                    data[1] = 0x04
                else:
                    data[1] = 0x03
                logging.warning(str(ex))
                conn_socket.send(bytes(data))
                conn_socket.close()
                return

            # exchange data
            while True:
                try:
                    read_fds, _, _ = select([conn_socket, client_socket], [], [])
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
            logging.warning("CMD: 0x%x not support" % int(values[0]))
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
    logging.basicConfig(
        filename='log/server.log',
        level=logging.DEBUG,
        format='[%(asctime)s] {%(pathname)s:%(lineno)d} %(levelname)s - %(message)s',
        datefmt='%H:%M:%S'
    )
    load_server_conf("server.json")
    run_server()
