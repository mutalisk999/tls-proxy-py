import json
import logging
import socket
import ssl

import gevent
from gevent import monkey
from gevent.select import select
from typing import Optional, Dict

monkey.patch_all()

client_conf: Optional[Dict] = None


def conn_handler(conn_socket):
    global client_conf

    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    client_socket = ssl.wrap_socket(client_socket, keyfile=client_conf.get("client_key"),
                                    certfile=client_conf.get("client_cert"))
    try:
        client_socket.connect((client_conf.get("server_host"), client_conf.get("server_port")))
    except Exception as ex:
        if isinstance(ex, ConnectionRefusedError):
            conn_socket.send(b"ConnectionRefusedError")
        elif isinstance(ex, TimeoutError):
            conn_socket.send(b"TimeoutError")
        else:
            conn_socket.send(str(ex).encode(encoding="ascii", errors="ignore"))
        conn_socket.close()
        return

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
                if not data:
                    logging.warning("conn_socket close.")
                    conn_socket.close()
                    client_socket.close()
                    return
                client_socket.send(data)

            if client_socket in read_fds:
                data = client_socket.recv(1024 * 1024)
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


def load_client_conf(conf_file):
    global client_conf

    f = open(conf_file)
    s = f.read(1024 * 1024)
    client_conf = json.loads(s)
    assert client_conf is not None and client_conf.get("listen_host") is not None and client_conf.get(
        "listen_port") is not None and client_conf.get("server_host") is not None and client_conf.get(
        "server_port") is not None and client_conf.get(
        "client_key") is not None and client_conf.get("client_cert") is not None


def run_client():
    listen_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listen_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    listen_socket.bind((client_conf.get("listen_host"), client_conf.get("listen_port")))
    listen_socket.listen(0)

    while True:
        connect_socket, _ = listen_socket.accept()
        gevent.spawn(conn_handler, connect_socket)


if __name__ == "__main__":
    logging.getLogger().setLevel(logging.DEBUG)
    load_client_conf("client.json")
    run_client()
