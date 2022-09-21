import json
import socket
import ssl

import gevent
from gevent import monkey
from gevent.select import select
from typing import Optional, Dict

monkey.patch_all()

server_conf: Optional[Dict] = None


def conn_handler(conn_socket):
    pass


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
    load_server_conf("server.json")
    run_server()
