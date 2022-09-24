#!/usr/bin/env python
# encoding: utf-8
import logging


async def tcp_copy(_loop, _tcp_socket_from, _tcp_socket_to):
    while True:
        try:
            data = await _loop.sock_recv(_tcp_socket_from, 1024 * 1024)
            if not data:
                break
            await _loop.sock_sendall(_tcp_socket_to, data)
        except Exception as ex:
            logging.warning(str(ex))
            _tcp_socket_from.close()
            _tcp_socket_to.close()
            break
