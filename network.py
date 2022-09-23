#!/usr/bin/env python
# encoding: utf-8


from gevent.select import select


def tcp_read_timeout(tcp_socket, timeout: int) -> bytes:
    read_fds, _, _ = select([tcp_socket], [], [], timeout=timeout)
    if tcp_socket in read_fds:
        return tcp_socket.recv(1024 * 1024)
    raise Exception("tcp_read_timeout timeout")
