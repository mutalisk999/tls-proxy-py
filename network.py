#!/usr/bin/env python
# encoding: utf-8


from gevent.select import select


def tcp_read_timeout(tcp_socket, timeout: int) -> bytes:
    read_fds, _, error_fds = select([tcp_socket], [], [tcp_socket], timeout=timeout)
    if tcp_socket in read_fds:
        return tcp_socket.recv(1024 * 1024)
    if tcp_socket in error_fds:
        raise Exception("tcp_read_timeout error")
    raise Exception("tcp_read_timeout timeout")
