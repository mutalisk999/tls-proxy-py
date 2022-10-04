#!/usr/bin/env python
# encoding: utf-8

import json
import logging
import ssl
import asyncio

from network import tcp_copy

client_conf = None


async def conn_handler(conn_reader, conn_writer):
    ssl_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ssl_ctx.options |= ssl.OP_NO_TLSv1
    ssl_ctx.options |= ssl.OP_NO_TLSv1_1
    ssl_ctx.load_cert_chain(certfile=client_conf.get("client_cert"), keyfile=client_conf.get("client_key"))
    ssl_ctx.check_hostname = False
    ssl_ctx.verify_mode = ssl.VerifyMode.CERT_NONE
    ssl_ctx.set_ciphers('ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384')

    try:
        client_reader, client_writer = await asyncio.open_connection(client_conf.get("server_host"),
                                                                     client_conf.get("server_port"),
                                                                     ssl=ssl_ctx)
    except Exception as ex:
        logging.warning(str(ex))
        if isinstance(ex, ConnectionRefusedError):
            conn_writer.write(b"ConnectionRefusedError")
            await conn_writer.drain()
            conn_writer.close()
        elif isinstance(ex, TimeoutError):
            conn_writer.write(b"TimeoutError")
            await conn_writer.drain()
            conn_writer.close()
        else:
            conn_writer.write(str(ex).encode(encoding="ascii", errors="ignore"))
            await conn_writer.drain()
            conn_writer.close()
        return

    # exchange data
    await asyncio.gather(
        asyncio.get_running_loop().create_task(tcp_copy(conn_reader, client_writer)),
        asyncio.get_running_loop().create_task(tcp_copy(client_reader, conn_writer))
    )


async def run_client(_client_conf):
    await asyncio.start_server(conn_handler,
                               _client_conf.get("listen_host"),
                               _client_conf.get("listen_port"))


def load_client_conf(conf_file):
    client_conf = json.loads(open(conf_file).read(4096))
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
    loop = asyncio.get_event_loop()
    client_conf = load_client_conf("client.json")
    loop.create_task(run_client(client_conf))
    loop.run_forever()
