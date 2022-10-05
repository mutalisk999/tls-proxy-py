#!/usr/bin/env python
# encoding: utf-8

import asyncio
import json
import ssl

import socks5
import logging

from network import tcp_copy


async def conn_handler(conn_reader, conn_writer):
    # read handshake data
    try:
        data = await conn_reader.read(4096)
        check = socks5.parse_handshake_body(data)
        if not check:
            conn_writer.close()
            return
        conn_writer.write(b'\x05\x00')
        await conn_writer.drain()
    except Exception as ex:
        logging.warning(str(ex))
        conn_writer.close()
        return

    # read request data
    try:
        data = await conn_reader.read(4096)
        values = socks5.parse_request_body(data)

        if values[0] == chr(0x01):
            # ip v6
            if values[1] == chr(0x04):
                raise Exception("ip v6 not supported")

            # ip v4 or domain name
            if values[1] in (chr(0x01), chr(0x03)):
                data = [0x05, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]

            try:
                logging.info("proxy to %s:%d" % (values[2], values[3]))
                client_reader, client_writer = await asyncio.open_connection(values[2], values[3])
                conn_writer.write(bytes(data))
                await conn_writer.drain()
            except Exception as ex:
                if isinstance(ex, ConnectionRefusedError):
                    data[1] = 0x05
                elif isinstance(ex, TimeoutError):
                    data[1] = 0x04
                else:
                    data[1] = 0x03
                logging.warning(str(ex))
                conn_writer.write(bytes(data))
                await conn_writer.drain()
                conn_writer.close()
                return

            # exchange data
            await asyncio.gather(
                asyncio.get_running_loop().create_task(tcp_copy(conn_reader, client_writer)),
                asyncio.get_running_loop().create_task(tcp_copy(client_reader, conn_writer))
            )

        else:
            logging.warning("CMD: 0x%x not support" % int(values[0]))
            conn_writer.close()
            return

    except Exception as ex:
        logging.warning(str(ex))
        conn_writer.close()
        return


async def run_server(_server_conf):
    ssl_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ssl_ctx.options |= ssl.OP_NO_TLSv1
    ssl_ctx.options |= ssl.OP_NO_TLSv1_1
    ssl_ctx.options |= ssl.OP_SINGLE_DH_USE
    ssl_ctx.options |= ssl.OP_SINGLE_ECDH_USE
    ssl_ctx.load_cert_chain(certfile=_server_conf.get("server_cert"), keyfile=_server_conf.get("server_key"))
    ssl_ctx.check_hostname = False
    ssl_ctx.verify_mode = ssl.VerifyMode.CERT_NONE
    ssl_ctx.set_ciphers('ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384')
    await asyncio.start_server(conn_handler,
                               _server_conf.get("listen_host"),
                               _server_conf.get("listen_port"),
                               ssl=ssl_ctx)


def load_server_conf(conf_file):
    server_conf = json.loads(open(conf_file).read(4096))
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
    loop = asyncio.new_event_loop()
    server_conf = load_server_conf("server.json")
    loop.create_task(run_server(server_conf))
    loop.run_forever()
