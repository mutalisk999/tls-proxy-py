#!/usr/bin/env python
# encoding: utf-8

import logging


async def tcp_copy(_reader, _writer):
    while True:
        try:
            data = await _reader.read(4096)
            if not data:
                _writer.close()
                break
            _writer.write(data)
            await _writer.drain()
        except Exception as ex:
            logging.warning(str(ex))
            _writer.close()
            break
