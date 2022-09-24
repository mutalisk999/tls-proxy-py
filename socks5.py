# protocol socks5
import socket
import ipaddr

ProtocolVersion = chr(0x05)


def get_methods_description(m: chr) -> str:
    if chr(m) == chr(0x0):
        return 'NO AUTHENTICATION REQUIRED'
    elif chr(m) == chr(0x01):
        return 'GSSAPI'
    elif chr(m) == chr(0x02):
        return 'USERNAME/PASSWORD'
    elif chr(m) == chr(0xff):
        return 'NO ACCEPTABLE METHODS'
    elif chr(0x03) <= chr(m) <= chr(0x7f):
        return 'IANA ASSIGNED'
    elif chr(0x80) <= chr(m) <= chr(0xfe):
        return 'RESERVED FOR PRIVATE METHODS'


def parse_handshake_body(data: bytes) -> bool:
    if len(data) <= 2:
        raise Exception("invalid handshake body length")
    if len(data) != int(data[1]) + 2:
        raise Exception("invalid handshake body length")
    if chr(data[0]) != ProtocolVersion:
        raise Exception("only support socks5 protocol")
    # method 'NO AUTHENTICATION REQUIRED' supported
    return True if chr(0x0) in [chr(c) for c in data[2:]] else False


def parse_request_body(data: bytes) -> tuple:
    if len(data) <= 4:
        raise Exception("invalid request body length")
    if chr(data[3]) not in (chr(0x01), chr(0x03), chr(0x04)):
        raise Exception("invalid field ATYP")
    if chr(data[0]) != ProtocolVersion:
        raise Exception("only support socks5 protocol")
    if chr(data[1]) not in (chr(0x01), chr(0x02), chr(0x03)):
        raise Exception("invalid field CMD")
    if chr(data[2]) != chr(0x0):
        raise Exception("invalid field RSV")
    if chr(data[3]) == chr(0x01):
        # ip v4
        if len(data) != 10:
            raise Exception("invalid request body length")
        return (chr(data[1]), chr(data[3]),
                socket.inet_ntoa(data[4:8]),
                int(data[8]) * 256 + int(data[9]))
    elif chr(data[3]) == chr(0x03):
        # domain name
        if len(data) != 7 + int(data[4]):
            raise Exception("invalid request body length")
        return (chr(data[1]), chr(data[3]), data[5:5 + int(data[4])].decode("ascii"),
                int(data[5 + int(data[4])]) * 256 + int(data[6 + int(data[4])]))
    elif chr(data[3]) == chr(0x04):
        # ip v6
        if len(data) != 22:
            raise Exception("invalid request body length")
        return (chr(data[1]), chr(data[3]),
                str(ipaddr.IPv6Address(ipaddr.Bytes(data[4:20]))),
                int(data[20]) * 256 + int(data[21]))
