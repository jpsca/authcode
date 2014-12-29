# coding=utf-8
"""
    Utilities for writing code that runs on Python 2 and 3.
"""
import sys


PY2 = sys.version_info[0] == 2

_identity = lambda x: x

if PY2:
    text_type = unicode

    def to_bytes(x, charset='utf8', errors='ignore'):
        if x is None:
            return None
        if isinstance(x, (bytes, bytearray, buffer)):
            return bytes(x)
        if isinstance(x, unicode):
            return x.encode(charset, errors)
        raise TypeError('Expected bytes')
else:
    text_type = str

    def to_bytes(x, charset='utf8', errors='ignore'):
        if x is None:
            return None
        if isinstance(x, (bytes, bytearray, memoryview)):
            return bytes(x)
        if isinstance(x, str):
            return x.encode(charset, errors)
        raise TypeError('Expected bytes')


def to_native(x, charset='utf8', errors='ignore'):
    bb = to_bytes(x, charset=charset, errors=errors)
    if not bb:
        return bb
    return bb.decode('utf8')


def to_unicode(x, charset='utf8', errors='ignore',
               allow_none_charset=False):
    if x is None:
        return None
    if not isinstance(x, bytes):
        return text_type(x)
    if charset is None and allow_none_charset:
        return x
    return x.decode(charset, errors)
