#!/usr/bin/env python
# -*- coding: utf-8 -*-

import os
import sys
from base64 import b64decode, b64encode

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'lib'))
from splunklib.searchcommands import \
    dispatch, StreamingCommand, Configuration, Option, validators
from splunklib.six import PY3, text_type

if PY3:
    maketrans = bytes.maketrans
    import binascii
    PaddingError = binascii.Error
else:
    from string import maketrans
    PaddingError = TypeError

BASE64_CHARS = b'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/='


def from_b64(input_bytes, custom_alphabet=None, padding=b'='):
    """
    Base64 decodes input, optionally with a custom base64 alphabet.

    :param input_bytes: Input to base64 encode
    :param custom_alphabet: Optional base64 alphabet
    :param padding: Optional base64 padding character when using a custom alphabet
    :return: Base64 decoded data
    """
    if not isinstance(input_bytes, bytes):
        input_bytes = input_bytes.encode('utf-8', errors='backslashreplace')
    if custom_alphabet is not None:
        input_bytes = input_bytes.translate(maketrans(custom_alphabet + padding, BASE64_CHARS))
    try:
        decoded_value = b64decode(input_bytes + b'====')
    except PaddingError:
        decoded_value = b64decode(input_bytes + b'A====')
    return decoded_value


def to_b64(input_bytes, custom_alphabet=None, padding=b'='):
    """
    Base64 encodes input, optionally with a custom base64 alphabet.

    :param input_bytes: Input to base64 encode
    :param custom_alphabet: Optional base64 alphabet
    :param padding: Optional base64 padding character when using a custom alphabet
    :return: Base64 encoded data
    """
    if not isinstance(input_bytes, bytes):
        input_bytes = input_bytes.encode('utf-8', errors='backslashreplace')
    encoded_value = b64encode(input_bytes)
    if custom_alphabet is not None:
        encoded_value = encoded_value.translate(maketrans(BASE64_CHARS, custom_alphabet + padding))
    return encoded_value


def backslash_escape(input_bytes):
    out_string = ''
    for c in input_bytes:
        if PY3:
            if c == 0x5c:
                c = chr(c) * 2
            elif c < 0x20 or c > 0x7e:
                c = '\\x{0:02x}'.format(c)
            else:
                c = chr(c)
        else:
            if c == '\\':
                c = c * 2
            elif c < ' ' or c > '~':
                c = '\\x{0:02x}'.format(ord(c))
        out_string += c
    return out_string


@Configuration()
class B64Command(StreamingCommand):
    """
    Encode a string to Base64
    Decode Base64 content

     | base64 [action=(encode|decode)] field=<field> [mode=(replace|append)]
     """

    field = Option(name='field', require=False, default='test')
    action = Option(name='action', require=False, default='encode')
    mode = Option(name='mode', require=False, default='replace')
    alphabet = Option(name='alphabet', require=False, default=None)
    backslash_escape = Option(name='backslash_escape', require=False, default=True, validate=validators.Boolean())
    encoding = Option(name='encoding', require=False, default=None)
    suppress_error = Option(name='suppress_error', require=False, default=False, validate=validators.Boolean())
    padding = BASE64_CHARS[-1:]
    show_info = Option(name='show_info', require=False, default=False, validate=validators.Boolean())

    def stream(self, records):
        # Custom alphabets must be 64 bytes long, or 65 with custom padding
        if self.alphabet is not None:
            if not isinstance(self.alphabet, bytes):
                self.alphabet = self.alphabet.encode('utf-8', errors='backslashreplace')
            if len(self.alphabet) == 65:
                self.alphabet, self.padding = self.alphabet[:-1], self.alphabet[-1:]
            elif len(self.alphabet) != 64:
                self.alphabet = None

        fct = from_b64 if self.action == 'decode' else to_b64

        if self.encoding is not None:
            import codecs
            try:
                codecs.lookup(self.encoding)
                self.backslash_escape = False
            except LookupError:
                self.encoding = None
                self.backslash_escape = True

        if self.mode == 'append':
            dest_field = 'base64'
        else:
            dest_field = self.field

        for record in records:

            if self.field not in record:
                yield record
                continue

            try:
                ret = fct(record[self.field], self.alphabet, self.padding)
                if self.backslash_escape:
                    record[dest_field] = backslash_escape(ret)
                elif self.action == 'decode' and self.encoding is not None:
                    record[dest_field] = ret.decode(self.encoding, errors='replace')
                else:
                    record[dest_field] = text_type(ret)

            except Exception as e:
                if not self.suppress_error:
                    raise e

            yield record


dispatch(B64Command, module_name=__name__)
