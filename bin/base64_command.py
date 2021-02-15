#!/usr/bin/env python
# -*- coding: utf-8 -*-

import os
import re
import sys
from base64 import b64decode, b64encode

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'lib'))
from splunklib.searchcommands import \
    dispatch, StreamingCommand, Configuration, Option, validators
from splunklib.six import PY3, ensure_str

if PY3:
    maketrans = bytes.maketrans
    import binascii
    PaddingError = binascii.Error
else:
    from string import maketrans
    PaddingError = TypeError

BASE64_CHARS = b'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/='
BASE64_RE_PRINTABLE = re.compile(
    b'''^
        ([ACDI-Za-f][0-3AC-HQS-Xgi-nwyz][014589ABEFIJMNQRUVYZcdghklopstwx][0-9A-Za-z+/])+
        ([ACDI-Za-f][0-3AC-HQS-Xgi-nwyz][014589ABEFIJMNQRUVYZcdghklopstwx=]?[0-9A-Za-z+/=]?)
        $''',
    re.VERBOSE
)


def from_b64(input_bytes, custom_alphabet=BASE64_CHARS, recurse=False):
    """
    Base64 decodes input, optionally with a custom base64 alphabet.

    :param input_bytes: Input to base64 encode
    :param custom_alphabet: Optional base64 alphabet
    :param recurse: Attempt recursive decoding
    :return: Base64 decoded data
    """
    if not isinstance(input_bytes, bytes):
        input_bytes = input_bytes.encode('ascii', errors='ignore')
    if custom_alphabet != BASE64_CHARS:
        input_bytes = input_bytes.translate(maketrans(custom_alphabet, BASE64_CHARS))
    try:
        decoded_value = b64decode(input_bytes + b'====')
    except PaddingError:
        decoded_value = b64decode(input_bytes + b'A====')
    if recurse:
        if BASE64_RE_PRINTABLE.match(decoded_value.replace(b'\x00', b'')):
            decoded_value = from_b64(
                decoded_value,
                custom_alphabet=custom_alphabet,
                recurse=recurse
            )
    return decoded_value


def to_b64(input_bytes, custom_alphabet=BASE64_CHARS):
    """
    Base64 encodes input, optionally with a custom base64 alphabet.

    :param input_bytes: Input to base64 encode
    :param custom_alphabet: Optional base64 alphabet
    :return: Base64 encoded data
    """
    if not isinstance(input_bytes, bytes):
        input_bytes = input_bytes.encode('utf-8', errors='backslashreplace')
    encoded_value = b64encode(input_bytes)
    if custom_alphabet != BASE64_CHARS:
        encoded_value = encoded_value.translate(maketrans(BASE64_CHARS, custom_alphabet))
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


class Base64Alphabet(validators.Validator):
    """Validate Base64 alphabets"""
    def __call__(self, value):
        if not value:
            return BASE64_CHARS
        if not isinstance(value, bytes):
            value = value.encode('ascii')
        alphabet_len = len(value)
        # Accept altchars, like "-_" for URL safe encoding. Third optional character is alternate padding
        if alphabet_len in (2, 3):
            if alphabet_len == 2:
                value += BASE64_CHARS[-1:]
            if any(c in BASE64_CHARS[:62] for c in value):
                raise ValueError('Alternate chars must not be in the normal base64 alphabet')
            return BASE64_CHARS.translate(maketrans(BASE64_CHARS[-3:], value))
        elif alphabet_len in (64, 65):
            if alphabet_len == 64:
                value += BASE64_CHARS[-1:]
            return value
        else:
            raise ValueError('Require 64 characters in alphabet (or 65 with padding), not {!s}'.format(alphabet_len))

    def format(self, value):
        return None if value is None else value


class Base64Actions(validators.Validator):
    """Validate ACTIONS for output location"""
    def __call__(self, value):
        if value is None:
            return None
        valid_actions = ('encode', 'decode')
        if value.lower() not in valid_actions:
            raise ValueError('Action option must be {}'.format(' or '.join(valid_actions)))
        return value.lower()

    def format(self, value):
        return None if value is None else value.lower()


class OutputEncoding(validators.Validator):
    """Validate output encoding format"""
    def __call__(self, value):
        if value is None:
            return None
        import codecs
        try:
            codecs.lookup(value)
        except LookupError as err:
            raise ValueError('Codec "{}" not found'.format(value.lower()))
        return value.lower()

    def format(self, value):
        return None if value is None else value.lower()


class OutputModes(validators.Validator):
    """Validate modes for output location"""
    def __call__(self, value):
        if value is None:
            return None
        valid_modes = ('replace', 'append')
        if value.lower() not in valid_modes:
            raise ValueError('Mode option must be {}'.format(' or '.join(valid_modes)))
        return value.lower()

    def format(self, value):
        return None if value is None else value.lower()


@Configuration()
class B64Command(StreamingCommand):
    """
    Encode a string to Base64
    Decode Base64 content

     | base64 [action=(encode|decode)] field=<field> [mode=(replace|append)]
     """

    field = Option(name='field', require=True, default=None)
    action = Option(name='action', require=False, default='decode', validate=Base64Actions())
    mode = Option(name='mode', require=False, default='replace', validate=OutputModes())
    alphabet = Option(name='alphabet', require=False, default=BASE64_CHARS, validate=Base64Alphabet())
    backslash_escape = Option(name='backslash_escape', require=False, default=True, validate=validators.Boolean())
    encoding = Option(name='encoding', require=False, default=None, validate=OutputEncoding())
    recurse = Option(name='recurse', require=False, default=False, validate=validators.Boolean())
    suppress_error = Option(name='suppress_error', require=False, default=False, validate=validators.Boolean())

    def stream(self, records):

        # Set the output field
        if self.mode == 'append':
            dest_field = 'base64'
        else:
            dest_field = self.field

        for record in records:
            # Return unchanged record if the field is not present
            if self.field not in record:
                yield record
                continue

            # Process field
            field_data_list = record[self.field]
            output_data_list = []

            # Ensure all values are in a list
            if not isinstance(field_data_list, list):
                field_data_list = [field_data_list]

            for field_data in field_data_list:
                try:
                    # Base64 Encoding
                    if self.action == 'encode':
                        # Expected input is UTF-8 read as Unicode.
                        # To pass other formats, it must be unescaped from backslash_escape
                        if self.backslash_escape:
                            field_data = field_data.encode('utf-8', errors='ignore').decode('unicode_escape')
                        field_data = field_data.encode(self.encoding, errors='ignore')
                        # Add encoded ASCII data to output
                        output_data_list.append(ensure_str(
                            to_b64(field_data, custom_alphabet=self.alphabet)
                        ))

                    # Base64 Decoding
                    else:
                        output_data = from_b64(field_data, custom_alphabet=self.alphabet, recurse=self.recurse)
                        # Try specified encoding
                        if self.encoding:
                            try:
                                decode_attempt = output_data.decode(self.encoding, errors='strict')
                                if '\x00' not in decode_attempt:
                                    output_data_list.append(decode_attempt)
                                    continue
                            except UnicodeDecodeError:
                                pass
                        # Backlash escape output
                        # Null values will break the data passed back through stdout
                        if self.backslash_escape or b'\x00' in output_data:
                            output_data_list.append(
                                backslash_escape(output_data)
                            )
                        # If encoding was not set, backslash_escape was not set, and no null found
                        else:
                            output_data_list.append(
                                output_data.decode('utf8', errors='replace')
                            )

                except Exception as e:
                    if not self.suppress_error:
                        raise e

                record[dest_field] = output_data_list

            yield record


dispatch(B64Command, module_name=__name__)
