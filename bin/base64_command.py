#!/usr/bin/env python
# -*- coding: utf-8 -*-

import os
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


class Base64Alphabet(validators.Validator):
    """Validate Base64 alphabets"""
    def __call__(self, value):
        if value is None:
            return None
        if not isinstance(value, bytes):
            encoded_value = value.encode('utf-8', errors='backslashreplace')
            alphabet_len = len(encoded_value)
        else:
            alphabet_len = len(value)
        if alphabet_len not in (64, 65):
            raise ValueError('Require 64 characters in alphabet (or 65 with padding), not {}'.format(alphabet_len))
        return value

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
            raise ValueError('Codec for "{}" not found'.format(value.lower()))
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
    alphabet = Option(name='alphabet', require=False, default=None, validate=Base64Alphabet())
    backslash_escape = Option(name='backslash_escape', require=False, default=True, validate=validators.Boolean())
    encoding = Option(name='encoding', require=False, default=None, validate=OutputEncoding())
    suppress_error = Option(name='suppress_error', require=False, default=False, validate=validators.Boolean())
    padding = BASE64_CHARS[-1:]

    def stream(self, records):
        # Custom alphabets must be 64 bytes long, or 65 with custom padding
        if self.alphabet is not None:
            if not isinstance(self.alphabet, bytes):
                self.alphabet = self.alphabet.encode('utf-8', errors='backslashreplace')
            if len(self.alphabet) == 65:
                self.alphabet, self.padding = self.alphabet[:-1], self.alphabet[-1:]
            elif len(self.alphabet) != 64:
                self.alphabet = None

        # Set the function for decoding or encoding the input
        if self.action == 'decode':
            fct = from_b64
        else:
            fct = to_b64
            # No implementation to converting to base64 with a specific encoding
            self.encoding = None

        if self.encoding is not None:
            import codecs
            try:
                # Look up the chosen encoding
                codecs.lookup(self.encoding)
                self.backslash_escape = False
            except LookupError:
                # fail back to backslash escape of output, should be caught earlier with the validator
                self.encoding = None
                self.backslash_escape = True

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
            try:
                field_data = record[self.field]
                if self.action == 'encode' and self.backslash_escape is True and '\\' in field_data:
                    # Convert data that was previously backslash_escaped back to bytes
                    field_data = field_data.encode('utf8').decode('unicode_escape').encode('latin1')
                ret = fct(field_data, self.alphabet, self.padding)

                # Backslash escape decoded data
                if self.action == 'decode' and self.backslash_escape:
                    record[dest_field] = backslash_escape(ret)
                # Use specified encoding
                elif self.action == 'decode' and self.encoding is not None:
                    decoded = ret.decode(self.encoding, errors='replace')
                    # If nulls are found, Splunk may not pass it back to subsequent commands
                    if '\x00' in decoded:
                        decoded = backslash_escape(ret.decode('latin1'))
                    record[dest_field] = decoded
                else:
                    # If nulls are found, Splunk may not pass it back to subsequent commands
                    record[dest_field] = ensure_str(ret).replace('\x00', '\\x00')

            except Exception as e:
                if not self.suppress_error:
                    raise e

            yield record


dispatch(B64Command, module_name=__name__)
