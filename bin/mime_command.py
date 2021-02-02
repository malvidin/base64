#!/usr/bin/env python
# -*- coding: utf-8 -*-

import os
import re
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'lib'))
from splunklib.searchcommands import \
    dispatch, StreamingCommand, Configuration, Option, validators
from splunklib.six import PY3, text_type

if PY3:
    from email.parser import Parser
    from email import policy
else:
    from email.header import decode_header, make_header


def decode_mime(encoded_field, unescape_folding=True):
    if unescape_folding and r'\t' in encoded_field or r'\r\n' in encoded_field:
        encoded_field = re.sub(r'(?!<\\)\\r\\n( |\\t)+', ' ', encoded_field)  # Unfold escaped CRLF
        encoded_field = re.sub(r'(?!<\\)\\r\\n$', '', encoded_field)  # Trim trailing CRLF
        encoded_field = re.sub(r'(?!<\\)\\t', '\t', encoded_field)  # Unescape tab characters
    # Decode the field and convert to Unicode
    if '=?' in encoded_field:
        if PY3:
            decoded = Parser(policy=policy.default).parsestr('MIMEDecode: {}'.format(encoded_field)).get('MIMEDecode')
            return text_type(decoded)
        else:
            return text_type(make_header(decode_header(encoded_field)))
    return encoded_field


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
class MIMECommand(StreamingCommand):
    """
    Decode MIME Encoded content

    Use Python 3 if Language specification in Encoded Words is needed
    See RFC 2184 for details (https://tools.ietf.org/html/rfc2184)
   
     | mimedecode field=<field> [mode=(replace|append)]
     """

    field = Option(name='field', require=True)
    mode = Option(name='mode', require=False, default='replace', validate=OutputModes())
    suppress_error = Option(name='suppress_error', require=False, default=False, validate=validators.Boolean())

    def stream(self, records):

        if self.mode == 'append':
            dest_field = 'mimedecode'
        else:
            dest_field = self.field

        for record in records:

            if self.field not in record:
                yield record
                continue

            try:
                decoded = decode_mime(record[self.field])
                if '\x00' in decoded:
                    decoded = decoded.replace('\x00', '\\x00')
                record[dest_field] = decoded

            except Exception as e:
                if not self.suppress_error:
                    raise e

            yield record


dispatch(MIMECommand, module_name=__name__)
