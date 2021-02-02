#!/usr/bin/env python
# -*- coding: utf-8 -*-

import argparse
import csv
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'lib'))
from splunklib.six import text_type, ensure_text
from splunklib.searchcommands.internals import CsvDialect

from base64_command import from_b64, to_b64, backslash_escape


def process_line(input_dict, encoded, decoded):
    try:
        if input_dict[encoded] and not input_dict[decoded]:
            input_dict[decoded] = backslash_escape(from_b64(input_dict[encoded]))
        elif input_dict[decoded] and not input_dict[encoded]:
            data = input_dict[decoded].encode('utf8').decode('unicode_escape').encode('latin1')
            input_dict[encoded] = ensure_text(to_b64(data))
    except:
        pass


def get_csv_writer(infile, outfile, *args):
    reader = csv.DictReader(infile, dialect=CsvDialect)
    header = reader.fieldnames
    for arg in args:
        if arg not in header:
            raise KeyError('{arg!r} from command line arguments not found in input CSV headers'.format(arg=arg))
    writer = csv.DictWriter(outfile, header, dialect=CsvDialect)
    writer.writeheader()
    return reader, writer


def main():
    parser = argparse.ArgumentParser(description='Base64 encode or base64 input.')
    parser.add_argument(
        'encoded', type=text_type, nargs=1,
        help='Input string to base64 with base64.')
    parser.add_argument(
        'decoded', type=text_type, nargs=1,
        help='Input string to encode with base64')

    parser.add_argument('-i', '--infile', nargs='?', type=argparse.FileType('r'), default=sys.stdin,
                        help='Input CSV, defaults to stdin')
    parser.add_argument('-o', '--outfile', nargs='?', type=argparse.FileType('w'), default=sys.stdout,
                        help='Input CSV, defaults to stdout')
    args = parser.parse_args()
    infile = args.infile
    outfile = args.outfile

    arg_list = [
        args.encoded[0],
        args.decoded[0],
    ]

    reader, writer = get_csv_writer(infile, outfile, *arg_list)
    for line in reader:
        process_line(line, *arg_list)
        writer.writerow(line)


if __name__ == '__main__':
    main()
